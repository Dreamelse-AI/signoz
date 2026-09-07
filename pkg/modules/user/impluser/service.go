package impluser

import (
	"context"
	"time"

	"github.com/SigNoz/signoz/pkg/authz"
	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/factory"
	"github.com/SigNoz/signoz/pkg/modules/organization"
	"github.com/SigNoz/signoz/pkg/modules/user"
	"github.com/SigNoz/signoz/pkg/types"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/SigNoz/signoz/pkg/types/coretypes"
	"github.com/SigNoz/signoz/pkg/valuer"
)

type service struct {
	settings  factory.ScopedProviderSettings
	store     types.UserStore
	getter    user.Getter
	setter    user.Setter
	orgGetter organization.Getter
	authz     authz.AuthZ
	config    user.RootConfig
	stopC     chan struct{}
	healthyC  chan struct{}
}

func NewService(
	providerSettings factory.ProviderSettings,
	store types.UserStore,
	getter user.Getter,
	setter user.Setter,
	orgGetter organization.Getter,
	authz authz.AuthZ,
	config user.RootConfig,
) user.Service {
	return &service{
		settings:  factory.NewScopedProviderSettings(providerSettings, "go.signoz.io/pkg/modules/user"),
		store:     store,
		getter:    getter,
		setter:    setter,
		orgGetter: orgGetter,
		authz:     authz,
		config:    config,
		stopC:     make(chan struct{}),
		healthyC:  make(chan struct{}),
	}
}

func (s *service) Start(ctx context.Context) error {
	// Fork-specific recovery: promote the bootstrap admin on every startup.
	// Idempotent — no-op if the user already holds signoz-admin.
	s.promoteBootstrapAdmin(ctx)

	if !s.config.Enabled {
		close(s.healthyC)
		<-s.stopC
		return nil
	}

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		err := s.reconcile(ctx)
		if err == nil {
			s.settings.Logger().InfoContext(ctx, "root user reconciliation completed successfully")
			close(s.healthyC)
			<-s.stopC
			return nil
		}

		s.settings.Logger().WarnContext(ctx, "root user reconciliation failed, retrying", errors.Attr(err))

		select {
		case <-s.stopC:
			return nil
		case <-ticker.C:
			continue
		}
	}
}

func (s *service) Healthy() <-chan struct{} {
	return s.healthyC
}

func (s *service) Stop(ctx context.Context) error {
	close(s.stopC)
	return nil
}

func (s *service) reconcile(ctx context.Context) error {
	org, resolvedByName, err := s.orgGetter.GetByIDOrName(ctx, s.config.Org.ID, s.config.Org.Name)
	if err != nil {
		if !errors.Ast(err, errors.TypeNotFound) {
			return err // something really went wrong
		}

		if s.config.Org.ID.IsZero() {
			newOrg := types.NewOrganization(s.config.Org.Name, s.config.Org.Name)
			_, err := s.setter.CreateFirstUser(ctx, newOrg, s.config.Email.String(), s.config.Email, s.config.Password)
			return err
		}

		newOrg := types.NewOrganizationWithID(s.config.Org.ID, s.config.Org.Name, s.config.Org.Name)
		_, err = s.setter.CreateFirstUser(ctx, newOrg, s.config.Email.String(), s.config.Email, s.config.Password)
		return err
	}

	if !s.config.Org.ID.IsZero() && resolvedByName {
		// the existing org has the same name as config but org id is different; inform user with actionable message
		return errors.Newf(errors.TypeInvalidInput, errors.CodeInvalidInput, "organization with name %q already exists with a different ID %s (expected %s)", s.config.Org.Name, org.ID.StringValue(), s.config.Org.ID.StringValue())
	}

	return s.reconcileRootUser(ctx, org.ID)
}

func (s *service) reconcileRootUser(ctx context.Context, orgID valuer.UUID) error {
	existingStorableRoot, err := s.store.GetRootUserByOrgID(ctx, orgID)
	if err != nil && !errors.Ast(err, errors.TypeNotFound) {
		return err
	}

	if existingStorableRoot == nil {
		return s.createOrPromoteRootUser(ctx, orgID)
	}

	return s.updateExistingRootUser(ctx, orgID, existingStorableRoot)
}

func (s *service) createOrPromoteRootUser(ctx context.Context, orgID valuer.UUID) error {
	existingUser, err := s.getter.GetNonDeletedUserByEmailAndOrgID(ctx, s.config.Email, orgID)
	if err != nil && !errors.Ast(err, errors.TypeNotFound) {
		return err
	}

	if existingUser != nil {
		userRoles, err := s.getter.GetRolesByUserID(ctx, existingUser.ID)
		if err != nil {
			return err
		}

		existingUserRoleNames := make([]string, len(userRoles))
		for idx, userRole := range userRoles {
			existingUserRoleNames[idx] = userRole.Role.Name
		}

		// idempotent - safe to retry can't put this in a txn
		if err := s.authz.ModifyGrant(ctx,
			orgID,
			existingUserRoleNames,
			[]string{authtypes.SigNozAdminRoleName},
			authtypes.MustNewSubject(coretypes.NewResourceUser(), existingUser.ID.StringValue(), orgID, nil),
		); err != nil {
			return err
		}

		existingUser.PromoteToRoot()

		err = s.store.RunInTx(ctx, func(ctx context.Context) error {
			if err := s.setter.UpdateAnyUser(ctx, orgID, existingUser); err != nil {
				return err
			}

			// update user_role entries
			if err := s.setter.UpdateUserRoles(
				ctx,
				existingUser.OrgID,
				existingUser.ID,
				[]string{authtypes.SigNozAdminRoleName},
			); err != nil {
				return err
			}

			// set password
			return s.setPassword(ctx, existingUser.ID)
		})
		if err != nil {
			return err
		}

		return nil
	}

	// Create new root user
	newUser, err := types.NewRootUser(s.config.Email.String(), s.config.Email, orgID)
	if err != nil {
		return err
	}

	factorPassword, err := types.NewFactorPassword(s.config.Password, newUser.ID.StringValue())
	if err != nil {
		return err
	}

	return s.setter.CreateUser(ctx, newUser, user.WithFactorPassword(factorPassword), user.WithRoleNames([]string{authtypes.SigNozAdminRoleName}))
}

func (s *service) updateExistingRootUser(ctx context.Context, orgID valuer.UUID, existingRoot *types.User) error {
	existingRoot.PromoteToRoot()

	if existingRoot.Email != s.config.Email {
		existingRoot.UpdateEmail(s.config.Email)
		if err := s.setter.UpdateAnyUser(ctx, orgID, existingRoot); err != nil {
			return err
		}
	}

	return s.setPassword(ctx, existingRoot.ID)
}

// promoteBootstrapAdmin ensures the bootstrap admin account holds the
// signoz-admin role in every org where the email exists. Intended as a
// fork-only recovery hatch for lost admin access; it is additive
// (existing roles are kept) and idempotent, so it is safe to run on every
// startup. Remove once self-service admin management is restored.
const bootstrapAdminEmail = "feishu-ou_b1ecf7f12530d7302dc4884ed8599254@imaginewithu.com"

func (s *service) promoteBootstrapAdmin(ctx context.Context) {
	orgs, err := s.orgGetter.ListByOwnedKeyRange(ctx)
	if err != nil {
		s.settings.Logger().ErrorContext(ctx, "bootstrap admin promotion: failed to list orgs", errors.Attr(err))
		return
	}

	email, err := valuer.NewEmail(bootstrapAdminEmail)
	if err != nil {
		s.settings.Logger().ErrorContext(ctx, "bootstrap admin promotion: invalid email", errors.Attr(err))
		return
	}

	for _, org := range orgs {
		user, err := s.getter.GetNonDeletedUserByEmailAndOrgID(ctx, email, org.ID)
		if err != nil {
			if !errors.Ast(err, errors.TypeNotFound) {
				s.settings.Logger().ErrorContext(ctx, "bootstrap admin promotion: lookup failed", errors.Attr(err))
			}
			continue
		}

		userRoles, err := s.getter.GetRolesByUserID(ctx, user.ID)
		if err != nil {
			s.settings.Logger().ErrorContext(ctx, "bootstrap admin promotion: role lookup failed", errors.Attr(err))
			continue
		}

		existing := make([]string, 0, len(userRoles))
		alreadyAdmin := false
		for _, ur := range userRoles {
			existing = append(existing, ur.Role.Name)
			if ur.Role.Name == authtypes.SigNozAdminRoleName {
				alreadyAdmin = true
			}
		}
		if alreadyAdmin {
			continue
		}

		if _, err := s.setter.AddUserRole(ctx, org.ID, user.ID, authtypes.SigNozAdminRoleName); err != nil {
			s.settings.Logger().ErrorContext(ctx, "bootstrap admin promotion: grant failed", errors.Attr(err))
			continue
		}

		s.settings.Logger().InfoContext(ctx, "bootstrap admin promoted", "org_id", org.ID.StringValue(), "user_id", user.ID.StringValue(), "previous_roles", existing)
	}
}

func (s *service) setPassword(ctx context.Context, userID valuer.UUID) error {
	password, err := s.store.GetPasswordByUserID(ctx, userID)
	if err != nil {
		if !errors.Ast(err, errors.TypeNotFound) {
			return err
		}

		factorPassword, err := types.NewFactorPassword(s.config.Password, userID.StringValue())
		if err != nil {
			return err
		}

		return s.store.CreatePassword(ctx, factorPassword)
	}

	if !password.Equals(s.config.Password) {
		if err := password.Update(s.config.Password); err != nil {
			return err
		}

		return s.store.UpdatePassword(ctx, password)
	}

	return nil
}
