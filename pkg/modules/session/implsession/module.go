package implsession

import (
	"context"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/SigNoz/signoz/pkg/authn"
	"github.com/SigNoz/signoz/pkg/authz"
	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/factory"
	"github.com/SigNoz/signoz/pkg/global"
	"github.com/SigNoz/signoz/pkg/modules/authdomain"
	"github.com/SigNoz/signoz/pkg/modules/organization"
	"github.com/SigNoz/signoz/pkg/modules/session"
	"github.com/SigNoz/signoz/pkg/modules/user"
	"github.com/SigNoz/signoz/pkg/tokenizer"
	"github.com/SigNoz/signoz/pkg/types"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/SigNoz/signoz/pkg/valuer"
)

type module struct {
	settings     factory.ScopedProviderSettings
	authNs       map[authtypes.AuthNProvider]authn.AuthN
	userSetter   user.Setter
	userGetter   user.Getter
	authDomain   authdomain.Module
	tokenizer    tokenizer.Tokenizer
	orgGetter    organization.Getter
	authz        authz.AuthZ
	globalConfig global.Config
}

func NewModule(providerSettings factory.ProviderSettings, authNs map[authtypes.AuthNProvider]authn.AuthN, userSetter user.Setter, userGetter user.Getter, authDomain authdomain.Module, tokenizer tokenizer.Tokenizer, orgGetter organization.Getter, authz authz.AuthZ, globalConfig global.Config) session.Module {
	return &module{
		settings:     factory.NewScopedProviderSettings(providerSettings, "github.com/SigNoz/signoz/pkg/modules/session/implsession"),
		authNs:       authNs,
		userSetter:   userSetter,
		userGetter:   userGetter,
		authDomain:   authDomain,
		tokenizer:    tokenizer,
		orgGetter:    orgGetter,
		authz:        authz,
		globalConfig: globalConfig,
	}
}

func (module *module) GetSessionContext(ctx context.Context, email valuer.Email, siteURL *url.URL) (*authtypes.SessionContext, error) {
	context := authtypes.NewSessionContext()

	orgs, err := module.orgGetter.ListByOwnedKeyRange(ctx)
	if err != nil {
		return nil, err
	}

	if len(orgs) == 0 {
		context.Exists = false
		return context, nil
	}

	var orgIDs []valuer.UUID
	for _, org := range orgs {
		orgIDs = append(orgIDs, org.ID)
	}

	users, err := module.userGetter.ListUsersByEmailAndOrgIDs(ctx, email, orgIDs)
	if err != nil {
		return nil, err
	}

	// filter out deleted users
	users = slices.DeleteFunc(users, func(user *types.User) bool { return user.ErrIfDeleted() != nil })

	// Since email is a valuer, we can be sure that it is a valid email and we can split it to get the domain name.
	name := strings.Split(email.String(), "@")[1]

	if len(users) == 0 {
		context.Exists = false

		for _, org := range orgs {
			orgContext, err := module.getOrgSessionContext(ctx, org, name, siteURL)
			if err != nil {
				// For some reason, there was an error in getting the org session context. Instead of failing the context call, we create a PasswordAuthNSupport for the org and add a warning.
				orgContext = authtypes.NewOrgSessionContext(org.ID, org.Name).AddPasswordAuthNSupport(authtypes.AuthNProviderEmailPassword).AddWarning(err)
			}

			context = context.AddOrgContext(orgContext)
		}

		return context, nil
	}

	context.Exists = true
	for _, user := range users {
		idx := slices.IndexFunc(orgs, func(org *types.Organization) bool {
			return org.ID == user.OrgID
		})

		if idx == -1 {
			continue
		}

		org := orgs[idx]
		orgContext, err := module.getOrgSessionContext(ctx, org, name, siteURL)
		if err != nil {
			// For some reason, there was an error in getting the org session context. Instead of failing the context call, we create a PasswordAuthNSupport for the org and add a warning.
			orgContext = authtypes.NewOrgSessionContext(org.ID, org.Name).AddPasswordAuthNSupport(authtypes.AuthNProviderEmailPassword).AddWarning(err)
		}

		context = context.AddOrgContext(orgContext)
	}

	return context, nil
}

func (module *module) CreatePasswordAuthNSession(ctx context.Context, authNProvider authtypes.AuthNProvider, email valuer.Email, password string, orgID valuer.UUID) (*authtypes.Token, error) {
	passwordAuthN, err := getProvider[authn.PasswordAuthN](authNProvider, module.authNs)
	if err != nil {
		return nil, err
	}

	identity, err := passwordAuthN.Authenticate(ctx, email.String(), password, orgID)
	if err != nil {
		return nil, err
	}

	return module.tokenizer.CreateToken(ctx, identity, map[string]string{})
}

func (module *module) CreateCallbackAuthNSession(ctx context.Context, authNProvider authtypes.AuthNProvider, values url.Values) (string, error) {
	callbackAuthN, err := getProvider[authn.CallbackAuthN](authNProvider, module.authNs)
	if err != nil {
		return "", err
	}

	callbackIdentity, err := callbackAuthN.HandleCallback(ctx, values)
	if err != nil {
		module.settings.Logger().ErrorContext(ctx, "failed to handle callback", errors.Attr(err), slog.Any("authn_provider", authNProvider))
		return "", err
	}

	if callbackIdentity.State.URL.Host != "" && !module.globalConfig.IsOriginAllowed(callbackIdentity.State.URL) {
		return "", errors.Newf(errors.TypeForbidden, global.ErrCodeOriginNotAllowed, "state redirect %q is not an allowed origin", callbackIdentity.State.URL.String())
	}

	authDomain, err := module.authDomain.GetByOrgIDAndID(ctx, callbackIdentity.OrgID, callbackIdentity.State.DomainID)
	if err != nil {
		return "", err
	}

	roleMapping := authDomain.AuthDomainConfig().RoleMapping

	roleAttributeExists := false
	if roleMapping != nil && roleMapping.UseRoleAttribute && callbackIdentity.Role != "" {
		_, err := module.authz.GetByOrgIDAndName(ctx, callbackIdentity.OrgID, authtypes.NormalizeRoleName(callbackIdentity.Role))
		if err == nil {
			roleAttributeExists = true
		}
	}

	roleNames := roleMapping.NewRolesFromCallbackIdentity(callbackIdentity, roleAttributeExists)

	newUser, err := types.NewUser(callbackIdentity.Name, callbackIdentity.Email, callbackIdentity.OrgID, types.UserStatusActive)
	if err != nil {
		return "", err
	}

	newUser, err = module.userSetter.GetOrCreateUser(ctx, newUser, user.WithRoleNames(roleNames))
	if err != nil {
		return "", err
	}

	if err := newUser.ErrIfRoot(); err != nil {
		return "", errors.WithAdditionalf(err, "root user can only authenticate via password")
	}

	token, err := module.tokenizer.CreateToken(ctx, authtypes.NewPrincipalUserIdentity(newUser.ID, newUser.OrgID, newUser.Email, authtypes.IdentNProviderTokenizer), map[string]string{})
	if err != nil {
		return "", err
	}

	redirectURL := &url.URL{
		Scheme:   callbackIdentity.State.URL.Scheme,
		Host:     callbackIdentity.State.URL.Host,
		Path:     callbackIdentity.State.URL.Path,
		RawQuery: authtypes.NewURLValuesFromToken(token, module.GetRotationInterval(ctx)).Encode(),
	}

	return redirectURL.String(), nil
}

func (module *module) RotateSession(ctx context.Context, accessToken string, refreshToken string) (*authtypes.Token, error) {
	return module.tokenizer.RotateToken(ctx, accessToken, refreshToken)
}

func (module *module) DeleteSession(ctx context.Context, accessToken string) error {
	return module.tokenizer.DeleteToken(ctx, accessToken)
}

func (module *module) GetRotationInterval(context.Context) time.Duration {
	return module.tokenizer.Config().Rotation.Interval
}

func (module *module) getOrgSessionContext(ctx context.Context, org *types.Organization, name string, siteURL *url.URL) (*authtypes.OrgSessionContext, error) {
	authDomain, err := module.authDomain.GetByNameAndOrgID(ctx, name, org.ID)
	if err != nil && !errors.Ast(err, errors.TypeNotFound) {
		return nil, err
	}

	if authDomain == nil {
		// The typed address does not belong to a configured domain. Providers whose
		// authorization lives entirely in the identity provider (feishu: the app's
		// member scope decides who may log in) must still be reachable here —
		// otherwise a user whose mailbox sits outside the org domain, or who has no
		// mailbox at all, could never reach the login button. Fall back to such a
		// domain if the org has one; password login stays reachable via ?password=Y.
		authDomain, err = module.getDomainAuthNAgnosticAuthDomain(ctx, org.ID)
		if err != nil {
			return nil, err
		}
	}

	if authDomain == nil {
		return authtypes.NewOrgSessionContext(org.ID, org.Name).AddPasswordAuthNSupport(authtypes.AuthNProviderEmailPassword), nil
	}

	if !authDomain.AuthDomainConfig().SSOEnabled {
		return authtypes.NewOrgSessionContext(org.ID, org.Name).AddPasswordAuthNSupport(authtypes.AuthNProviderEmailPassword), nil
	}

	provider, err := getProvider[authn.CallbackAuthN](authDomain.AuthDomainConfig().AuthNProvider, module.authNs)
	if err != nil {
		return nil, err
	}

	if !module.globalConfig.IsOriginAllowed(siteURL) {
		return nil, errors.Newf(errors.TypeInvalidInput, global.ErrCodeOriginNotAllowed, "ref %q is not an allowed origin", siteURL.String())
	}

	loginURL, err := provider.LoginURL(ctx, siteURL, authDomain)
	if err != nil {
		return nil, err
	}

	return authtypes.NewOrgSessionContext(org.ID, org.Name).AddCallbackAuthNSupport(authDomain.AuthDomainConfig().AuthNProvider, loginURL), nil
}

// getDomainAuthNAgnosticAuthDomain returns the org's SSO-enabled auth domain
// whose provider does not derive authorization from the email domain, or nil if
// there is none. Only feishu qualifies: google carries an hd claim and saml/oidc
// domains are provisioned per mail domain on purpose, so widening them would let
// an unrelated tenant in.
func (module *module) getDomainAuthNAgnosticAuthDomain(ctx context.Context, orgID valuer.UUID) (*authtypes.AuthDomain, error) {
	authDomains, err := module.authDomain.ListByOrgID(ctx, orgID)
	if err != nil {
		if errors.Ast(err, errors.TypeNotFound) {
			return nil, nil
		}

		return nil, err
	}

	candidates := make([]*authtypes.AuthDomain, 0, len(authDomains))
	for _, authDomain := range authDomains {
		config := authDomain.AuthDomainConfig()
		if config.SSOEnabled && config.AuthNProvider == authtypes.AuthNProviderFeishu {
			candidates = append(candidates, authDomain)
		}
	}

	if len(candidates) == 0 {
		return nil, nil
	}

	// ListByOrgID does not order its rows, so an org holding more than one feishu
	// domain would otherwise hand out a different client_id per request and look
	// like an intermittent login failure. Pick the oldest one deterministically.
	slices.SortFunc(candidates, func(a, b *authtypes.AuthDomain) int {
		if diff := a.StorableAuthDomain().CreatedAt.Compare(b.StorableAuthDomain().CreatedAt); diff != 0 {
			return diff
		}

		return strings.Compare(a.StorableAuthDomain().ID.String(), b.StorableAuthDomain().ID.String())
	})

	return candidates[0], nil
}

func getProvider[T authn.AuthN](authNProvider authtypes.AuthNProvider, authNs map[authtypes.AuthNProvider]authn.AuthN) (T, error) {
	var provider T

	provider, ok := authNs[authNProvider].(T)
	if !ok {
		return provider, errors.New(errors.TypeNotFound, errors.CodeNotFound, "authn provider not found")
	}

	return provider, nil
}
