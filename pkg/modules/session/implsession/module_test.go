package implsession

import (
	"context"
	"testing"

	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/modules/authdomain"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/SigNoz/signoz/pkg/valuer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubAuthDomainModule serves a fixed list of auth domains; every other method
// is unreachable from the code under test.
type stubAuthDomainModule struct {
	authdomain.Module

	authDomains []*authtypes.AuthDomain
	err         error
}

func (s *stubAuthDomainModule) ListByOrgID(context.Context, valuer.UUID) ([]*authtypes.AuthDomain, error) {
	if s.err != nil {
		return nil, s.err
	}

	return s.authDomains, nil
}

func newAuthDomain(t *testing.T, name string, provider authtypes.AuthNProvider, ssoEnabled bool) *authtypes.AuthDomain {
	t.Helper()

	config := &authtypes.AuthDomainConfig{SSOEnabled: ssoEnabled, AuthNProvider: provider}
	switch provider {
	case authtypes.AuthNProviderFeishu:
		config.Feishu = &authtypes.FeishuConfig{ClientID: "cli_test", ClientSecret: "secret"}
	case authtypes.AuthNProviderGoogleAuth:
		config.Google = &authtypes.GoogleConfig{ClientID: "google_test", ClientSecret: "secret"}
	}

	authDomain, err := authtypes.NewAuthDomainFromConfig(name, config, valuer.GenerateUUID())
	require.NoError(t, err)

	return authDomain
}

func newModuleWithAuthDomains(authDomainModule authdomain.Module) *module {
	return &module{authDomain: authDomainModule}
}

// The whole point of the fallback: a feishu domain must be reachable no matter
// what mail domain the visitor typed, because the feishu app — not the mailbox —
// decides who may sign in.
func TestGetDomainAuthNAgnosticAuthDomainFindsFeishu(t *testing.T) {
	feishu := newAuthDomain(t, "example.com", authtypes.AuthNProviderFeishu, true)
	module := newModuleWithAuthDomains(&stubAuthDomainModule{authDomains: []*authtypes.AuthDomain{feishu}})

	got, err := module.getDomainAuthNAgnosticAuthDomain(context.Background(), valuer.GenerateUUID())
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, feishu.StorableAuthDomain().ID, got.StorableAuthDomain().ID)
}

// Google carries an hd claim and is provisioned per mail domain on purpose:
// widening it to arbitrary addresses would let an unrelated tenant in.
func TestGetDomainAuthNAgnosticAuthDomainSkipsGoogle(t *testing.T) {
	google := newAuthDomain(t, "example.com", authtypes.AuthNProviderGoogleAuth, true)
	module := newModuleWithAuthDomains(&stubAuthDomainModule{authDomains: []*authtypes.AuthDomain{google}})

	got, err := module.getDomainAuthNAgnosticAuthDomain(context.Background(), valuer.GenerateUUID())
	require.NoError(t, err)
	assert.Nil(t, got)
}

// A feishu domain with SSO switched off must not resurrect itself through the
// fallback, otherwise disabling SSO in the UI would have no effect.
func TestGetDomainAuthNAgnosticAuthDomainSkipsDisabledSSO(t *testing.T) {
	feishu := newAuthDomain(t, "example.com", authtypes.AuthNProviderFeishu, false)
	module := newModuleWithAuthDomains(&stubAuthDomainModule{authDomains: []*authtypes.AuthDomain{feishu}})

	got, err := module.getDomainAuthNAgnosticAuthDomain(context.Background(), valuer.GenerateUUID())
	require.NoError(t, err)
	assert.Nil(t, got)
}

// No auth domain at all is the plain password-login deployment: the caller falls
// through to password support, so this must be a nil result and not an error.
func TestGetDomainAuthNAgnosticAuthDomainWithoutAuthDomains(t *testing.T) {
	module := newModuleWithAuthDomains(&stubAuthDomainModule{authDomains: nil})

	got, err := module.getDomainAuthNAgnosticAuthDomain(context.Background(), valuer.GenerateUUID())
	require.NoError(t, err)
	assert.Nil(t, got)
}

// A not-found error from the store means the same thing as an empty list.
func TestGetDomainAuthNAgnosticAuthDomainSwallowsNotFound(t *testing.T) {
	module := newModuleWithAuthDomains(&stubAuthDomainModule{err: errors.New(errors.TypeNotFound, errors.CodeNotFound, "no auth domains")})

	got, err := module.getDomainAuthNAgnosticAuthDomain(context.Background(), valuer.GenerateUUID())
	require.NoError(t, err)
	assert.Nil(t, got)
}

// Any other store failure must surface: silently falling back to password login
// would mask a broken database behind a confusing login screen.
func TestGetDomainAuthNAgnosticAuthDomainPropagatesError(t *testing.T) {
	module := newModuleWithAuthDomains(&stubAuthDomainModule{err: errors.New(errors.TypeInternal, errors.CodeInternal, "boom")})

	_, err := module.getDomainAuthNAgnosticAuthDomain(context.Background(), valuer.GenerateUUID())
	require.Error(t, err)
}
