package feishucallbackauthn

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/global"
	"github.com/SigNoz/signoz/pkg/instrumentation/instrumentationtest"
	"github.com/SigNoz/signoz/pkg/types"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/SigNoz/signoz/pkg/valuer"
)

type authNStore struct {
	authDomain *authtypes.AuthDomain
}

func (store *authNStore) GetActiveUserAndFactorPasswordByEmailAndOrgID(_ context.Context, _ string, _ valuer.UUID) (*types.User, *types.FactorPassword, []*authtypes.UserRole, error) {
	return nil, nil, nil, nil
}

func (store *authNStore) GetAuthDomainFromID(_ context.Context, domainID valuer.UUID) (*authtypes.AuthDomain, error) {
	if store.authDomain != nil && store.authDomain.StorableAuthDomain().ID == domainID {
		return store.authDomain, nil
	}

	return nil, errors.Newf(errors.TypeNotFound, authtypes.ErrCodeAuthDomainNotFound, "auth domain not found")
}

// fakeFeishu is a fake feishu open platform serving the token exchange and the
// user info endpoints.
type fakeFeishu struct {
	server *httptest.Server

	accessToken string
	tokenCode   int
	tokenBody   map[string]string

	userInfoCode            int
	userInfoName            string
	userInfoEmail           string
	userInfoEnterpriseEmail string
	userInfoOpenID          string
	userInfoAuthorization   string
}

func newFakeFeishu(t *testing.T) *fakeFeishu {
	t.Helper()

	fake := &fakeFeishu{accessToken: "u-access-token", userInfoOpenID: "ou_test"}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(rw http.ResponseWriter, req *http.Request) {
		body := make(map[string]string)
		require.NoError(t, json.NewDecoder(req.Body).Decode(&body))
		fake.tokenBody = body

		rw.Header().Set("Content-Type", "application/json")
		if fake.tokenCode != 0 {
			require.NoError(t, json.NewEncoder(rw).Encode(map[string]any{"code": fake.tokenCode, "error": "invalid_request", "error_description": "pkce verification failed"}))
			return
		}

		require.NoError(t, json.NewEncoder(rw).Encode(map[string]any{"code": 0, "access_token": fake.accessToken, "token_type": "Bearer", "expires_in": 7200}))
	})
	mux.HandleFunc("GET /user_info", func(rw http.ResponseWriter, req *http.Request) {
		fake.userInfoAuthorization = req.Header.Get("Authorization")

		rw.Header().Set("Content-Type", "application/json")
		if fake.userInfoCode != 0 {
			require.NoError(t, json.NewEncoder(rw).Encode(map[string]any{"code": fake.userInfoCode, "msg": "unauthorized"}))
			return
		}

		require.NoError(t, json.NewEncoder(rw).Encode(map[string]any{"code": 0, "msg": "success", "data": map[string]string{
			"name":             fake.userInfoName,
			"en_name":          fake.userInfoName,
			"email":            fake.userInfoEmail,
			"enterprise_email": fake.userInfoEnterpriseEmail,
			"open_id":          fake.userInfoOpenID,
		}}))
	})

	fake.server = httptest.NewServer(mux)
	t.Cleanup(fake.server.Close)

	return fake
}

func newFeishuAuthDomain(t *testing.T, name string, useLark bool) *authtypes.AuthDomain {
	t.Helper()

	authDomain, err := authtypes.NewAuthDomainFromConfig(name, &authtypes.AuthDomainConfig{
		SSOEnabled:    true,
		AuthNProvider: authtypes.AuthNProviderFeishu,
		Feishu: &authtypes.FeishuConfig{
			ClientID:     "cli_test",
			ClientSecret: "secret_test",
			UseLark:      useLark,
		},
	}, valuer.GenerateUUID())
	require.NoError(t, err)

	return authDomain
}

func newAuthN(t *testing.T, authDomain *authtypes.AuthDomain, fake *fakeFeishu) *AuthN {
	t.Helper()

	authN, err := New(context.Background(), &authNStore{authDomain: authDomain}, instrumentationtest.New().ToProviderSettings(), global.Config{})
	require.NoError(t, err)

	if fake != nil {
		authN.endpointsOverride = &endpoints{
			authorizeURL: fake.server.URL + "/authorize",
			tokenURL:     fake.server.URL + "/token",
			userInfoURL:  fake.server.URL + "/user_info",
		}
	}

	return authN
}

func siteURL(t *testing.T) *url.URL {
	t.Helper()

	u, err := url.Parse("https://signoz.example.com/login")
	require.NoError(t, err)

	return u
}

func callbackQuery(authDomain *authtypes.AuthDomain, site *url.URL) url.Values {
	return url.Values{
		"code":  {"one-time-code"},
		"state": {authtypes.NewState(site, authDomain.StorableAuthDomain().ID).URL.String()},
	}
}

func TestLoginURL(t *testing.T) {
	authDomain := newFeishuAuthDomain(t, "example.com", false)
	authN := newAuthN(t, authDomain, nil)

	loginURL, err := authN.LoginURL(context.Background(), siteURL(t), authDomain)
	require.NoError(t, err)

	parsed, err := url.Parse(loginURL)
	require.NoError(t, err)

	assert.Equal(t, "accounts.feishu.cn", parsed.Host)
	assert.Equal(t, "/open-apis/authen/v1/authorize", parsed.Path)
	assert.Equal(t, "cli_test", parsed.Query().Get("client_id"))
	assert.Equal(t, "code", parsed.Query().Get("response_type"))
	assert.Equal(t, "https://signoz.example.com/api/v1/complete/feishu", parsed.Query().Get("redirect_uri"))

	state, err := authtypes.NewStateFromString(parsed.Query().Get("state"))
	require.NoError(t, err)
	assert.Equal(t, authDomain.StorableAuthDomain().ID, state.DomainID)
}

func TestLoginURLWithLark(t *testing.T) {
	authDomain := newFeishuAuthDomain(t, "example.com", true)
	authN := newAuthN(t, authDomain, nil)

	loginURL, err := authN.LoginURL(context.Background(), siteURL(t), authDomain)
	require.NoError(t, err)

	parsed, err := url.Parse(loginURL)
	require.NoError(t, err)
	assert.Equal(t, "accounts.larksuite.com", parsed.Host)
}

func TestLoginURLWithMismatchedAuthDomain(t *testing.T) {
	authDomain, err := authtypes.NewAuthDomainFromConfig("example.com", &authtypes.AuthDomainConfig{
		SSOEnabled:    true,
		AuthNProvider: authtypes.AuthNProviderGoogleAuth,
		Google: &authtypes.GoogleConfig{
			ClientID:     "google-client-id",
			ClientSecret: "google-client-secret",
		},
	}, valuer.GenerateUUID())
	require.NoError(t, err)

	authN := newAuthN(t, authDomain, nil)

	_, err = authN.LoginURL(context.Background(), siteURL(t), authDomain)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "domain type is not feishu")
}

func TestHandleCallback(t *testing.T) {
	authDomain := newFeishuAuthDomain(t, "example.com", false)
	fake := newFakeFeishu(t)
	fake.userInfoName = "Zhang San"
	fake.userInfoEnterpriseEmail = "zhangsan@example.com"

	authN := newAuthN(t, authDomain, fake)

	identity, err := authN.HandleCallback(context.Background(), callbackQuery(authDomain, siteURL(t)))
	require.NoError(t, err)

	assert.Equal(t, "Zhang San", identity.Name)
	assert.Equal(t, "zhangsan@example.com", identity.Email.StringValue())
	assert.Equal(t, authDomain.StorableAuthDomain().OrgID, identity.OrgID)
	assert.Equal(t, authDomain.StorableAuthDomain().ID, identity.State.DomainID)

	// The token exchange must be a json POST carrying the code and the exact
	// redirect_uri used during authorization.
	assert.Equal(t, "authorization_code", fake.tokenBody["grant_type"])
	assert.Equal(t, "cli_test", fake.tokenBody["client_id"])
	assert.Equal(t, "secret_test", fake.tokenBody["client_secret"])
	assert.Equal(t, "one-time-code", fake.tokenBody["code"])
	assert.Equal(t, "https://signoz.example.com/api/v1/complete/feishu", fake.tokenBody["redirect_uri"])

	// The user info request must carry the user access token as a bearer token.
	assert.Equal(t, "Bearer u-access-token", fake.userInfoAuthorization)
}

func TestHandleCallbackWithEmailFallback(t *testing.T) {
	authDomain := newFeishuAuthDomain(t, "example.com", false)
	fake := newFakeFeishu(t)
	fake.userInfoName = "Li Si"
	fake.userInfoEmail = "lisi@example.com"

	authN := newAuthN(t, authDomain, fake)

	identity, err := authN.HandleCallback(context.Background(), callbackQuery(authDomain, siteURL(t)))
	require.NoError(t, err)
	assert.Equal(t, "lisi@example.com", identity.Email.StringValue())
}

func TestHandleCallbackPrefersEnterpriseEmail(t *testing.T) {
	authDomain := newFeishuAuthDomain(t, "example.com", false)
	fake := newFakeFeishu(t)
	fake.userInfoEmail = "personal@gmail.com"
	fake.userInfoEnterpriseEmail = "corp@example.com"

	authN := newAuthN(t, authDomain, fake)

	identity, err := authN.HandleCallback(context.Background(), callbackQuery(authDomain, siteURL(t)))
	require.NoError(t, err)
	assert.Equal(t, "corp@example.com", identity.Email.StringValue())
}

// A user the app authorized but who has no mailbox gets a stable synthesized
// identity derived from open_id, rather than being rejected.
func TestHandleCallbackWithoutEmail(t *testing.T) {
	authDomain := newFeishuAuthDomain(t, "example.com", false)
	fake := newFakeFeishu(t)

	authN := newAuthN(t, authDomain, fake)

	identity, err := authN.HandleCallback(context.Background(), callbackQuery(authDomain, siteURL(t)))
	require.NoError(t, err)
	assert.Equal(t, "feishu-ou_test@example.com", identity.Email.StringValue())
}

// The synthesized address must be stable across logins, otherwise the same
// person would be provisioned as a new signoz user on every sign-in.
func TestHandleCallbackWithoutEmailIsStable(t *testing.T) {
	authDomain := newFeishuAuthDomain(t, "example.com", false)
	fake := newFakeFeishu(t)

	authN := newAuthN(t, authDomain, fake)

	first, err := authN.HandleCallback(context.Background(), callbackQuery(authDomain, siteURL(t)))
	require.NoError(t, err)

	second, err := authN.HandleCallback(context.Background(), callbackQuery(authDomain, siteURL(t)))
	require.NoError(t, err)

	assert.Equal(t, first.Email.StringValue(), second.Email.StringValue())
}

// Authorization is the feishu app's member scope, not the mail domain: a user
// whose mailbox lives outside the org domain is admitted with their real email.
func TestHandleCallbackWithForeignEmailDomain(t *testing.T) {
	authDomain := newFeishuAuthDomain(t, "example.com", false)
	fake := newFakeFeishu(t)
	fake.userInfoEnterpriseEmail = "contractor@other.com"

	authN := newAuthN(t, authDomain, fake)

	identity, err := authN.HandleCallback(context.Background(), callbackQuery(authDomain, siteURL(t)))
	require.NoError(t, err)
	assert.Equal(t, "contractor@other.com", identity.Email.StringValue())
}

// open_id is the last resort for identity; without it there is nothing stable to
// key the account on, so the login must fail rather than collide accounts.
func TestHandleCallbackWithoutEmailAndOpenID(t *testing.T) {
	authDomain := newFeishuAuthDomain(t, "example.com", false)
	fake := newFakeFeishu(t)
	fake.userInfoOpenID = ""

	authN := newAuthN(t, authDomain, fake)

	_, err := authN.HandleCallback(context.Background(), callbackQuery(authDomain, siteURL(t)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "neither email nor open_id")
}

func TestHandleCallbackWithTokenError(t *testing.T) {
	authDomain := newFeishuAuthDomain(t, "example.com", false)
	fake := newFakeFeishu(t)
	fake.tokenCode = 20049

	authN := newAuthN(t, authDomain, fake)

	_, err := authN.HandleCallback(context.Background(), callbackQuery(authDomain, siteURL(t)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get token (code=20049)")
}

func TestHandleCallbackWithUserInfoError(t *testing.T) {
	authDomain := newFeishuAuthDomain(t, "example.com", false)
	fake := newFakeFeishu(t)
	fake.userInfoCode = 99991668

	authN := newAuthN(t, authDomain, fake)

	_, err := authN.HandleCallback(context.Background(), callbackQuery(authDomain, siteURL(t)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get user info (code=99991668)")
}

func TestHandleCallbackWithProviderError(t *testing.T) {
	authDomain := newFeishuAuthDomain(t, "example.com", false)
	authN := newAuthN(t, authDomain, nil)

	_, err := authN.HandleCallback(context.Background(), url.Values{
		"error":             {"access_denied"},
		"error_description": {"the user denied the request"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error while authenticating")
}

func TestHandleCallbackWithInvalidState(t *testing.T) {
	authDomain := newFeishuAuthDomain(t, "example.com", false)
	authN := newAuthN(t, authDomain, nil)

	_, err := authN.HandleCallback(context.Background(), url.Values{
		"code":  {"one-time-code"},
		"state": {"https://signoz.example.com/login?domain_id=not-a-uuid"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid state")
}
