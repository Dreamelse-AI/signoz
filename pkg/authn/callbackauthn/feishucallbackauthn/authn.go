package feishucallbackauthn

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/SigNoz/signoz/pkg/authn"
	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/factory"
	"github.com/SigNoz/signoz/pkg/global"
	"github.com/SigNoz/signoz/pkg/http/client"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/SigNoz/signoz/pkg/valuer"
)

const (
	redirectPath string = "/api/v1/complete/feishu"

	// Feishu (China) endpoints. Feishu is not a standard OIDC provider: there is
	// no discovery document and the token response carries no id_token, so the
	// endpoints are spelled out here and the exchange is done over plain HTTP.
	// The token endpoint must be the authen/v2 one paired with
	// authen/v1/authorize; the oauth/v3 token endpoint belongs to a different
	// OAuth stack and rejects codes issued by authen/v1/authorize.
	feishuAuthorizeURL string = "https://accounts.feishu.cn/open-apis/authen/v1/authorize"
	feishuTokenURL     string = "https://open.feishu.cn/open-apis/authen/v2/oauth/token"
	feishuUserInfoURL  string = "https://open.feishu.cn/open-apis/authen/v1/user_info"

	// Lark (international) endpoints, symmetrical to the Feishu ones.
	larkAuthorizeURL string = "https://accounts.larksuite.com/open-apis/authen/v1/authorize"
	larkTokenURL     string = "https://open.larksuite.com/open-apis/authen/v2/oauth/token"
	larkUserInfoURL  string = "https://open.larksuite.com/open-apis/authen/v1/user_info"

	maxResponseBytes int64 = 1 << 20

	// feishuLocalPart prefixes the synthesized address of a feishu user with no
	// email, so such accounts are recognizable in the user list and can never be
	// confused with a real mailbox.
	feishuLocalPart string = "feishu-"
)

var _ authn.CallbackAuthN = (*AuthN)(nil)

type endpoints struct {
	authorizeURL string
	tokenURL     string
	userInfoURL  string
}

type AuthN struct {
	store        authtypes.AuthNStore
	settings     factory.ScopedProviderSettings
	httpClient   *client.Client
	globalConfig global.Config

	// endpointsOverride replaces the provider endpoints in tests.
	endpointsOverride *endpoints
}

// tokenResponse is the response of the authen/v2/oauth/token endpoint. A
// non-zero code indicates an error even when the http status is 200.
type tokenResponse struct {
	Code             int    `json:"code"`
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// userInfoResponse is the response of the authen/v1/user_info endpoint.
type userInfoResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		Name            string `json:"name"`
		EnName          string `json:"en_name"`
		Email           string `json:"email"`
		EnterpriseEmail string `json:"enterprise_email"`
		OpenID          string `json:"open_id"`
	} `json:"data"`
}

func New(ctx context.Context, store authtypes.AuthNStore, providerSettings factory.ProviderSettings, globalConfig global.Config) (*AuthN, error) {
	settings := factory.NewScopedProviderSettings(providerSettings, "github.com/SigNoz/signoz/pkg/authn/callbackauthn/feishucallbackauthn")

	httpClient, err := client.New(settings.Logger(), providerSettings.TracerProvider, providerSettings.MeterProvider)
	if err != nil {
		return nil, err
	}

	return &AuthN{
		store:        store,
		settings:     settings,
		httpClient:   httpClient,
		globalConfig: globalConfig,
	}, nil
}

func (a *AuthN) LoginURL(ctx context.Context, siteURL *url.URL, authDomain *authtypes.AuthDomain) (string, error) {
	if authDomain.AuthDomainConfig().AuthNProvider != authtypes.AuthNProviderFeishu {
		return "", errors.Newf(errors.TypeInternal, authtypes.ErrCodeAuthDomainMismatch, "domain type is not feishu")
	}

	config := authDomain.AuthDomainConfig().Feishu
	authorizeURL, err := url.Parse(a.endpoints(config).authorizeURL)
	if err != nil {
		return "", err
	}

	query := authorizeURL.Query()
	query.Set("client_id", config.ClientID)
	query.Set("response_type", "code")
	query.Set("redirect_uri", a.redirectURL(siteURL))
	query.Set("state", authtypes.NewState(siteURL, authDomain.StorableAuthDomain().ID).URL.String())
	authorizeURL.RawQuery = query.Encode()

	return authorizeURL.String(), nil
}

func (a *AuthN) HandleCallback(ctx context.Context, query url.Values) (*authtypes.CallbackIdentity, error) {
	if err := query.Get("error"); err != "" {
		a.settings.Logger().ErrorContext(ctx, "feishu: error while authenticating", slog.String("error", err), slog.String("error_description", query.Get("error_description")))
		return nil, errors.Newf(errors.TypeInternal, errors.CodeInternal, "feishu: error while authenticating").WithAdditional(query.Get("error_description"))
	}

	state, err := authtypes.NewStateFromString(query.Get("state"))
	if err != nil {
		a.settings.Logger().ErrorContext(ctx, "feishu: invalid state", errors.Attr(err))
		return nil, errors.Newf(errors.TypeInvalidInput, authtypes.ErrCodeInvalidState, "feishu: invalid state").WithAdditional(err.Error())
	}

	authDomain, err := a.store.GetAuthDomainFromID(ctx, state.DomainID)
	if err != nil {
		return nil, err
	}

	if authDomain.AuthDomainConfig().AuthNProvider != authtypes.AuthNProviderFeishu {
		return nil, errors.Newf(errors.TypeInternal, authtypes.ErrCodeAuthDomainMismatch, "domain type is not feishu")
	}

	config := authDomain.AuthDomainConfig().Feishu
	endpoints := a.endpoints(config)

	accessToken, err := a.exchangeCode(ctx, endpoints, config, query.Get("code"), a.redirectURL(state.URL))
	if err != nil {
		return nil, err
	}

	userInfo, err := a.fetchUserInfo(ctx, endpoints, accessToken)
	if err != nil {
		return nil, err
	}

	// Authorization is delegated entirely to the feishu app: reaching this point
	// means feishu issued a code for this user against our client_id, so the user
	// is inside the app's visibility scope. Neither the presence of an email nor
	// its domain is used as a gate — the app's own member scope is the policy.
	//
	// The email is still needed as the local identity key (signoz keys users by
	// email), so prefer the enterprise email, fall back to the personal one, and
	// finally synthesize a stable address from the immutable open_id.
	rawEmail := userInfo.Data.EnterpriseEmail
	if rawEmail == "" {
		rawEmail = userInfo.Data.Email
	}

	if rawEmail == "" {
		if userInfo.Data.OpenID == "" {
			a.settings.Logger().ErrorContext(ctx, "feishu: user info carries neither email nor open_id")
			return nil, errors.New(errors.TypeForbidden, errors.CodeForbidden, "feishu: user info carries neither email nor open_id")
		}

		rawEmail = syntheticEmail(userInfo.Data.OpenID, authDomain.StorableAuthDomain().Name)
		a.settings.Logger().InfoContext(ctx, "feishu: no email in user info, using synthesized address", slog.String("open_id", userInfo.Data.OpenID), slog.String("email", rawEmail))
	}

	email, err := valuer.NewEmail(rawEmail)
	if err != nil {
		return nil, errors.Newf(errors.TypeInvalidInput, errors.CodeInvalidInput, "feishu: failed to parse email").WithAdditional(err.Error())
	}

	name := userInfo.Data.Name
	if name == "" {
		name = userInfo.Data.EnName
	}

	return authtypes.NewCallbackIdentity(name, email, authDomain.StorableAuthDomain().OrgID, state, nil, ""), nil
}

func (a *AuthN) ProviderInfo(ctx context.Context, authDomain *authtypes.AuthDomain) *authtypes.AuthNProviderInfo {
	return &authtypes.AuthNProviderInfo{
		RelayStatePath: nil,
	}
}

// exchangeCode exchanges the one-time authorization code for a user access
// token. Unlike standard OAuth token endpoints, feishu expects a JSON body.
func (a *AuthN) exchangeCode(ctx context.Context, endpoints endpoints, config *authtypes.FeishuConfig, code string, redirectURL string) (string, error) {
	body, err := json.Marshal(map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     config.ClientID,
		"client_secret": config.ClientSecret,
		"code":          code,
		"redirect_uri":  redirectURL,
	})
	if err != nil {
		return "", errors.Newf(errors.TypeInternal, errors.CodeInternal, "feishu: failed to marshal token request")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoints.tokenURL, bytes.NewReader(body))
	if err != nil {
		return "", errors.Newf(errors.TypeInternal, errors.CodeInternal, "feishu: failed to create token request")
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		a.settings.Logger().ErrorContext(ctx, "feishu: failed to get token", errors.Attr(err))
		return "", errors.Newf(errors.TypeInternal, errors.CodeInternal, "feishu: failed to get token")
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	var token tokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&token); err != nil {
		a.settings.Logger().ErrorContext(ctx, "feishu: invalid token response", errors.Attr(err))
		return "", errors.Newf(errors.TypeInternal, errors.CodeInternal, "feishu: invalid token response")
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 || token.Code != 0 || token.AccessToken == "" {
		a.settings.Logger().ErrorContext(ctx, "feishu: failed to get token", slog.Int("status_code", resp.StatusCode), slog.Int("code", token.Code), slog.String("error", token.Error), slog.String("error_description", token.ErrorDescription))
		return "", errors.Newf(errors.TypeForbidden, errors.CodeForbidden, "feishu: failed to get token (code=%d)", token.Code).WithAdditional(token.ErrorDescription)
	}

	return token.AccessToken, nil
}

// fetchUserInfo fetches the profile of the logged-in user with the user access
// token obtained from exchangeCode.
func (a *AuthN) fetchUserInfo(ctx context.Context, endpoints endpoints, accessToken string) (*userInfoResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoints.userInfoURL, nil)
	if err != nil {
		return nil, errors.Newf(errors.TypeInternal, errors.CodeInternal, "feishu: failed to create user info request")
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		a.settings.Logger().ErrorContext(ctx, "feishu: failed to get user info", errors.Attr(err))
		return nil, errors.Newf(errors.TypeInternal, errors.CodeInternal, "feishu: failed to get user info")
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	userInfo := new(userInfoResponse)
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(userInfo); err != nil {
		a.settings.Logger().ErrorContext(ctx, "feishu: invalid user info response", errors.Attr(err))
		return nil, errors.Newf(errors.TypeInternal, errors.CodeInternal, "feishu: invalid user info response")
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 || userInfo.Code != 0 {
		a.settings.Logger().ErrorContext(ctx, "feishu: failed to get user info", slog.Int("status_code", resp.StatusCode), slog.Int("code", userInfo.Code), slog.String("msg", userInfo.Msg))
		return nil, errors.Newf(errors.TypeForbidden, errors.CodeForbidden, "feishu: failed to get user info (code=%d)", userInfo.Code).WithAdditional(userInfo.Msg)
	}

	return userInfo, nil
}

func (a *AuthN) endpoints(config *authtypes.FeishuConfig) endpoints {
	if a.endpointsOverride != nil {
		return *a.endpointsOverride
	}

	if config != nil && config.UseLark {
		return endpoints{
			authorizeURL: larkAuthorizeURL,
			tokenURL:     larkTokenURL,
			userInfoURL:  larkUserInfoURL,
		}
	}

	return endpoints{
		authorizeURL: feishuAuthorizeURL,
		tokenURL:     feishuTokenURL,
		userInfoURL:  feishuUserInfoURL,
	}
}

func (a *AuthN) redirectURL(siteURL *url.URL) string {
	return (&url.URL{
		Scheme: siteURL.Scheme,
		Host:   siteURL.Host,
		Path:   path.Join(a.globalConfig.ExternalPath(), redirectPath),
	}).String()
}

// syntheticEmail builds the local identity key for a feishu user who has no
// email at all. open_id is stable per (app, user), so the same person keeps the
// same signoz account across logins. The address is namespaced under the auth
// domain so it can never collide with a real mailbox in that domain.
func syntheticEmail(openID string, authDomainName string) string {
	return feishuLocalPart + strings.ToLower(openID) + "@" + strings.ToLower(authDomainName)
}
