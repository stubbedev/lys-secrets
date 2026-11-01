package bitwarden

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/stubbedev/lys-secrets/vault"
)

// endpoints are a server's API and identity URLs.
type endpoints struct {
	API, Identity, Send string
}

var clouds = map[string]endpoints{
	vault.CloudUS: {API: "https://api.bitwarden.com", Identity: "https://identity.bitwarden.com", Send: "https://send.bitwarden.com/#"},
	vault.CloudEU: {API: "https://api.bitwarden.eu", Identity: "https://identity.bitwarden.eu", Send: "https://vault.bitwarden.eu/#/send/"},
}

// endpointsOf resolves where server's account lives: an official cloud
// by its name, a self-hosted server's API under /api and its identity
// server under /identity.
func endpointsOf(server vault.Server) endpoints {
	if cloud, ok := clouds[server.String()]; ok {
		return cloud
	}
	return endpoints{API: server.String() + "/api", Identity: server.String() + "/identity", Send: server.String() + "/#/send/"}
}

// Device is how this client registers with the server: its stable
// identifier and the name the account's device list shows.
type Device struct {
	ID, Name string
}

// The client identity: the desktop client id and Bitwarden's
// LinuxDesktop device type, the category this client is.
const (
	clientID          = "desktop"
	deviceTypeLinux   = "8"
	httpTimeout       = 30 * time.Second
	maxRedirects      = 10
	maxResponseBytes  = 64 << 20
	newDeviceMessage  = "new device verification required"
	tokenScope        = "api offline_access" //nolint:gosec // an OAuth scope, not a credential
	apiKeyScope       = "api"
	formContentType   = "application/x-www-form-urlencoded; charset=utf-8"
	jsonContentType   = "application/json"
	headerDeviceType  = "Device-Type"
	headerClientName  = "Bitwarden-Client-Name"
	headerAuthEmail   = "Auth-Email"
	headerContentType = "Content-Type"
	headerAccept      = "Accept"
	headerAuth        = "Authorization"
)

// Client talks to one server as one device. Every request carries the
// caller's context and a timeout.
type Client struct {
	server endpoints
	device Device
	http   *http.Client
}

// NewClient is a client for server as device.
func NewClient(server vault.Server, device Device) *Client {
	return &Client{server: endpointsOf(server), device: device, http: &http.Client{Timeout: httpTimeout, CheckRedirect: checkRedirect}}
}

// checkRedirect keeps net/http's limit on redirects and refuses one that
// would downgrade the connection, since a 307 resends the password hash
// and a same-host redirect keeps the bearer token.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	return vault.CheckTransport(req.URL)
}

// APIError is a server answer the flow does not handle: the operation
// and the server's status and message.
type APIError struct {
	Op string
	vault.ServerError
}

func (e *APIError) Error() string { return "bitwarden: " + e.Op + ": " + e.ServerError.Error() }

// Unwrap is the server's answer, as the vault contract reports it.
func (e *APIError) Unwrap() error { return &e.ServerError }

func apiError(op string, status int, message string) *APIError {
	return &APIError{Op: op, Status: status, Message: message}
}

// Prelogin is an account's key derivation and its master-password salt.
type Prelogin struct {
	Kdf  Kdf
	Salt string
}

// Prelogin asks how the account derives its master key. Older servers
// (Vaultwarden among them) answer only the original endpoint, without a
// salt: then the salt is the email.
func (c *Client) Prelogin(ctx context.Context, email string) (Prelogin, error) {
	body, err := json.Marshal(map[string]string{"email": email})
	if err != nil {
		return Prelogin{}, fmt.Errorf("bitwarden: prelogin request: %w", err)
	}
	var current struct {
		KdfSettings struct {
			KdfType     KdfType
			Iterations  int
			Memory      *int
			Parallelism *int
		}
		Salt string
	}
	status, err := c.postJSON(ctx, "prelogin", c.server.Identity+"/accounts/prelogin/password", body, &current)
	if err == nil {
		k := current.KdfSettings
		p := Prelogin{Kdf: Kdf{Type: k.KdfType, Iterations: k.Iterations, Memory: deref(k.Memory), Parallelism: deref(k.Parallelism)}, Salt: current.Salt}
		if p.Salt == "" {
			p.Salt = email
		}
		return p, nil
	}
	if status != http.StatusNotFound {
		return Prelogin{}, err
	}
	var legacy struct {
		Kdf            KdfType
		KdfIterations  int
		KdfMemory      *int
		KdfParallelism *int
	}
	if _, err := c.postJSON(ctx, "prelogin", c.server.Identity+"/accounts/prelogin", body, &legacy); err != nil {
		return Prelogin{}, err
	}
	return Prelogin{Kdf: Kdf{Type: legacy.Kdf, Iterations: legacy.KdfIterations, Memory: deref(legacy.KdfMemory), Parallelism: deref(legacy.KdfParallelism)}, Salt: email}, nil
}

func deref(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// Token is a login's answer: the access and refresh tokens, when the
// access token expires, and the account's wrapped keys.
type Token struct {
	AccessToken  string
	RefreshToken string
	Expires      time.Time
	Key          string
	PrivateKey   string
}

// PasswordLogin exchanges the master password hash for tokens. A second
// factor or a new device's emailed code, when the server asks, comes as
// TwoFactorRequiredError or ErrNewDeviceVerification; retry with it.
func (c *Client) PasswordLogin(ctx context.Context, email, passwordHash string, tf *vault.TwoFactor, newDeviceOTP string, now time.Time) (Token, error) {
	form := c.tokenForm()
	form.Set("grant_type", "password")
	form.Set("username", email)
	form.Set("password", passwordHash)
	form.Set("scope", tokenScope)
	form.Set("client_id", clientID)
	if tf != nil {
		form.Set("twoFactorToken", tf.Code)
		form.Set("twoFactorProvider", strconv.Itoa(int(tf.Provider)))
		form.Set("twoFactorRemember", "0")
	}
	if newDeviceOTP != "" {
		form.Set("newDeviceOtp", newDeviceOTP)
	}
	return c.token(ctx, "login", form, base64.RawURLEncoding.EncodeToString([]byte(email)), now)
}

// APIKeyLogin logs in with the account's personal API key: no second
// factor or device check, for the factors this client does not speak.
func (c *Client) APIKeyLogin(ctx context.Context, id, secret string, now time.Time) (Token, error) {
	form := c.tokenForm()
	form.Set("grant_type", "client_credentials")
	form.Set("scope", apiKeyScope)
	form.Set("client_id", id)
	form.Set("client_secret", secret)
	return c.token(ctx, "API key login", form, "", now)
}

// Refresh trades the refresh token for a new access token, under the
// client id that logged in.
func (c *Client) Refresh(ctx context.Context, refreshToken, loginClientID string, now time.Time) (Token, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", loginClientID)
	form.Set("refresh_token", refreshToken)
	t, err := c.token(ctx, "refresh", form, "", now)
	if err == nil && t.RefreshToken == "" {
		t.RefreshToken = refreshToken
	}
	return t, err
}

func (c *Client) tokenForm() url.Values {
	form := url.Values{}
	form.Set("deviceType", deviceTypeLinux)
	form.Set("deviceIdentifier", c.device.ID)
	form.Set("deviceName", c.device.Name)
	return form
}

// token posts a /connect/token form and reads the answer or the
// challenge in it.
func (c *Client) token(ctx context.Context, op string, form url.Values, authEmail string, now time.Time) (Token, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.server.Identity+"/connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return Token{}, fmt.Errorf("bitwarden: %s request: %w", op, err)
	}
	req.Header.Set(headerContentType, formContentType)
	req.Header.Set(headerAccept, jsonContentType)
	req.Header.Set(headerDeviceType, deviceTypeLinux)
	req.Header.Set(headerClientName, clientID)
	if authEmail != "" {
		req.Header.Set(headerAuthEmail, authEmail)
	}
	status, raw, err := c.do(req, op)
	if err != nil {
		return Token{}, err
	}
	var body struct {
		AccessToken         string `json:"access_token"`
		RefreshToken        string `json:"refresh_token"`
		ExpiresIn           int    `json:"expires_in"`
		Key                 string
		PrivateKey          string
		TwoFactorProviders2 map[string]json.RawMessage
		ErrorModel          struct{ Message string }
		Error               string `json:"error"`
		ErrorDescription    string `json:"error_description"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			return Token{}, fmt.Errorf("bitwarden: %s: HTTP %d with an unreadable body: %w", op, status, err)
		}
	}
	switch {
	case status == http.StatusOK:
		if body.AccessToken == "" {
			return Token{}, fmt.Errorf("bitwarden: %s: the answer has no access token", op)
		}
		return Token{
			AccessToken: body.AccessToken, RefreshToken: body.RefreshToken,
			Expires: now.Add(time.Duration(body.ExpiresIn) * time.Second),
			Key:     body.Key, PrivateKey: body.PrivateKey,
		}, nil
	case status == http.StatusBadRequest && len(body.TwoFactorProviders2) > 0:
		e := &vault.TwoFactorRequiredError{}
		for k := range body.TwoFactorProviders2 {
			if p, err := strconv.ParseUint(k, 10, 32); err == nil {
				e.Providers = append(e.Providers, vault.TwoFactorProvider(p))
			}
		}
		slices.Sort(e.Providers)
		return Token{}, e
	case status == http.StatusBadRequest && strings.EqualFold(body.ErrorModel.Message, newDeviceMessage):
		return Token{}, vault.ErrNewDeviceVerification
	case status == http.StatusBadRequest && body.Error == "invalid_grant":
		return Token{}, fmt.Errorf("%w: %s", vault.ErrInvalidCredentials, firstNonEmpty(body.ErrorModel.Message, body.ErrorDescription))
	default:
		return Token{}, apiError(op, status, firstNonEmpty(body.ErrorModel.Message, body.ErrorDescription, body.Error))
	}
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// SendLoginEmail asks the server to email the login's second-factor
// code.
func (c *Client) SendLoginEmail(ctx context.Context, email, passwordHash string) error {
	body, err := json.Marshal(map[string]string{"email": email, "masterPasswordHash": passwordHash, "deviceIdentifier": c.device.ID})
	if err != nil {
		return fmt.Errorf("bitwarden: login email request: %w", err)
	}
	_, err = c.postJSON(ctx, "send the login email", c.server.API+"/two-factor/send-email-login", body, nil)
	return err
}

// Sync fetches the account: its profile with the wrapped keys, folders,
// collections and ciphers.
func (c *Client) Sync(ctx context.Context, accessToken string) (SyncResponse, error) {
	var s SyncResponse
	if err := c.api(ctx, "sync", http.MethodGet, "/sync?excludeDomains=true", accessToken, nil, &s); err != nil {
		return SyncResponse{}, err
	}
	return s, nil
}

func (c *Client) CreateCipher(ctx context.Context, accessToken string, req cipherRequest) (SyncCipher, error) {
	var created SyncCipher
	if err := c.api(ctx, "create a login", http.MethodPost, "/ciphers", accessToken, req, &created); err != nil {
		return SyncCipher{}, err
	}
	if created.ID == "" {
		return SyncCipher{}, errors.New("bitwarden: create a login: the answer has no id")
	}
	return created, nil
}

func (c *Client) CreateSend(ctx context.Context, accessToken string, req sendRequest) (SyncSend, error) {
	var created SyncSend
	if err := c.api(ctx, "create a Send", http.MethodPost, "/sends", accessToken, req, &created); err != nil {
		return SyncSend{}, err
	}
	if created.ID == "" || created.AccessID == "" {
		return SyncSend{}, errors.New("bitwarden: create a Send: the answer has no id or access id")
	}
	return created, nil
}

func (c *Client) DeleteSend(ctx context.Context, accessToken string, id vault.SendID) error {
	return c.api(ctx, "delete a Send", http.MethodDelete, "/sends/"+url.PathEscape(string(id)), accessToken, nil, nil)
}

func (c *Client) sendURL(accessID string, material []byte) (string, error) {
	if accessID == "" || strings.Trim(accessID, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
		return "", fmt.Errorf("bitwarden: the Send access id %q is not base64url", accessID)
	}
	return c.server.Send + accessID + "/" + base64.RawURLEncoding.EncodeToString(material), nil
}

func (c *Client) api(ctx context.Context, op, method, path, accessToken string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("bitwarden: %s request: %w", op, err)
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.server.API+path, body)
	if err != nil {
		return fmt.Errorf("bitwarden: %s request: %w", op, err)
	}
	if in != nil {
		req.Header.Set(headerContentType, jsonContentType)
	}
	req.Header.Set(headerAuth, "Bearer "+accessToken)
	req.Header.Set(headerAccept, jsonContentType)
	req.Header.Set(headerDeviceType, deviceTypeLinux)
	req.Header.Set(headerClientName, clientID)
	status, raw, err := c.do(req, op)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return apiError(op, status, errorMessage(raw))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("bitwarden: %s: unreadable answer: %w", op, err)
	}
	return nil
}

// postJSON posts body and decodes a 200's JSON into out (nil to ignore
// it), returning the status so a caller can branch on a 404.
func (c *Client) postJSON(ctx context.Context, op, endpoint string, body []byte, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return 0, fmt.Errorf("bitwarden: %s request: %w", op, err)
	}
	req.Header.Set(headerContentType, jsonContentType)
	req.Header.Set(headerAccept, jsonContentType)
	req.Header.Set(headerDeviceType, deviceTypeLinux)
	req.Header.Set(headerClientName, clientID)
	status, raw, err := c.do(req, op)
	if err != nil {
		return 0, err
	}
	if status != http.StatusOK {
		return status, apiError(op, status, errorMessage(raw))
	}
	if out == nil {
		return status, nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return status, fmt.Errorf("bitwarden: %s: unreadable answer: %w", op, err)
	}
	return status, nil
}

func (c *Client) do(req *http.Request, op string) (int, []byte, error) {
	resp, err := c.http.Do(req)
	if errors.Is(err, vault.ErrInsecureServer) {
		return 0, nil, fmt.Errorf("bitwarden: %s: the server redirected: %w", op, err)
	}
	if err != nil {
		return 0, nil, fmt.Errorf("bitwarden: %s: %w: %w", op, vault.ErrUnreachable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return 0, nil, fmt.Errorf("bitwarden: %s: read the answer: %w", op, err)
	}
	return resp.StatusCode, raw, nil
}

// errorMessage is the message in an error body, "" when there is none.
func errorMessage(raw []byte) string {
	var body struct {
		Message    string
		ErrorModel struct{ Message string }
	}
	if json.Unmarshal(raw, &body) != nil {
		return ""
	}
	return firstNonEmpty(body.ErrorModel.Message, body.Message)
}
