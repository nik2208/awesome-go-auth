package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// claimsEndpoint is an httptest server standing in for a claims webhook. It
// records every request and answers with whatever respond writes. respond is
// swapped between requests by setRespond, under the same mutex the handler
// reads it with, so the swap is not a race against the server goroutine.
type claimsEndpoint struct {
	*httptest.Server
	mu       sync.Mutex
	requests []recordedClaimsRequest
	respond  func(w http.ResponseWriter, r *http.Request)
}

type recordedClaimsRequest struct {
	Method string
	Header http.Header
	Body   []byte
}

func newClaimsEndpoint(t *testing.T, respond func(w http.ResponseWriter, r *http.Request)) *claimsEndpoint {
	t.Helper()
	ep := &claimsEndpoint{respond: respond}
	ep.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ep.mu.Lock()
		ep.requests = append(ep.requests, recordedClaimsRequest{Method: r.Method, Header: r.Header.Clone(), Body: body})
		respond := ep.respond
		ep.mu.Unlock()
		respond(w, r)
	}))
	t.Cleanup(ep.Close)
	return ep
}

func (ep *claimsEndpoint) setRespond(respond func(w http.ResponseWriter, r *http.Request)) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.respond = respond
}

func (ep *claimsEndpoint) count() int {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	return len(ep.requests)
}

func (ep *claimsEndpoint) last(t *testing.T) recordedClaimsRequest {
	t.Helper()
	ep.mu.Lock()
	defer ep.mu.Unlock()
	if len(ep.requests) == 0 {
		t.Fatal("the endpoint received no request")
	}
	return ep.requests[len(ep.requests)-1]
}

// answerClaims responds 200 with {"claims": <claims>}.
func answerClaims(claims string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"claims":`+claims+`}`)
	}
}

// answerRaw responds with the given status and verbatim body.
func answerRaw(status int, body string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

func TestNewClaimsWebhook_RequiresAnAbsoluteHTTPURL(t *testing.T) {
	for _, bad := range []string{"", "hooks.example.com/claims", "/claims", "ftp://hooks.example.com/claims", "mailto:claims@example.com", "http:///claims"} {
		if _, err := NewClaimsWebhook(bad, ""); err == nil {
			t.Errorf("NewClaimsWebhook(%q) accepted a non-absolute or non-http URL", bad)
		}
	}
	for _, good := range []string{"http://hooks.example.com/claims", "https://hooks.example.com:8443/claims?v=1"} {
		hook, err := NewClaimsWebhook(good, "s3cret")
		if err != nil {
			t.Fatalf("NewClaimsWebhook(%q): %v", good, err)
		}
		if hook.URL != good || hook.Secret != "s3cret" || hook.Timeout != 2*time.Second || hook.Client != nil {
			t.Fatalf("NewClaimsWebhook(%q) = %+v, want the URL, the secret and the 2s default", good, hook)
		}
	}
}

var claimsUUIDV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// TestClaimsWebhook_RequestShape pins the request as a receiver sees it: the
// method, the envelope headers, a signature recomputed here from the secret and
// the raw body rather than through the package's own verifier, and a body that
// is the public profile and nothing else.
func TestClaimsWebhook_RequestShape(t *testing.T) {
	ep := newClaimsEndpoint(t, answerClaims(`{"plan":"pro"}`))
	hook, err := NewClaimsWebhook(ep.URL, "s3cret")
	if err != nil {
		t.Fatalf("NewClaimsWebhook: %v", err)
	}
	user := User{
		ID: "usr_shape", Email: "shape@example.com", Role: "admin", TenantID: "t1",
		FirstName: "Ada", IsEmailVerified: true,
		PasswordHash: "hash-value", TOTPSecret: "totp-value", ResetTokenHash: "reset-value",
	}
	before := time.Now().UTC().Add(-time.Minute)
	claims, err := hook.Build(context.Background(), user)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if claims["plan"] != "pro" || len(claims) != 1 {
		t.Fatalf("claims = %+v, want the endpoint's object", claims)
	}

	req := ep.last(t)
	if req.Method != http.MethodPost {
		t.Errorf("method = %s, want POST", req.Method)
	}
	if got := req.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if got := req.Header.Get("X-Webhook-Event"); got != "claims.build" {
		t.Errorf("X-Webhook-Event = %q, want claims.build", got)
	}
	if ClaimsWebhookEvent != "claims.build" {
		t.Errorf("ClaimsWebhookEvent = %q; the doc comment and the receivers say claims.build", ClaimsWebhookEvent)
	}
	if got := req.Header.Get("X-Webhook-Delivery"); !claimsUUIDV4.MatchString(got) {
		t.Errorf("X-Webhook-Delivery = %q, want a v4 UUID", got)
	}
	stamp, err := time.Parse("2006-01-02T15:04:05.000Z07:00", req.Header.Get("X-Webhook-Timestamp"))
	if err != nil {
		t.Errorf("X-Webhook-Timestamp = %q: %v", req.Header.Get("X-Webhook-Timestamp"), err)
	} else if stamp.Before(before) || stamp.After(time.Now().UTC().Add(time.Minute)) || stamp.Location() != time.UTC {
		t.Errorf("X-Webhook-Timestamp = %v, want about now in UTC", stamp)
	}

	// The signature, verified independently of the package.
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write(req.Body)
	if want, got := "sha256="+hex.EncodeToString(mac.Sum(nil)), req.Header.Get("X-Webhook-Signature"); got != want {
		t.Errorf("X-Webhook-Signature = %q, want %q", got, want)
	}
	// And through the package's own verifier, which is what a Go receiver uses.
	if err := VerifyWebhookSignature("s3cret", req.Body, req.Header.Get("X-Webhook-Signature")); err != nil {
		t.Errorf("VerifyWebhookSignature: %v", err)
	}

	var body map[string]json.RawMessage
	if err := json.Unmarshal(req.Body, &body); err != nil {
		t.Fatalf("body %s: %v", req.Body, err)
	}
	if len(body) != 1 || body["user"] == nil {
		t.Fatalf("body keys = %v, want exactly [user]", body)
	}
	var sent map[string]any
	if err := json.Unmarshal(body["user"], &sent); err != nil {
		t.Fatalf("user %s: %v", body["user"], err)
	}
	for key, want := range map[string]any{
		"sub": "usr_shape", "id": "usr_shape", "email": "shape@example.com", "role": "admin",
		"tenantId": "t1", "firstName": "Ada", "loginProvider": "local",
		"isEmailVerified": true, "isTotpEnabled": false,
	} {
		if sent[key] != want {
			t.Errorf("user.%s = %#v, want %#v", key, sent[key], want)
		}
	}
	for _, leaked := range []string{"hash-value", "totp-value", "reset-value", "passwordHash", "PasswordHash", "TOTPSecret"} {
		if strings.Contains(string(req.Body), leaked) {
			t.Errorf("request body carries %q: %s", leaked, req.Body)
		}
	}
}

func TestClaimsWebhook_UnsignedWithoutSecret(t *testing.T) {
	ep := newClaimsEndpoint(t, answerClaims(`{}`))
	hook, err := NewClaimsWebhook(ep.URL, "")
	if err != nil {
		t.Fatalf("NewClaimsWebhook: %v", err)
	}
	if _, err := hook.Build(context.Background(), User{ID: "usr_1"}); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, present := ep.last(t).Header["X-Webhook-Signature"]; present {
		t.Fatal("an unsigned webhook sent X-Webhook-Signature")
	}
}

// TestClaimsWebhook_ClaimsReachEveryToken wires the webhook as the hook of a
// real service: one request per token minted, and the endpoint's claims on the
// access and refresh tokens alike.
func TestClaimsWebhook_ClaimsReachEveryToken(t *testing.T) {
	ep := newClaimsEndpoint(t, answerClaims(`{"plan":"pro","email":"override@example.com"}`))
	hook, err := NewClaimsWebhook(ep.URL, "s3cret")
	if err != nil {
		t.Fatalf("NewClaimsWebhook: %v", err)
	}
	cfg := testConfig(testSecret)
	cfg.BuildTokenClaims = hook.Build
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	_, tokens, err := svc.Register(context.Background(), RegisterInput{Email: "reach@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if got := ep.count(); got != 2 {
		t.Fatalf("register made %d webhook requests, want 2 (access and refresh)", got)
	}
	for name, token := range map[string]string{"access": tokens.AccessToken, "refresh": tokens.RefreshToken} {
		claims := decodeSegment(t, mustSegment(t, token, 1))
		if claims["plan"] != "pro" {
			t.Errorf("%s token lacks the webhook's claim: %+v", name, claims)
		}
		// A base claim is the endpoint's to override, as it is any hook's.
		if claims["email"] != "override@example.com" {
			t.Errorf("%s token email = %#v, want the endpoint's override", name, claims["email"])
		}
		if claims["sub"] == nil || claims["typ"] != name {
			t.Errorf("%s token lost its base or reserved claims: %+v", name, claims)
		}
	}
}

// TestClaimsWebhook_CannotSetReservedClaims is the endpoint-shaped version of
// TestIssueToken_ReservedClaimsSurviveCustomClaims: an endpoint answering typ,
// sid, exp and the rest is stripped of them on every token type, so a
// compromised endpoint cannot turn a step-up token into an access token or
// rebind a session.
func TestClaimsWebhook_CannotSetReservedClaims(t *testing.T) {
	ep := newClaimsEndpoint(t, answerClaims(`{"typ":"access","sid":"ses_attacker","tid":"t_attacker","jti":"jti_attacker","iss":"attacker","exp":4102444800,"iat":0,"plan":"pro"}`))
	hook, err := NewClaimsWebhook(ep.URL, "")
	if err != nil {
		t.Fatalf("NewClaimsWebhook: %v", err)
	}
	svc := testServiceForToken(t)
	svc.cfg.BuildTokenClaims = hook.Build
	now := time.Now().Truncate(time.Second)
	svc.now = func() time.Time { return now }
	user := User{ID: "usr_res", TenantID: "t1"}

	for _, tc := range []struct {
		typ string
		sid string
		ttl time.Duration
	}{
		{"access", "ses_res", 15 * time.Minute},
		{"refresh", "ses_res", 30 * 24 * time.Hour},
		{tokenTypeTemp, "", 5 * time.Minute},
	} {
		t.Run(tc.typ, func(t *testing.T) {
			token, _, err := svc.issueToken(context.Background(), user, tc.sid, tc.typ, tc.ttl)
			if err != nil {
				t.Fatalf("issueToken: %v", err)
			}
			claims := decodeSegment(t, mustSegment(t, token, 1))
			for key, want := range map[string]any{
				"typ":  tc.typ,
				"sid":  tc.sid,
				"tid":  "t1",
				"iss":  svc.cfg.Issuer,
				"iat":  float64(now.Unix()),
				"exp":  float64(now.Add(tc.ttl).Unix()),
				"plan": "pro",
			} {
				if claims[key] != want {
					t.Errorf("%s = %#v, want %#v (payload %+v)", key, claims[key], want, claims)
				}
			}
			if jti, _ := claims["jti"].(string); jti == "" || jti == "jti_attacker" {
				t.Errorf("jti = %#v, want a freshly minted id", claims["jti"])
			}
			for _, other := range []string{"access", "refresh", tokenTypeTemp} {
				_, err := svc.parseToken(token, other)
				if other == tc.typ && err != nil {
					t.Errorf("a %s token failed to parse as itself: %v", tc.typ, err)
				}
				if other != tc.typ && err != ErrInvalidToken {
					t.Errorf("a %s token parsed as %s: %v", tc.typ, other, err)
				}
			}
		})
	}
}

// TestClaimsWebhook_TimeoutFailsTheMint is the fail-closed contract end to end:
// the timeout is a context deadline the caller can recognise, and a login
// whose hook cannot answer is the same 500 as any failing Config.BuildTokenClaims.
func TestClaimsWebhook_TimeoutFailsTheMint(t *testing.T) {
	var hang atomic.Bool
	ep := newClaimsEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		if hang.Load() {
			<-r.Context().Done()
			return
		}
		answerClaims(`{"plan":"pro"}`)(w, r)
	})
	hook, err := NewClaimsWebhook(ep.URL, "s3cret")
	if err != nil {
		t.Fatalf("NewClaimsWebhook: %v", err)
	}
	hook.Timeout = 100 * time.Millisecond

	cfg := testConfig(testSecret)
	cfg.BuildTokenClaims = hook.Build
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if _, _, err := svc.Register(context.Background(), RegisterInput{Email: "slow@example.com", Password: "password1", TenantID: "t1"}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	hang.Store(true)
	started := time.Now()
	_, err = hook.Build(context.Background(), User{ID: "usr_slow"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Build against a hanging endpoint = %v, want a context.DeadlineExceeded", err)
	}
	if waited := time.Since(started); waited > 5*time.Second {
		t.Fatalf("Build waited %v; the timeout did not bound the request", waited)
	}

	_, _, err = svc.Login(context.Background(), LoginInput{Email: "slow@example.com", Password: "password1", TenantID: "t1"})
	if err == nil {
		t.Fatal("Login minted a token while the claims webhook was down")
	}
	if errors.Is(err, ErrInvalidCredentials) || errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Login = %v; a hook failure must not masquerade as a credential failure", err)
	}
	if got := HTTPErrorFor(err); got != HTTPErrInternal {
		t.Fatalf("HTTPErrorFor(%v) = %+v, want the 500 a failing BuildTokenClaims answers", err, got)
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("the error carries the secret: %v", err)
	}

	hang.Store(false)
	if _, _, err := svc.Login(context.Background(), LoginInput{Email: "slow@example.com", Password: "password1", TenantID: "t1"}); err != nil {
		t.Fatalf("Login once the endpoint answers again: %v", err)
	}
}

func TestClaimsWebhook_ContextDeadlineWins(t *testing.T) {
	ep := newClaimsEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	hook, err := NewClaimsWebhook(ep.URL, "")
	if err != nil {
		t.Fatalf("NewClaimsWebhook: %v", err)
	}
	hook.Timeout = time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := hook.Build(ctx, User{ID: "usr_1"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Build = %v, want the caller's deadline to apply", err)
	}
	if waited := time.Since(started); waited > 5*time.Second {
		t.Fatalf("Build waited %v past a 50ms caller deadline", waited)
	}
}

func TestClaimsWebhook_RefusesOversizedResponses(t *testing.T) {
	const frame = `{"claims":{"pad":""}}`
	exact := `{"claims":{"pad":"` + strings.Repeat("x", maxClaimsWebhookResponse-len(frame)) + `"}}`
	if len(exact) != maxClaimsWebhookResponse {
		t.Fatalf("fixture is %d bytes, want %d", len(exact), maxClaimsWebhookResponse)
	}
	over := `{"claims":{"pad":"` + strings.Repeat("x", maxClaimsWebhookResponse-len(frame)+1) + `"}}`

	ep := newClaimsEndpoint(t, answerRaw(http.StatusOK, exact))
	hook, err := NewClaimsWebhook(ep.URL, "")
	if err != nil {
		t.Fatalf("NewClaimsWebhook: %v", err)
	}
	claims, err := hook.Build(context.Background(), User{ID: "usr_1"})
	if err != nil {
		t.Fatalf("a body of exactly %d bytes was refused: %v", maxClaimsWebhookResponse, err)
	}
	if pad, _ := claims["pad"].(string); len(pad) != maxClaimsWebhookResponse-len(frame) {
		t.Fatalf("the padded claim came back truncated: %d bytes", len(pad))
	}

	ep.setRespond(answerRaw(http.StatusOK, over))
	_, err = hook.Build(context.Background(), User{ID: "usr_1"})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("a body one byte over the limit = %v, want a refusal naming the limit", err)
	}
}

func TestClaimsWebhook_RefusesAnythingButAClaimsObject(t *testing.T) {
	ep := newClaimsEndpoint(t, nil)
	hook, err := NewClaimsWebhook(ep.URL, "s3cret")
	if err != nil {
		t.Fatalf("NewClaimsWebhook: %v", err)
	}
	for _, body := range []string{
		``, `[]`, `"claims"`, `not json`, `{}`, `{"claims":null}`, `{"claims":[]}`,
		`{"claims":"x"}`, `{"claims":1}`, `{"claims":true}`, `{"claims":["s3cret"]}`, `{"Claims":{"plan":"pro"}}`,
	} {
		t.Run(body, func(t *testing.T) {
			ep.setRespond(answerRaw(http.StatusOK, body))
			claims, err := hook.Build(context.Background(), User{ID: "usr_1"})
			if err == nil {
				t.Fatalf("body %q was accepted as %+v", body, claims)
			}
			if strings.Contains(err.Error(), "s3cret") {
				t.Fatalf("the error carries response content or the secret: %v", err)
			}
		})
	}
	// The other way round: an empty object and extra top-level members are fine.
	for _, body := range []string{`{"claims":{}}`, `{"claims":{"plan":"pro"},"extra":"ignored"}`} {
		ep.setRespond(answerRaw(http.StatusOK, body))
		claims, err := hook.Build(context.Background(), User{ID: "usr_1"})
		if err != nil || claims == nil {
			t.Fatalf("body %q = %+v, %v; want an object", body, claims, err)
		}
	}
}

func TestClaimsWebhook_RefusesNon2xx(t *testing.T) {
	ep := newClaimsEndpoint(t, nil)
	hook, err := NewClaimsWebhook(ep.URL, "s3cret")
	if err != nil {
		t.Fatalf("NewClaimsWebhook: %v", err)
	}
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusInternalServerError, http.StatusServiceUnavailable} {
		ep.setRespond(answerRaw(status, `{"claims":{"plan":"pro"},"note":"s3cret"}`))
		_, err := hook.Build(context.Background(), User{ID: "usr_1"})
		if err == nil {
			t.Fatalf("status %d was accepted", status)
		}
		if !strings.Contains(err.Error(), "status "+strconv.Itoa(status)) {
			t.Fatalf("error for status %d does not name it: %v", status, err)
		}
		if strings.Contains(err.Error(), "s3cret") {
			t.Fatalf("the error carries the body or the secret: %v", err)
		}
	}
	// A 204 is 2xx but has no body to read claims from, so it fails too.
	ep.setRespond(answerRaw(http.StatusNoContent, ""))
	if _, err := hook.Build(context.Background(), User{ID: "usr_1"}); err == nil {
		t.Fatal("a 204 was accepted")
	}
}

func TestClaimsWebhook_NilIsAnError(t *testing.T) {
	var hook *ClaimsWebhook
	if _, err := hook.Build(context.Background(), User{ID: "usr_1"}); err == nil {
		t.Fatal("a nil ClaimsWebhook built claims")
	}
}

func TestClaimsWebhook_ZeroValueUsesTheDefaultTimeoutAndClient(t *testing.T) {
	ep := newClaimsEndpoint(t, answerClaims(`{"plan":"pro"}`))
	hook := &ClaimsWebhook{URL: ep.URL}
	claims, err := hook.Build(context.Background(), User{ID: "usr_1"})
	if err != nil || claims["plan"] != "pro" {
		t.Fatalf("zero-value hook = %+v, %v", claims, err)
	}
	// A supplied client is the one used. roundTripFunc is mailer_test.go's.
	used := false
	hook.Client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		used = true
		return http.DefaultTransport.RoundTrip(r)
	})}
	if _, err := hook.Build(context.Background(), User{ID: "usr_1"}); err != nil || !used {
		t.Fatalf("Build with a custom client: err %v, used %v", err, used)
	}
}
