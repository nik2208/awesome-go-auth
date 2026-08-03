package echo

import (
	"net/http"

	"github.com/labstack/echo/v4"
	auth "github.com/nik2208/awesome-go-auth"
	nethttpadapter "github.com/nik2208/awesome-go-auth/adapter/nethttp"
)

const userContextKey = "awesome_go_auth_user"

// UserFromContext extracts authenticated user from echo.Context.
func UserFromContext(c echo.Context) (auth.User, bool) {
	v := c.Get(userContextKey)
	if v == nil {
		return auth.User{}, false
	}
	user, ok := v.(auth.User)
	return user, ok
}

// Adapter serves the auth routes on Echo. Responses are written through the
// shared wire helpers rather than echo's own JSON writer so that every adapter
// emits byte-identical bodies and cookies.
type Adapter struct {
	auth *auth.Auth
	cfg  auth.HTTPConfig
}

// New returns an Echo adapter using the default wire conventions.
func New(a *auth.Auth) *Adapter {
	return NewWithConfig(a, auth.DefaultHTTPConfig())
}

// NewWithConfig returns an Echo adapter using the supplied wire conventions.
func NewWithConfig(a *auth.Auth, cfg auth.HTTPConfig) *Adapter {
	return &Adapter{auth: a, cfg: a.ResolveHTTPConfig(cfg)}
}

// Config reports the resolved wire conventions this adapter serves.
func (ad *Adapter) Config() auth.HTTPConfig { return ad.cfg }

// Middleware returns an Echo-native middleware.
func Middleware(a *auth.Auth) echo.MiddlewareFunc {
	return New(a).Middleware()
}

// Mount mounts auth routes on an Echo group.
func Mount(group *echo.Group, a *auth.Auth) {
	New(a).Mount(group)
}

// MountWithConfig mounts auth routes using the supplied wire conventions.
func MountWithConfig(group *echo.Group, a *auth.Auth, cfg auth.HTTPConfig) {
	NewWithConfig(a, cfg).Mount(group)
}

// Middleware validates access tokens and injects the user into the context.
func (ad *Adapter) Middleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			token := auth.AccessTokenFromRequest(c.Request())
			if token == "" {
				auth.WriteHTTPError(c.Response(), auth.HTTPErrNoAccessToken)
				return nil
			}
			user, err := ad.auth.Me(c.Request().Context(), token)
			if err != nil {
				auth.WriteHTTPError(c.Response(), auth.AccessHTTPError(err))
				return nil
			}
			c.Set(userContextKey, user)
			return next(c)
		}
	}
}

// Mount attaches the auth endpoints.
func (ad *Adapter) Mount(group *echo.Group) {
	prefix := ad.cfg.Prefix()
	group.POST(prefix+"/register", ad.guard(ad.register))
	group.POST(prefix+"/login", ad.guard(ad.login))
	group.POST(prefix+"/refresh", ad.guard(ad.refresh))
	group.POST(prefix+"/logout", ad.guard(ad.logout))
	group.GET(prefix+"/me", ad.guard(ad.Middleware()(ad.me)))

	// Sessions and account management (account.go).
	group.GET(prefix+"/sessions", ad.guard(ad.Middleware()(ad.sessions)))
	group.DELETE(prefix+"/sessions/:handle", ad.guard(ad.Middleware()(ad.revokeSession)))
	group.POST(prefix+"/sessions/cleanup", ad.guard(ad.cleanupSessions))
	group.PATCH(prefix+"/profile", ad.guard(ad.Middleware()(ad.updateProfile)))
	group.POST(prefix+"/add-phone", ad.guard(ad.Middleware()(ad.addPhone)))
	group.DELETE(prefix+"/account", ad.guard(ad.Middleware()(ad.deleteAccount)))

	// Passwordless and 2FA (passwordless.go). The four send/verify routes are
	// unauthenticated by contract; the three enrolment routes sit behind the
	// access-token middleware and are therefore the only ones CSRF-checked.
	group.POST(prefix+"/magic-link/send", ad.guard(ad.magicLinkSend))
	group.POST(prefix+"/magic-link/verify", ad.guard(ad.magicLinkVerify))
	group.POST(prefix+"/sms/send", ad.guard(ad.smsSend))
	group.POST(prefix+"/sms/verify", ad.guard(ad.smsVerify))
	group.POST(prefix+"/2fa/setup", ad.guard(ad.Middleware()(ad.twoFactorSetup)))
	group.POST(prefix+"/2fa/verify-setup", ad.guard(ad.Middleware()(ad.twoFactorVerifySetup)))
	group.POST(prefix+"/2fa/verify", ad.guard(ad.twoFactorVerify))
	group.POST(prefix+"/2fa/disable", ad.guard(ad.Middleware()(ad.twoFactorDisable)))
	ad.mountPasswordEmail(group, prefix)

	// OAuth and account linking. Echo registers the routes with its own
	// ":param" syntax but serves the shared net/http handlers: the group's
	// behaviour is entirely path- and body-driven, so re-implementing it here
	// would only create somewhere for the adapters to drift.
	oauth := nethttpadapter.NewWithConfig(ad.auth, ad.cfg)
	group.GET(prefix+"/oauth/:provider", serveHTTP(oauth.OAuthAuthorizeHandler()))
	group.GET(prefix+"/oauth/:provider/callback", serveHTTP(oauth.OAuthCallbackHandler()))
	group.GET(prefix+"/linked-accounts", serveHTTP(oauth.LinkedAccountsHandler()))
	group.DELETE(prefix+"/linked-accounts/:provider/:providerAccountId", serveHTTP(oauth.UnlinkAccountHandler()))
	group.POST(prefix+"/link-request", serveHTTP(oauth.LinkRequestHandler()))
	group.POST(prefix+"/link-verify", serveHTTP(oauth.LinkVerifyHandler()))
}

// serveHTTP adapts a net/http handler to echo. The handler writes the whole
// response, so there is nothing left for echo to render.
func serveHTTP(h http.Handler) echo.HandlerFunc {
	return func(c echo.Context) error {
		h.ServeHTTP(c.Response(), c.Request())
		return nil
	}
}

// guard runs the shared CSRF middleware in front of an Echo handler. Reusing
// the net/http middleware — rather than reimplementing it here — is what keeps
// the enforcement matrix identical across adapters.
func (ad *Adapter) guard(h echo.HandlerFunc) echo.HandlerFunc {
	mw := auth.CSRFMiddleware(ad.cfg)
	return func(c echo.Context) error {
		var err error
		mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			c.SetRequest(r)
			err = h(c)
		})).ServeHTTP(c.Response(), c.Request())
		return err
	}
}

func (ad *Adapter) register(c echo.Context) error {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		TenantID string `json:"tenantId"`
	}
	if err := c.Bind(&req); err != nil {
		auth.WriteHTTPError(c.Response(), auth.HTTPErrInvalidBody)
		return nil
	}
	user, tokens, err := ad.auth.Register(c.Request().Context(), auth.RegisterInput{Email: req.Email, Password: req.Password, TenantID: req.TenantID})
	if err != nil {
		auth.WriteServiceError(c.Response(), err)
		return nil
	}
	ad.cfg.WriteTokens(c.Response(), c.Request(), http.StatusCreated, tokens, map[string]any{"userId": user.ID})
	return nil
}

func (ad *Adapter) login(c echo.Context) error {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		TenantID string `json:"tenantId"`
	}
	if err := c.Bind(&req); err != nil {
		auth.WriteHTTPError(c.Response(), auth.HTTPErrInvalidBody)
		return nil
	}
	_, tokens, err := ad.auth.Login(c.Request().Context(), auth.LoginInput{Email: req.Email, Password: req.Password, TenantID: req.TenantID})
	if err != nil {
		auth.WriteServiceError(c.Response(), err)
		return nil
	}
	ad.cfg.WriteTokens(c.Response(), c.Request(), http.StatusOK, tokens, nil)
	return nil
}

func (ad *Adapter) refresh(c echo.Context) error {
	refresh := auth.RefreshTokenFromRequest(c.Request())
	if refresh == "" {
		auth.WriteHTTPError(c.Response(), auth.HTTPErrNoRefreshToken)
		return nil
	}
	tokens, err := ad.auth.Refresh(c.Request().Context(), refresh)
	if err != nil {
		auth.WriteHTTPError(c.Response(), auth.RefreshHTTPError(err))
		return nil
	}
	ad.cfg.WriteTokens(c.Response(), c.Request(), http.StatusOK, tokens, nil)
	return nil
}

func (ad *Adapter) logout(c echo.Context) error {
	ad.auth.LogoutRequest(c.Request().Context(), c.Request())
	ad.cfg.Cookies.ClearAuthCookies(c.Response(), ad.cfg.CSRF.Enabled)
	auth.WriteSuccess(c.Response(), http.StatusOK, nil)
	return nil
}

func (ad *Adapter) me(c echo.Context) error {
	user, ok := UserFromContext(c)
	if !ok {
		auth.WriteHTTPError(c.Response(), auth.HTTPErrNoAccessToken)
		return nil
	}
	auth.WriteJSON(c.Response(), http.StatusOK, auth.NewPublicUser(user))
	return nil
}
