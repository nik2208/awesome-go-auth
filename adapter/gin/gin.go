package gin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	auth "github.com/nik2208/awesome-go-auth"
	nethttpadapter "github.com/nik2208/awesome-go-auth/adapter/nethttp"
)

const userContextKey = "awesome_go_auth_user"

// UserFromContext extracts authenticated user from gin.Context.
func UserFromContext(c *gin.Context) (auth.User, bool) {
	v, ok := c.Get(userContextKey)
	if !ok {
		return auth.User{}, false
	}
	user, ok := v.(auth.User)
	return user, ok
}

// Adapter serves the auth routes on Gin. Responses are written through the
// shared wire helpers rather than gin's own JSON writer so that every adapter
// emits byte-identical bodies and cookies.
type Adapter struct {
	auth *auth.Auth
	cfg  auth.HTTPConfig
}

// New returns a Gin adapter using the default wire conventions.
func New(a *auth.Auth) *Adapter {
	return NewWithConfig(a, auth.DefaultHTTPConfig())
}

// NewWithConfig returns a Gin adapter using the supplied wire conventions.
func NewWithConfig(a *auth.Auth, cfg auth.HTTPConfig) *Adapter {
	return &Adapter{auth: a, cfg: a.ResolveHTTPConfig(cfg)}
}

// Config reports the resolved wire conventions this adapter serves.
func (ad *Adapter) Config() auth.HTTPConfig { return ad.cfg }

// Middleware returns a Gin-native middleware.
func Middleware(a *auth.Auth) gin.HandlerFunc {
	return New(a).Middleware()
}

// Mount mounts all auth routes into a Gin RouterGroup.
func Mount(group gin.IRoutes, a *auth.Auth) {
	New(a).Mount(group)
}

// MountWithConfig mounts all auth routes using the supplied wire conventions.
func MountWithConfig(group gin.IRoutes, a *auth.Auth, cfg auth.HTTPConfig) {
	NewWithConfig(a, cfg).Mount(group)
}

// Middleware validates access tokens and injects the user into the context.
func (ad *Adapter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := auth.AccessTokenFromRequest(c.Request)
		if token == "" {
			auth.WriteHTTPError(c.Writer, auth.HTTPErrNoAccessToken)
			c.Abort()
			return
		}
		user, err := ad.auth.Me(c.Request.Context(), token)
		if err != nil {
			auth.WriteHTTPError(c.Writer, auth.AccessHTTPError(err))
			c.Abort()
			return
		}
		c.Set(userContextKey, user)
		c.Next()
	}
}

// Mount attaches the auth endpoints.
func (ad *Adapter) Mount(group gin.IRoutes) {
	prefix := ad.cfg.Prefix()
	group.POST(prefix+"/register", ad.guard(ad.register))
	group.POST(prefix+"/login", ad.guard(ad.login))
	group.POST(prefix+"/refresh", ad.guard(ad.refresh))
	group.POST(prefix+"/logout", ad.guard(ad.logout))
	group.GET(prefix+"/me", ad.guard(ad.Middleware()), ad.me)

	// OAuth and account linking. Gin registers the routes with its own ":param"
	// syntax but serves the shared net/http handlers: the group's behaviour is
	// entirely path- and body-driven, so re-implementing it here would only
	// create somewhere for the adapters to drift.
	oauth := nethttpadapter.NewWithConfig(ad.auth, ad.cfg)
	group.GET(prefix+"/oauth/:provider", serveHTTP(oauth.OAuthAuthorizeHandler()))
	group.GET(prefix+"/oauth/:provider/callback", serveHTTP(oauth.OAuthCallbackHandler()))
	group.GET(prefix+"/linked-accounts", serveHTTP(oauth.LinkedAccountsHandler()))
	// The unlink route is registered as a catch-all, not as two path parameters.
	// Gin matches on the UNESCAPED path, so a providerAccountId containing %2F —
	// which net/http, chi and echo all deliver to the handler intact, as Express
	// does — arrives here as three segments and would miss a two-parameter
	// pattern entirely, giving gin a 404 where every other adapter answers 200.
	// The shared handler reads its parameters off r.URL.EscapedPath() and rejects
	// any shape that is not exactly <provider>/<providerAccountId> with the same
	// bare 404 the other routers emit, so the catch-all widens what reaches the
	// handler without widening what the route answers. The bare :provider entry
	// is there to keep gin from answering a one-segment path with a 307 to the
	// catch-all's trailing slash.
	group.DELETE(prefix+"/linked-accounts/:provider", serveHTTP(oauth.UnlinkAccountHandler()))
	group.DELETE(prefix+"/linked-accounts/:provider/*providerAccountId", serveHTTP(oauth.UnlinkAccountHandler()))
	group.POST(prefix+"/link-request", serveHTTP(oauth.LinkRequestHandler()))
	group.POST(prefix+"/link-verify", serveHTTP(oauth.LinkVerifyHandler()))
}

// serveHTTP adapts a net/http handler to gin. The handler is terminal, so
// there is no chain left to abort.
func serveHTTP(h http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) { h.ServeHTTP(c.Writer, c.Request) }
}

// guard runs the shared CSRF middleware in front of a Gin handler. Reusing the
// net/http middleware — rather than reimplementing it here — is what keeps the
// enforcement matrix identical across adapters.
func (ad *Adapter) guard(h gin.HandlerFunc) gin.HandlerFunc {
	mw := auth.CSRFMiddleware(ad.cfg)
	return func(c *gin.Context) {
		reached := false
		mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			reached = true
			c.Request = r
			h(c)
		})).ServeHTTP(c.Writer, c.Request)
		if !reached {
			// The middleware rejected the request and already wrote the body;
			// gin would otherwise run the rest of the chain on top of it.
			c.Abort()
		}
	}
}

func (ad *Adapter) register(c *gin.Context) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		TenantID string `json:"tenantId"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrInvalidBody)
		return
	}
	user, tokens, err := ad.auth.Register(c.Request.Context(), auth.RegisterInput{Email: req.Email, Password: req.Password, TenantID: req.TenantID})
	if err != nil {
		auth.WriteServiceError(c.Writer, err)
		return
	}
	ad.cfg.WriteTokens(c.Writer, c.Request, http.StatusCreated, tokens, map[string]any{"userId": user.ID})
}

func (ad *Adapter) login(c *gin.Context) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		TenantID string `json:"tenantId"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrInvalidBody)
		return
	}
	_, tokens, err := ad.auth.Login(c.Request.Context(), auth.LoginInput{Email: req.Email, Password: req.Password, TenantID: req.TenantID})
	if err != nil {
		auth.WriteServiceError(c.Writer, err)
		return
	}
	ad.cfg.WriteTokens(c.Writer, c.Request, http.StatusOK, tokens, nil)
}

func (ad *Adapter) refresh(c *gin.Context) {
	refresh := auth.RefreshTokenFromRequest(c.Request)
	if refresh == "" {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrNoRefreshToken)
		return
	}
	tokens, err := ad.auth.Refresh(c.Request.Context(), refresh)
	if err != nil {
		auth.WriteHTTPError(c.Writer, auth.RefreshHTTPError(err))
		return
	}
	ad.cfg.WriteTokens(c.Writer, c.Request, http.StatusOK, tokens, nil)
}

func (ad *Adapter) logout(c *gin.Context) {
	ad.auth.LogoutRequest(c.Request.Context(), c.Request)
	ad.cfg.Cookies.ClearAuthCookies(c.Writer, ad.cfg.CSRF.Enabled)
	auth.WriteSuccess(c.Writer, http.StatusOK, nil)
}

func (ad *Adapter) me(c *gin.Context) {
	user, ok := UserFromContext(c)
	if !ok {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrNoAccessToken)
		return
	}
	auth.WriteJSON(c.Writer, http.StatusOK, auth.NewPublicUser(user))
}
