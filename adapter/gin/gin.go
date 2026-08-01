package gin

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	auth "github.com/nik2208/awesome-go-auth"
)

const userContextKey = "awesome_go_auth_user"
const refreshCookieTTLMultiplier = 10

// UserFromContext extracts authenticated user from gin.Context.
func UserFromContext(c *gin.Context) (auth.User, bool) {
	v, ok := c.Get(userContextKey)
	if !ok {
		return auth.User{}, false
	}
	user, ok := v.(auth.User)
	return user, ok
}

// Middleware returns a Gin-native middleware.
func Middleware(a *auth.Auth) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := bearerToken(c.GetHeader("Authorization"))
		if token == "" {
			if cookie, err := c.Cookie("access_token"); err == nil {
				token = strings.TrimSpace(cookie)
			}
		}
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		user, err := a.Me(c.Request.Context(), token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		c.Set(userContextKey, user)
		c.Next()
	}
}

// Mount mounts all auth routes into a Gin RouterGroup.
func Mount(group gin.IRoutes, a *auth.Auth) {
	group.POST("/auth/register", func(c *gin.Context) {
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
			TenantID string `json:"tenantId"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
			return
		}
		user, tokens, err := a.Register(c.Request.Context(), auth.RegisterInput{Email: req.Email, Password: req.Password, TenantID: req.TenantID})
		if err != nil {
			writeError(c, err)
			return
		}
		setAuthCookies(c, tokens)
		c.JSON(http.StatusCreated, gin.H{"user": auth.NewPublicUser(user), "tokens": tokens})
	})

	group.POST("/auth/login", func(c *gin.Context) {
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
			TenantID string `json:"tenantId"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
			return
		}
		user, tokens, err := a.Login(c.Request.Context(), auth.LoginInput{Email: req.Email, Password: req.Password, TenantID: req.TenantID})
		if err != nil {
			writeError(c, err)
			return
		}
		setAuthCookies(c, tokens)
		c.JSON(http.StatusOK, gin.H{"user": auth.NewPublicUser(user), "tokens": tokens})
	})

	group.POST("/auth/refresh", func(c *gin.Context) {
		refresh := ""
		if cookie, err := c.Cookie("refresh_token"); err == nil {
			refresh = strings.TrimSpace(cookie)
		}
		if refresh == "" {
			var req struct {
				RefreshToken string `json:"refreshToken"`
			}
			if err := c.ShouldBindJSON(&req); err == nil {
				refresh = strings.TrimSpace(req.RefreshToken)
			}
		}
		if refresh == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing refresh token"})
			return
		}
		tokens, err := a.Refresh(c.Request.Context(), refresh)
		if err != nil {
			writeError(c, err)
			return
		}
		setAuthCookies(c, tokens)
		c.JSON(http.StatusOK, gin.H{"tokens": tokens})
	})

	group.POST("/auth/logout", func(c *gin.Context) {
		refresh := ""
		if cookie, err := c.Cookie("refresh_token"); err == nil {
			refresh = strings.TrimSpace(cookie)
		}
		if refresh == "" {
			var req struct {
				RefreshToken string `json:"refreshToken"`
			}
			if err := c.ShouldBindJSON(&req); err == nil {
				refresh = strings.TrimSpace(req.RefreshToken)
			}
		}
		if refresh == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing refresh token"})
			return
		}
		if err := a.Logout(c.Request.Context(), refresh); err != nil {
			writeError(c, err)
			return
		}
		c.SetCookie("access_token", "", -1, "/", "", true, true)
		c.SetCookie("refresh_token", "", -1, "/", "", true, true)
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	group.GET("/auth/me", Middleware(a), func(c *gin.Context) {
		user, ok := UserFromContext(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"user": auth.NewPublicUser(user)})
	})
}

func setAuthCookies(c *gin.Context, tokens auth.AuthTokens) {
	maxAge := int(tokens.ExpiresIn.Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	c.SetCookie("access_token", tokens.AccessToken, maxAge, "/", "", true, true)
	c.SetCookie("refresh_token", tokens.RefreshToken, maxAge*refreshCookieTTLMultiplier, "/", "", true, true)
}

func writeError(c *gin.Context, err error) {
	status := http.StatusInternalServerError
	switch err {
	case auth.ErrInvalidCredentials, auth.ErrInvalidToken, auth.ErrSessionNotFound, auth.ErrSessionRevoked, auth.ErrEmailNotVerified, auth.ErrInvalidCode, auth.ErrTwoFactorRequired:
		status = http.StatusUnauthorized
	case auth.ErrUserExists, auth.ErrAlreadyExists:
		status = http.StatusConflict
	case auth.ErrWeakPassword:
		status = http.StatusBadRequest
	}
	c.JSON(status, gin.H{"error": err.Error()})
}

func bearerToken(header string) string {
	header = strings.TrimSpace(header)
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
