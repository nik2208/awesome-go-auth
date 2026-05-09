package echo

import (
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	auth "github.com/nik2208/awesome-go-auth"
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

// Middleware returns an Echo-native middleware.
func Middleware(a *auth.Auth) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			token := bearerToken(c.Request().Header.Get("Authorization"))
			if token == "" {
				if cookie, err := c.Cookie("access_token"); err == nil {
					token = strings.TrimSpace(cookie.Value)
				}
			}
			if token == "" {
				return c.JSON(http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			}
			user, err := a.Me(c.Request().Context(), token)
			if err != nil {
				return c.JSON(http.StatusUnauthorized, map[string]any{"error": err.Error()})
			}
			c.Set(userContextKey, user)
			return next(c)
		}
	}
}

// Mount mounts auth routes on an Echo group.
func Mount(group *echo.Group, a *auth.Auth) {
	group.POST("/auth/register", func(c echo.Context) error {
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
			TenantID string `json:"tenantId"`
		}
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]any{"error": "invalid body"})
		}
		user, tokens, err := a.Register(c.Request().Context(), auth.RegisterInput{Email: req.Email, Password: req.Password, TenantID: req.TenantID})
		if err != nil {
			return writeError(c, err)
		}
		setAuthCookies(c, tokens)
		return c.JSON(http.StatusCreated, map[string]any{"user": user, "tokens": tokens})
	})

	group.POST("/auth/login", func(c echo.Context) error {
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
			TenantID string `json:"tenantId"`
		}
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]any{"error": "invalid body"})
		}
		user, tokens, err := a.Login(c.Request().Context(), auth.LoginInput{Email: req.Email, Password: req.Password, TenantID: req.TenantID})
		if err != nil {
			return writeError(c, err)
		}
		setAuthCookies(c, tokens)
		return c.JSON(http.StatusOK, map[string]any{"user": user, "tokens": tokens})
	})

	group.POST("/auth/refresh", func(c echo.Context) error {
		refresh := ""
		if cookie, err := c.Cookie("refresh_token"); err == nil {
			refresh = strings.TrimSpace(cookie.Value)
		}
		if refresh == "" {
			var req struct {
				RefreshToken string `json:"refreshToken"`
			}
			if err := c.Bind(&req); err == nil {
				refresh = strings.TrimSpace(req.RefreshToken)
			}
		}
		if refresh == "" {
			return c.JSON(http.StatusBadRequest, map[string]any{"error": "missing refresh token"})
		}
		tokens, err := a.Refresh(c.Request().Context(), refresh)
		if err != nil {
			return writeError(c, err)
		}
		setAuthCookies(c, tokens)
		return c.JSON(http.StatusOK, map[string]any{"tokens": tokens})
	})

	group.POST("/auth/logout", func(c echo.Context) error {
		refresh := ""
		if cookie, err := c.Cookie("refresh_token"); err == nil {
			refresh = strings.TrimSpace(cookie.Value)
		}
		if refresh == "" {
			var req struct {
				RefreshToken string `json:"refreshToken"`
			}
			if err := c.Bind(&req); err == nil {
				refresh = strings.TrimSpace(req.RefreshToken)
			}
		}
		if refresh == "" {
			return c.JSON(http.StatusBadRequest, map[string]any{"error": "missing refresh token"})
		}
		if err := a.Logout(c.Request().Context(), refresh); err != nil {
			return writeError(c, err)
		}
		c.SetCookie(&http.Cookie{Name: "access_token", Value: "", Path: "/", HttpOnly: true, Secure: true, MaxAge: -1})
		c.SetCookie(&http.Cookie{Name: "refresh_token", Value: "", Path: "/", HttpOnly: true, Secure: true, MaxAge: -1})
		return c.JSON(http.StatusOK, map[string]any{"ok": true})
	})

	group.GET("/auth/me", func(c echo.Context) error {
		return Middleware(a)(func(c echo.Context) error {
			user, ok := UserFromContext(c)
			if !ok {
				return c.JSON(http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			}
			return c.JSON(http.StatusOK, map[string]any{"user": user})
		})(c)
	})
}

func setAuthCookies(c echo.Context, tokens auth.AuthTokens) {
	expires := time.Now().Add(tokens.ExpiresIn)
	c.SetCookie(&http.Cookie{Name: "access_token", Value: tokens.AccessToken, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, Expires: expires})
	c.SetCookie(&http.Cookie{Name: "refresh_token", Value: tokens.RefreshToken, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

func writeError(c echo.Context, err error) error {
	status := http.StatusInternalServerError
	switch err {
	case auth.ErrInvalidCredentials, auth.ErrInvalidToken, auth.ErrSessionNotFound, auth.ErrSessionRevoked, auth.ErrEmailNotVerified, auth.ErrInvalidCode, auth.ErrTwoFactorRequired:
		status = http.StatusUnauthorized
	case auth.ErrUserExists, auth.ErrAlreadyExists:
		status = http.StatusConflict
	case auth.ErrWeakPassword:
		status = http.StatusBadRequest
	}
	return c.JSON(status, map[string]any{"error": err.Error()})
}

func bearerToken(header string) string {
	header = strings.TrimSpace(header)
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
