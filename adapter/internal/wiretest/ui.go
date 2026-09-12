package wiretest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
)

// The built-in UI group: GET <prefix>/ui/config, the document the UI fetches
// before it renders anything (ui.router.ts:95-170).
//
// It is the second route the adapters mount conditionally — on
// HTTPConfig.UI.Enabled, which is the reference's config.ui.enabled
// (auth.router.ts:1639-1648) — so the other half of the contract, that it is
// absent without the flag and tracked by the generated document in both
// directions, is the "ui" conditional set at the bottom of this file.
//
// What is asserted here is the shape: the exact key set of the document and of
// its two nested objects, the settings store winning over the static branding,
// the language selection, the echoed headless flag, and the reduced document a
// store failure produces.

// The static branding the cases configure. The values are deliberately not the
// defaults, so an assertion on them cannot pass on a document that ignored the
// configuration.
const (
	testUIPrimaryColor   = "#112233"
	testUISecondaryColor = "#445566"
	testUISiteName       = "Wiretest Auth"
	testUICustomLogo     = "https://cdn.example.com/custom-logo.svg"
	testUILogoURL        = "https://cdn.example.com/legacy-logo.svg"
	testUIBgColor        = "#f0f4ff"
	testUIBgImage        = "https://cdn.example.com/bg.jpg"
	testUICardBg         = "#ffffff"
	testUICustomCSS      = ":root { --radius: 4px }"
)

// The stored branding an administrator would have written through the admin
// panel, which has to win over every static value above.
const (
	testUIStoredPrimaryColor = "#aabbcc"
	testUIStoredSiteName     = "Stored Name"
	testUIStoredLogoURL      = "https://cdn.example.com/stored-logo.svg"
	testUIStoredBgColor      = "#001122"
)

// The reference's defaults (ui.router.ts:126-129), spelled out rather than read
// from the package constants: this is the wire, and a test that quoted the
// implementation would follow it wherever it went.
const (
	testUIDefaultPrimaryColor   = "#4a90d9"
	testUIDefaultSecondaryColor = "#6c757d"
	testUIDefaultSiteName       = "Awesome Node Auth"
)

// testUITwoFactorAppName switches the twoFactor feature flag on: it is this
// port's spelling of the reference's twoFactor block.
const testUITwoFactorAppName = "Wiretest"

// errUIStore is what the failing stores answer with. The document must not
// carry it — the client is told nothing at all, which is the reference's
// behaviour and the reason the reduced features object is worth pinning.
var errUIStore = errors.New("wiretest: store is unreachable")

// uiFailingSettings is a settings store that cannot answer, the first half of
// the reference's try block (ui.router.ts:99).
type uiFailingSettings struct{}

func (uiFailingSettings) GetSettings(context.Context) (auth.AuthSettings, error) {
	return auth.AuthSettings{}, errUIStore
}

func (uiFailingSettings) UpdateSettings(context.Context, auth.AuthSettings) (auth.AuthSettings, error) {
	return auth.AuthSettings{}, errUIStore
}

// uiFailingTemplates is a template store whose UI half cannot answer, the other
// half of the same try block (:108). The mail half is a working memory store, so
// the failure is the one the case is about.
type uiFailingTemplates struct {
	*auth.MemoryTemplateStore
}

func (uiFailingTemplates) GetUITranslations(context.Context, string) (auth.UITranslation, bool, error) {
	return auth.UITranslation{}, false, errUIStore
}

// uiHTTPConfig is the wire configuration with the UI switched on and nothing
// else changed.
func uiHTTPConfig() auth.HTTPConfig {
	cfg := auth.DefaultHTTPConfig()
	cfg.UI.Enabled = true
	return cfg
}

// uiBrandedConfig is uiHTTPConfig with every static member of the branding set.
func uiBrandedConfig() auth.HTTPConfig {
	cfg := uiHTTPConfig()
	cfg.UI.Branding = auth.UIBranding{
		PrimaryColor:   testUIPrimaryColor,
		SecondaryColor: testUISecondaryColor,
		LogoURL:        testUILogoURL,
		SiteName:       testUISiteName,
		CustomLogo:     testUICustomLogo,
		BgColor:        testUIBgColor,
		BgImage:        testUIBgImage,
		CardBg:         testUICardBg,
	}
	cfg.UI.CustomCSS = testUICustomCSS
	return cfg
}

// uiTranslationStore is a template store holding the config page in two
// languages. The page is "config" and not "login": the reference derives the
// page from the request path, and on this route that path is always /config
// (ui.router.ts:107).
func uiTranslationStore(t *testing.T) auth.TemplateStore {
	t.Helper()
	store := auth.NewMemoryTemplateStore()
	if _, err := store.UpdateUITranslations(context.Background(), "config", map[string]map[string]string{
		"en": {"signIn": "Sign in"},
		"it": {"signIn": "Accedi"},
	}); err != nil {
		t.Fatalf("seed ui translations: %v", err)
	}
	return store
}

// uiConfigRequest builds a request for the config route, with query appended
// when it is not empty.
func uiConfigRequest(env *Env, query string) *http.Request {
	target := env.Config.Prefix() + auth.UIConfigRoute
	if query != "" {
		target += "?" + query
	}
	return httptest.NewRequest(http.MethodGet, target, nil)
}

// uiDocument issues the request and returns the decoded document, holding it to
// the top-level key set on the way past. Both the success and the failure paths
// answer 200 with these six keys — that is what makes the failure path
// invisible to a client that does not look at features.
func uiDocument(t *testing.T, env *Env, query string) map[string]any {
	t.Helper()
	rec := env.Do(uiConfigRequest(env, query))
	AssertStatus(t, rec, http.StatusOK)
	body := Body(t, rec)
	AssertKeys(t, body, "apiPrefix", "features", "ui", "translations", "lang", "headless")
	return body
}

// uiObject reads one nested object out of the document.
func uiObject(t *testing.T, body map[string]any, key string) map[string]any {
	t.Helper()
	object, ok := body[key].(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v, want an object", key, body[key])
	}
	return object
}

// assertUIValues fails unless each named member holds this value.
func assertUIValues(t *testing.T, object map[string]any, want map[string]any) {
	t.Helper()
	for member, value := range want {
		if object[member] != value {
			t.Errorf("%s = %#v, want %#v", member, object[member], value)
		}
	}
}

// assertUIUnrouted fails unless the request missed the route entirely. The Go
// routers disagree among themselves on 404 versus 405, so both are accepted;
// what matters is that no document came back.
func assertUIUnrouted(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	switch rec.Code {
	case http.StatusNotFound, http.StatusMethodNotAllowed:
	default:
		t.Fatalf("status = %d, want 404 or 405 (body %q)", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); strings.Contains(body, "apiPrefix") {
		t.Errorf("an unrouted request was served the UI config document: %s", body)
	}
}

func testUIConfig(t *testing.T, mount Mounter) {
	t.Run("the document carries the reference keys and the configured branding", func(t *testing.T) {
		// NewEnv wires all six senders, so the four delivery-derived flags are on.
		env := NewEnv(t, mount, uiBrandedConfig(),
			auth.WithTwoFactorAppName(testUITwoFactorAppName),
			auth.WithOAuth(auth.OAuthWiring{
				Service: auth.NewOAuthService(
					auth.GoogleProvider("google-client", "google-secret", "https://api.example.com/auth/oauth/google/callback"),
					auth.GitHubProvider("github-client", "github-secret", "https://api.example.com/auth/oauth/github/callback"),
				),
				LinkedAccounts: auth.NewMemoryLinkedAccounts(),
				PendingLinks:   auth.NewMemoryPendingLinks(),
			}),
		)
		body := uiDocument(t, env, "")

		if body["apiPrefix"] != env.Config.Prefix() {
			t.Errorf("apiPrefix = %#v, want %q", body["apiPrefix"], env.Config.Prefix())
		}
		if body["lang"] != "en" {
			t.Errorf("lang = %#v, want %q", body["lang"], "en")
		}
		if body["headless"] != false {
			t.Errorf("headless = %#v, want false", body["headless"])
		}

		features := uiObject(t, body, "features")
		AssertKeys(t, features, "register", "magicLink", "sms", "google", "github",
			"forgotPassword", "verifyEmail", "twoFactor")
		assertUIValues(t, features, map[string]any{
			// register is unconditional here: this port always mounts
			// POST <prefix>/register, where the reference mounts it only with an
			// onRegister hook and reports that same condition (:115).
			"register":       true,
			"magicLink":      true,
			"sms":            true,
			"google":         true,
			"github":         true,
			"forgotPassword": true,
			// The verification sender is wired, but the mode is the default none,
			// so the deployment does not want verification and the flag is off.
			"verifyEmail": false,
			"twoFactor":   true,
		})

		ui := uiObject(t, body, "ui")
		AssertKeys(t, ui, "primaryColor", "secondaryColor", "logoUrl", "siteName",
			"customCss", "bgColor", "bgImage", "cardBg")
		assertUIValues(t, ui, map[string]any{
			"primaryColor":   testUIPrimaryColor,
			"secondaryColor": testUISecondaryColor,
			// customLogo wins over the legacy logoUrl (:128).
			"logoUrl":   testUICustomLogo,
			"siteName":  testUISiteName,
			"customCss": testUICustomCSS,
			"bgColor":   testUIBgColor,
			"bgImage":   testUIBgImage,
			"cardBg":    testUICardBg,
		})

		translations := uiObject(t, body, "translations")
		if len(translations) != 0 {
			t.Errorf("translations = %#v, want an empty object with no template store", translations)
		}
	})

	t.Run("an unconfigured deployment gets the reference defaults and nothing else", func(t *testing.T) {
		// No senders, no providers, no branding: the document a deployment that
		// only switched the UI on receives.
		env := NewEnvWithoutDelivery(t, mount, uiHTTPConfig())
		body := uiDocument(t, env, "")

		features := uiObject(t, body, "features")
		AssertKeys(t, features, "register", "magicLink", "sms", "google", "github",
			"forgotPassword", "verifyEmail", "twoFactor")
		assertUIValues(t, features, map[string]any{
			"register": true, "magicLink": false, "sms": false, "google": false,
			"github": false, "forgotPassword": false, "verifyEmail": false, "twoFactor": false,
		})

		// The five optional members are absent rather than null, which is what
		// JSON.stringify does with the undefined the reference leaves them as.
		ui := uiObject(t, body, "ui")
		AssertKeys(t, ui, "primaryColor", "secondaryColor", "siteName")
		assertUIValues(t, ui, map[string]any{
			"primaryColor":   testUIDefaultPrimaryColor,
			"secondaryColor": testUIDefaultSecondaryColor,
			"siteName":       testUIDefaultSiteName,
		})
	})

	t.Run("the settings store wins over the static branding", func(t *testing.T) {
		store := seedSettings(t, auth.AuthSettings{UI: &auth.UISettings{
			PrimaryColor: stringPtr(testUIStoredPrimaryColor),
			SiteName:     stringPtr(testUIStoredSiteName),
			LogoURL:      stringPtr(testUIStoredLogoURL),
			BgColor:      stringPtr(testUIStoredBgColor),
		}})

		env := NewEnv(t, mount, uiBrandedConfig(), auth.WithSettingsStore(store))
		ui := uiObject(t, uiDocument(t, env, ""), "ui")
		assertUIValues(t, ui, map[string]any{
			"primaryColor": testUIStoredPrimaryColor,
			"siteName":     testUIStoredSiteName,
			// The stored logo beats config.ui.customLogo, which beats the legacy
			// config.ui.logoUrl (:128).
			"logoUrl": testUIStoredLogoURL,
			"bgColor": testUIStoredBgColor,
			// Members the store did not carry keep the static value…
			"secondaryColor": testUISecondaryColor,
			"bgImage":        testUIBgImage,
			"cardBg":         testUICardBg,
			// …and customCss is static-only: there is no stored member for it and
			// the reference reads it from the config alone (:130).
			"customCss": testUICustomCSS,
		})
	})

	t.Run("lang selects the translations", func(t *testing.T) {
		env := NewEnv(t, mount, uiHTTPConfig(), auth.WithTemplateStore(uiTranslationStore(t)))

		for _, tc := range []struct {
			name  string
			query string
			lang  string
			want  string
		}{
			// No parameter and no configured default: English (:103).
			{"default", "", "en", "Sign in"},
			{"query", "lang=it", "it", "Accedi"},
			// A language the page does not hold falls back to English, while the
			// document still reports the language that was asked for (:110).
			{"unknown language falls back to en", "lang=de", "de", "Sign in"},
			// An empty parameter is no parameter, as the empty string is falsy there.
			{"empty parameter", "lang=", "en", "Sign in"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				body := uiDocument(t, env, tc.query)
				if body["lang"] != tc.lang {
					t.Errorf("lang = %#v, want %q", body["lang"], tc.lang)
				}
				translations := uiObject(t, body, "translations")
				AssertKeys(t, translations, "signIn")
				if translations["signIn"] != tc.want {
					t.Errorf("translations.signIn = %#v, want %q", translations["signIn"], tc.want)
				}
			})
		}
	})

	t.Run("UIOptions.DefaultLang is the fallback the request overrides", func(t *testing.T) {
		cfg := uiHTTPConfig()
		cfg.UI.DefaultLang = "it"
		env := NewEnv(t, mount, cfg, auth.WithTemplateStore(uiTranslationStore(t)))

		body := uiDocument(t, env, "")
		if body["lang"] != "it" {
			t.Errorf("lang = %#v, want the configured default %q", body["lang"], "it")
		}
		if got := uiObject(t, body, "translations")["signIn"]; got != "Accedi" {
			t.Errorf("translations.signIn = %#v, want %q", got, "Accedi")
		}

		body = uiDocument(t, env, "lang=en")
		if body["lang"] != "en" {
			t.Errorf("lang = %#v, want the requested %q", body["lang"], "en")
		}
	})

	t.Run("a template store holding no config page answers an empty object", func(t *testing.T) {
		env := NewEnv(t, mount, uiHTTPConfig(), auth.WithTemplateStore(auth.NewMemoryTemplateStore()))
		if translations := uiObject(t, uiDocument(t, env, "lang=it"), "translations"); len(translations) != 0 {
			t.Errorf("translations = %#v, want an empty object", translations)
		}
	})

	t.Run("headless is echoed", func(t *testing.T) {
		// The flag auth.js reads to stop redirecting on session loss. It is added
		// by the route rather than by getUiConfig (:166-168).
		cfg := uiHTTPConfig()
		cfg.UI.Headless = true
		env := NewEnv(t, mount, cfg)
		if body := uiDocument(t, env, ""); body["headless"] != true {
			t.Errorf("headless = %#v, want true", body["headless"])
		}
	})

	t.Run("a failing store answers the reduced document", func(t *testing.T) {
		// The reference's catch (:143-161): still 200, still the same six keys,
		// but three feature flags instead of eight, the default branding whatever
		// was configured, no translations, and English whatever was asked for.
		// This is reproduced rather than fixed — a client cannot tell it from a
		// success, which is the bug, and the family's clients are written against
		// it (reference-issues N32).
		for _, tc := range []struct {
			name string
			opt  auth.Option
		}{
			{"settings store", auth.WithSettingsStore(uiFailingSettings{})},
			{"template store", auth.WithTemplateStore(uiFailingTemplates{auth.NewMemoryTemplateStore()})},
		} {
			t.Run(tc.name, func(t *testing.T) {
				cfg := uiBrandedConfig()
				cfg.UI.Headless = true
				env := NewEnv(t, mount, cfg, tc.opt)
				body := uiDocument(t, env, "lang=it")

				features := uiObject(t, body, "features")
				AssertKeys(t, features, "register", "google", "github")
				assertUIValues(t, features, map[string]any{
					"register": false, "google": false, "github": false,
				})

				ui := uiObject(t, body, "ui")
				AssertKeys(t, ui, "primaryColor", "secondaryColor", "siteName")
				assertUIValues(t, ui, map[string]any{
					"primaryColor":   testUIDefaultPrimaryColor,
					"secondaryColor": testUIDefaultSecondaryColor,
					"siteName":       testUIDefaultSiteName,
				})

				if translations := uiObject(t, body, "translations"); len(translations) != 0 {
					t.Errorf("translations = %#v, want an empty object", translations)
				}
				if body["lang"] != "en" {
					t.Errorf("lang = %#v, want %q whatever the request asked for", body["lang"], "en")
				}
				if body["apiPrefix"] != env.Config.Prefix() {
					t.Errorf("apiPrefix = %#v, want %q", body["apiPrefix"], env.Config.Prefix())
				}
				// headless is set outside getUiConfig, so the fallback carries it.
				if body["headless"] != true {
					t.Errorf("headless = %#v, want true on the fallback too", body["headless"])
				}
				if raw := env.Do(uiConfigRequest(env, "")).Body.String(); strings.Contains(raw, errUIStore.Error()) {
					t.Errorf("the store error reached the client: %s", raw)
				}
			})
		}
	})

	t.Run("no credential is required and the CSRF cookie is seeded", func(t *testing.T) {
		// The login page fetches this before any session exists, so the route
		// asks for nothing. It sits behind the CSRF middleware only for the
		// cookie that middleware hands out, which the reference seeds from a
		// router-level middleware registered ahead of its UI router
		// (auth.router.ts:529-535).
		env := NewEnv(t, mount, uiHTTPConfig())
		rec := env.Do(uiConfigRequest(env, ""))
		AssertStatus(t, rec, http.StatusOK)
		if cookie := Cookie(t, rec, hostCSRF); cookie.Value == "" {
			t.Error("the CSRF cookie was seeded with an empty value")
		}
		// And because that cookie is per-client, the document must not be
		// storable by a shared cache. The header is this port's addition to a
		// route the reference leaves uncached; see the handler comment.
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("Cache-Control = %q, want %q on a response that seeds a CSRF cookie", got, "no-store")
		}
	})

	t.Run("the route is GET-only", func(t *testing.T) {
		env := NewEnv(t, mount, uiHTTPConfig())
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			t.Run(method, func(t *testing.T) {
				assertUIUnrouted(t, env.Do(httptest.NewRequest(method, env.Config.Prefix()+auth.UIConfigRoute, nil)))
			})
		}
	})

	t.Run("without UI.Enabled there is no route", func(t *testing.T) {
		// The reference mounts its whole ui router only under config.ui.enabled
		// (auth.router.ts:1639-1648). testOpenAPI asserts the same thing through
		// the conditional set; this is the group saying it in its own terms.
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		assertUIUnrouted(t, env.Do(uiConfigRequest(env, "")))
	})

	t.Run("the deprecated UIEnabled still mounts it", func(t *testing.T) {
		// A deployment configured before UIOptions existed keeps working, which
		// is the whole point of keeping the field.
		cfg := auth.DefaultHTTPConfig()
		cfg.UIEnabled = true
		env := NewEnv(t, mount, cfg)
		uiDocument(t, env, "")
	})
}

// stringPtr is the pointer every optional UISettings member is.
func stringPtr(value string) *string { return &value }

// uiRouteSet is the conditional set testOpenAPI replays: configured, the adapter
// serves GET <prefix>/ui/config and the document generated with OpenAPIInfo.UI
// describes it; unconfigured, neither does.
func uiRouteSet() conditionalRouteSet {
	return conditionalRouteSet{
		name:      "ui",
		configure: func(pc *probeConfig) { pc.HTTP.UI.Enabled = true },
		routes:    map[string]string{auth.UIConfigRoute: http.MethodGet},
		spec:      func() auth.OpenAPIInfo { return auth.OpenAPIInfo{UI: true} },
	}
}
