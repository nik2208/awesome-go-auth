package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The parts of POST <tools>/webhook/{provider} that the four-adapter suite
// cannot reach: the body rules, which are the ones express.json() enforces one
// layer up in the reference, and the path parameter's own edges.
//
// Everything about the seam itself — what the runner is handed, the fail-closed
// answers, the fallback order — is asserted where it is observable, in
// adapter/internal/wiretest/tools_webhook.go.

func toolsInboundBodyOf(t *testing.T, cfg HTTPConfig, raw string) (string, error) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/tools/webhook/stripe", strings.NewReader(raw))
	body, err := toolsInboundBody(httptest.NewRecorder(), req, cfg)
	return string(body), err
}

func TestToolsInboundBody(t *testing.T) {
	cfg := DefaultHTTPConfig()
	for _, c := range []struct {
		name string
		raw  string
		want string
		ok   bool
	}{
		// express.json() leaves an empty body as {}, so a provider that pings an
		// endpoint reaches the same script it otherwise would.
		{"empty", "", "{}", true},
		{"whitespace", " \n\t ", "{}", true},
		{"an object", `{"a":1}`, `{"a":1}`, true},
		{"an array", `[1,2]`, `[1,2]`, true},
		// Surrounding whitespace is trimmed and nothing inside is touched: the
		// runner is handed the bytes the provider sent, key order, duplicates and
		// number spellings included.
		{"trimmed, not reformatted", "\n" + `{"b":1,"a":2,"a":3,"n":1.50}` + "\n", `{"b":1,"a":2,"a":3,"n":1.50}`, true},
		// express.json's `strict` defaults to true: only an object or an array is
		// accepted at the top level.
		{"a string", `"hello"`, "", false},
		{"a number", "5", "", false},
		{"null", "null", "", false},
		{"not json at all", "hello", "", false},
		{"unterminated", `{"a":`, "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := toolsInboundBodyOf(t, cfg, c.raw)
			if c.ok && err != nil {
				t.Fatalf("toolsInboundBody(%q) = error %v, want %q", c.raw, err, c.want)
			}
			if !c.ok {
				if err == nil {
					t.Fatalf("toolsInboundBody(%q) = %q, want an error", c.raw, got)
				}
				return
			}
			if got != c.want {
				t.Errorf("toolsInboundBody(%q) = %q, want %q", c.raw, got, c.want)
			}
		})
	}
}

func TestToolsInboundBodyLimit(t *testing.T) {
	// The limit the reference's host enforces in express.json() and this route
	// has to enforce itself, because it is the thing reading the body. Over it
	// the read fails and the route answers its one failure, rather than
	// buffering whatever a stranger decided to send.
	cfg := DefaultHTTPConfig()
	cfg.Tools.WebhookMaxBytes = 16
	if _, err := toolsInboundBodyOf(t, cfg, `{"a":1}`); err != nil {
		t.Fatalf("a body under the limit was refused: %v", err)
	}
	if _, err := toolsInboundBodyOf(t, cfg, `{"pad":"`+strings.Repeat("x", 64)+`"}`); err == nil {
		t.Errorf("a body over the limit was accepted")
	}
	// Zero is the default rather than "no limit": a configuration that forgot to
	// set it must not be the unbounded one.
	cfg.Tools.WebhookMaxBytes = 0
	if _, err := toolsInboundBodyOf(t, cfg, `{"pad":"`+strings.Repeat("x", 64)+`"}`); err != nil {
		t.Errorf("the default limit refused a 72-byte body: %v", err)
	}
	if _, err := toolsInboundBodyOf(t, cfg,
		`{"pad":"`+strings.Repeat("x", int(DefaultInboundWebhookMaxBytes)+1)+`"}`); err == nil {
		t.Errorf("the default limit accepted a body past DefaultInboundWebhookMaxBytes")
	}
}

func TestToolsInboundMounted(t *testing.T) {
	// `webhook && (options.onWebhook || options.webhookStore?.findByProvider)`
	// (tools.router.ts:250). A script runner is deliberately not part of it: a
	// runner with no store to find a script in runs nothing, and a store with no
	// runner is the fail-closed case rather than an unmounted route.
	base := DefaultHTTPConfig()
	base.Tools.Enabled = true
	hook := func(*http.Request, string, []byte) (InboundScriptResult, bool, error) {
		return InboundScriptResult{}, false, nil
	}
	for _, c := range []struct {
		name string
		edit func(*ToolsOptions)
		want bool
	}{
		{"neither", func(*ToolsOptions) {}, false},
		{"a callback", func(o *ToolsOptions) { o.OnWebhook = hook }, true},
		{"a store", func(o *ToolsOptions) { o.InboundWebhooks = NewMemoryWebhookStore() }, true},
		{"a runner alone", func(o *ToolsOptions) { o.ScriptRunner = nil }, false},
		{"the flag off", func(o *ToolsOptions) { o.OnWebhook = hook; o.DisableWebhook = true }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := base
			c.edit(&cfg.Tools)
			if got := toolsInboundMounted(cfg); got != c.want {
				t.Errorf("toolsInboundMounted = %v, want %v", got, c.want)
			}
		})
	}
}
