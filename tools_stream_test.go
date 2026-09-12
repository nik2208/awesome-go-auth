package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The parts of GET <tools>/stream that are decisions rather than wire: the two
// query parses, the credential copy in front of the guard, and the two answers
// the route gives instead of a stream.
//
// The stream itself — the headers, the connected frame, the topic list a client
// is actually registered with — is pinned for all four adapters in
// adapter/internal/wiretest/tools_stream.go. What is here is what that suite
// cannot reach: Express's query-parser edges, which are invisible from a mount
// that can only send one shape of request at a time, and a ResponseWriter that
// cannot be flushed, which no adapter produces.

func TestToolsSseQueryToken(t *testing.T) {
	// `req.query['token'] && typeof req.query['token'] === 'string'`
	// (tools.router.ts:186). The two edges are Express's: an empty value is
	// falsy, and a repeated parameter parses to an array that fails the typeof
	// test — so both fall through to whatever credential the request already
	// carried.
	for _, c := range []struct {
		query string
		want  string
		ok    bool
	}{
		{"", "", false},
		{"?token=abc", "abc", true},
		{"?token=", "", false},
		{"?token=a&token=b", "", false},
		{"?token=a&token=a", "", false},
		{"?topics=global", "", false},
		{"?token=a%20b", "a b", true},
	} {
		t.Run(c.query, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/tools/stream"+c.query, nil)
			got, ok := toolsSseQueryToken(r)
			if got != c.want || ok != c.ok {
				t.Errorf("toolsSseQueryToken(%q) = %q, %v, want %q, %v", c.query, got, ok, c.want, c.ok)
			}
		})
	}
}

func TestToolsStreamRequestedTopics(t *testing.T) {
	// `req.query.topics.split(',').map(t => t.trim()).filter(Boolean)`
	// (tools.router.ts:203-205), including the branch a non-string takes: no
	// request at all, which StreamTopics reads as "the whole authorised list".
	for _, c := range []struct {
		name   string
		values []string
		want   string
	}{
		{"absent", nil, ""},
		{"empty", []string{""}, ""},
		{"one", []string{"global"}, "global"},
		{"two", []string{"global,user:u1"}, "global,user:u1"},
		{"trimmed", []string{" global , user:u1 "}, "global,user:u1"},
		{"empties dropped", []string{"global,,,user:u1,"}, "global,user:u1"},
		{"only separators", []string{",,,"}, ""},
		{"repeated is not a string", []string{"global", "user:u1"}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := strings.Join(toolsStreamRequestedTopics(c.values), ","); got != c.want {
				t.Errorf("toolsStreamRequestedTopics(%q) = %q, want %q", c.values, got, c.want)
			}
		})
	}
}

// TestToolsSseTokenMiddleware is extractSseToken (tools.router.ts:185-190): the
// posture of this route, which is a credential read out of a URL. See the head
// of tools_stream.go for what that costs.
func TestToolsSseTokenMiddleware(t *testing.T) {
	seen := func(t *testing.T, req *http.Request) string {
		t.Helper()
		var got string
		ToolsSseTokenMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			got = r.Header.Get("Authorization")
		})).ServeHTTP(httptest.NewRecorder(), req)
		return got
	}

	t.Run("a query token becomes a bearer header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/tools/stream?token=abc", nil)
		if got := seen(t, req); got != "Bearer abc" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer abc")
		}
	})

	t.Run("it overwrites a header that was already there", func(t *testing.T) {
		// The assignment is unconditional there, so the query token is the
		// credential whenever both are present — and a request with a valid
		// header and a stale ?token= is refused. Which one wins is observable,
		// and this is the case that says which.
		req := httptest.NewRequest(http.MethodGet, "/tools/stream?token=query", nil)
		req.Header.Set("Authorization", "Bearer header")
		if got := seen(t, req); got != "Bearer query" {
			t.Errorf("Authorization = %q, want the query token to win", got)
		}
	})

	t.Run("no usable token leaves the request alone", func(t *testing.T) {
		for _, query := range []string{"", "?token=", "?token=a&token=b"} {
			req := httptest.NewRequest(http.MethodGet, "/tools/stream"+query, nil)
			req.Header.Set("Authorization", "Bearer header")
			if got := seen(t, req); got != "Bearer header" {
				t.Errorf("%q: Authorization = %q, want it untouched", query, got)
			}
		}
	})

	t.Run("the caller's own request is not mutated", func(t *testing.T) {
		// The reference assigns into req.headers in place. Handing the guard a
		// clone instead keeps the synthesised credential out of the request
		// object a framework still holds when its own logging middleware runs.
		req := httptest.NewRequest(http.MethodGet, "/tools/stream?token=abc", nil)
		if got := seen(t, req); got != "Bearer abc" {
			t.Fatalf("Authorization = %q, want %q", got, "Bearer abc")
		}
		if got := req.Header.Get("Authorization"); got != "" {
			t.Errorf("the original request carries Authorization %q, want it untouched", got)
		}
	})

	t.Run("the guard runs behind it, not in front", func(t *testing.T) {
		// The reference registers extractSseToken before ...protect
		// (tools.router.ts:192). A guard that ran first would see the request
		// without the header, which is the whole failure this ordering avoids.
		order := []string{}
		guard := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, "guard:"+r.Header.Get("Authorization"))
				next.ServeHTTP(w, r)
			})
		}
		cfg := HTTPConfig{Tools: ToolsOptions{Access: ToolsProtected(guard)}}
		handler := ToolsSseTokenMiddleware(ToolsProtectMiddleware(cfg)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			order = append(order, "handler:"+r.Header.Get("Authorization"))
		})))
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/tools/stream?token=abc", nil))
		if got := strings.Join(order, " "); got != "guard:Bearer abc handler:Bearer abc" {
			t.Errorf("order = %q, want the guard to see the copied token", got)
		}
	})
}

// toolsStreamTestConfig is a mounted tools router whose facade holds a manager.
func toolsStreamTestConfig(t *testing.T) HTTPConfig {
	t.Helper()
	manager, err := NewSseManager(context.Background())
	if err != nil {
		t.Fatalf("NewSseManager: %v", err)
	}
	cfg := toolsTestConfig()
	cfg.Tools.AuthTools = &AuthTools{Events: NewEventBus(), SSE: manager}
	return cfg
}

func TestToolsStreamWithoutAManager(t *testing.T) {
	// `res.status(503).json({ error: 'SSE not enabled' })`
	// (tools.router.ts:193-196). toolsTestConfig's facade has no manager, which
	// is the reference's default (auth-tools.ts:33).
	rec := httptest.NewRecorder()
	(&Auth{}).ToolsHandler(toolsTestConfig()).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, DefaultToolsPath+ToolsStreamPath, nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body %q)", rec.Code, rec.Body.String())
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"error":"SSE not enabled"}` {
		t.Errorf("body = %q, want the reference's one-key literal", got)
	}
}

func TestToolsStreamOnAWriterThatCannotStream(t *testing.T) {
	// Serve refuses a ResponseWriter it cannot flush and says so without having
	// touched the response, so this route still owns it (see
	// ErrSseStreamingUnsupported). The reference has no shape to copy — an
	// Express response is always flushable — and the honest answer is the
	// generic 500: the deployment cannot stream, which is neither the client's
	// doing nor a feature the host switched off, so it is not the 503 above.
	//
	// The receiver is a zero Auth, which is also the case that pins the nil
	// service the failure path logs through.
	w := &sseUnflushableRecorder{hdr: make(http.Header)}
	(&Auth{}).ToolsHandler(toolsStreamTestConfig(t)).
		ServeHTTP(w, httptest.NewRequest(http.MethodGet, DefaultToolsPath+ToolsStreamPath, nil))
	if got := w.hdr.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want the error envelope's — Serve must leave no event-stream headers behind", got)
	}
	for _, name := range []string{"Cache-Control", "Connection", "X-Accel-Buffering"} {
		if got := w.hdr.Get(name); got != "" {
			t.Errorf("%s = %q, want it removed with the rest of the streaming headers", name, got)
		}
	}
}

// TestToolsStreamIsMountedOnTheFlag is the reference's `if (stream)`
// (tools.router.ts:184) at the switch rather than at the document.
func TestToolsStreamIsMountedOnTheFlag(t *testing.T) {
	cfg := toolsStreamTestConfig(t)
	cfg.Tools.DisableStream = true
	rec := httptest.NewRecorder()
	(&Auth{}).ToolsHandler(cfg).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, DefaultToolsPath+ToolsStreamPath, nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET %s with the flag off = %d, want 404", DefaultToolsPath+ToolsStreamPath, rec.Code)
	}
}
