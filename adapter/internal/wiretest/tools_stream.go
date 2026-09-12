package wiretest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

// GET <tools>/stream for all four adapters: the posture in front of it, the
// topics the server decides, and the first frames of the stream itself.
//
// # Why this set is not served by Env.Do
//
// Every other case in this suite issues a request, gets a recorder back and
// reads it. An SSE route never returns: auth.SseManager.Serve blocks for the
// life of the connection, so ServeHTTP does too, and a recorder that is only
// readable after the handler returns is readable when the connection is already
// over. So the cases below run the handler on a goroutine against a recorder
// that hands each written frame to the test as it is written, and end the
// stream by cancelling the request's context — which is what a client
// disconnecting looks like to a Go server.
//
// Nothing here sleeps for an interval it expects something to happen in, which
// is the rule sse_test.go set for the manager's own suite and the reason this
// one does not flake at -count=2 under the parallel load this project's gate
// runs at. Every wait is a deadline only a failure reaches; the one ordering
// that matters — a broadcast must not race the connection's registration — is
// arranged by polling ConnectionCount rather than by pausing.
//
// # What is asserted, and what is deliberately not
//
// Asserted, because it is true on all four adapters: that the response carries
// the four streaming headers; that the `connected` frame arrives and names the
// topics the server authorised; that a topic the principal is not entitled to
// is dropped from that list; that an event broadcast to an authorised topic
// reaches the connection; that `?token=` reaches the guard as an Authorization
// header and overwrites one that was already there; and that the route answers
// 503 with no manager and 404 with the feature flag off.
//
// Not asserted, and each for a reason rather than an oversight:
//
//   - The heartbeat. It is a 30 second interval by default, and the only honest
//     ways to observe it are to wait for one — a sleep proportional to a timer,
//     which is the flake this suite refuses — or to reconfigure the manager down
//     to milliseconds, which tests the option rather than the route. The frame's
//     bytes are pinned in the package's own sse_test.go, where the manager is
//     constructed directly.
//   - Where a frame lands on the socket. A recorder sees a write and a flush;
//     it cannot see what a framework's own buffering, or a proxy's, does with
//     them afterwards. echo wraps the writer in its own Response and gin in its
//     own ResponseWriter, and both forward Flush — which is all this suite can
//     honestly claim, and is why the assertion is "the frame was written and
//     flushed" rather than "the client received it".
//   - The status line. Serve never calls WriteHeader: it sets four headers and
//     flushes, which is a 200 on a real server and on three of the four
//     adapters, while gin commits its own recorded status at the same moment.
//     The recorder below therefore treats the first flush as the commit, the
//     way net/http does, and the cases read the headers rather than asserting a
//     status code that no adapter is free to choose differently.
//   - Resume. There is nothing to assert a guarantee about, which is itself
//     pinned: "a reconnection resumes from now" below proves the negative in
//     the only way a negative can be proved, by provoking the next frame and
//     showing it is the new one.

// toolsStreamDeadline bounds every wait in this file. It is a failure deadline
// and not a delay: a passing case never reaches it.
const toolsStreamDeadline = 10 * time.Second

// The principal the guard injects in the cases that need one, and a topic
// belonging to somebody else.
const (
	toolsStreamUserID   = "u-stream"
	toolsStreamTenantID = "t-stream"
	toolsStreamOther    = auth.SseTopicUserPrefix + "someone-else"
)

// toolsStreamRecorder is an http.ResponseWriter that hands each frame to the
// test as it is written, so a blocking handler can be asserted on while it runs.
//
// It is the wiretest counterpart of sse_test.go's sseRecorder. Header, body and
// status are behind a mutex because the handler writes them on its own
// goroutine while the test reads them on its own.
type toolsStreamRecorder struct {
	mu        sync.Mutex
	header    http.Header
	status    int
	committed http.Header
	body      bytes.Buffer

	frames chan string
}

func newToolsStreamRecorder() *toolsStreamRecorder {
	return &toolsStreamRecorder{header: make(http.Header), frames: make(chan string, 64)}
}

func (w *toolsStreamRecorder) Header() http.Header { return w.header }

// commit snapshots the headers the way a real ResponseWriter freezes them when
// the status line goes out. Callers hold the lock.
func (w *toolsStreamRecorder) commit(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.committed = w.header.Clone()
}

func (w *toolsStreamRecorder) WriteHeader(status int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.commit(status)
}

func (w *toolsStreamRecorder) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.commit(http.StatusOK)
	w.body.Write(p)
	w.mu.Unlock()
	select {
	case w.frames <- string(p):
	default:
	}
	return len(p), nil
}

// Flush is what makes this writer streamable at all: auth.SseManager.Serve
// probes for it through http.ResponseController before it writes anything, and
// answers ErrSseStreamingUnsupported when the probe fails.
func (w *toolsStreamRecorder) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.commit(http.StatusOK)
}

// committedHeader is the header map as it was when the response was committed.
func (w *toolsStreamRecorder) committedHeader(t *testing.T) http.Header {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.committed == nil {
		t.Fatalf("the response was never committed; body so far %q", w.body.String())
	}
	return w.committed
}

// next returns the next frame written, failing on the deadline.
func (w *toolsStreamRecorder) next(t *testing.T) string {
	t.Helper()
	select {
	case frame := <-w.frames:
		return frame
	case <-time.After(toolsStreamDeadline):
		w.mu.Lock()
		defer w.mu.Unlock()
		t.Fatalf("timed out waiting for an SSE frame; body so far %q", w.body.String())
		return ""
	}
}

// toolsStream is one SSE connection open against a mounted adapter.
type toolsStream struct {
	rec    *toolsStreamRecorder
	cancel context.CancelFunc
	done   chan struct{}
}

// openToolsStream issues GET <tools>/stream against the mount and returns once
// the handler is running. query is appended raw, decorate may set headers.
func openToolsStream(t *testing.T, env *Env, query string, decorate func(*http.Request)) *toolsStream {
	t.Helper()
	target := env.Config.ToolsPath() + auth.ToolsStreamPath + query
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, target, nil).WithContext(ctx)
	if decorate != nil {
		decorate(req)
	}
	stream := &toolsStream{rec: newToolsStreamRecorder(), cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(stream.done)
		env.Handler.ServeHTTP(stream.rec, req)
	}()
	t.Cleanup(stream.close)
	return stream
}

// close ends the connection and waits for the handler to return, so that no
// goroutine of one case is still writing while the next one runs.
func (s *toolsStream) close() {
	s.cancel()
	select {
	case <-s.done:
	case <-time.After(toolsStreamDeadline):
	}
}

// toolsConnectedFrame is the first frame of every stream
// (sse-manager.ts:140-146), decoded. The payload key is `rawData`, which is the
// reference's own spelling and not a typo here.
type toolsConnectedFrame struct {
	Type    string `json:"type"`
	Topic   string `json:"topic"`
	RawData struct {
		ConnectionID string   `json:"connectionId"`
		Topics       []string `json:"topics"`
	} `json:"rawData"`
}

// toolsStreamPayload decodes the single `data:` line of one frame.
func toolsStreamPayload(t *testing.T, frame string, into any) {
	t.Helper()
	for _, line := range strings.Split(frame, "\n") {
		if data, ok := strings.CutPrefix(line, "data: "); ok {
			if err := json.Unmarshal([]byte(data), into); err != nil {
				t.Fatalf("decode frame payload %q: %v", data, err)
			}
			return
		}
	}
	t.Fatalf("no data line in frame %q", frame)
}

// toolsStreamTopics opens a stream and returns the topics the server authorised
// it, read off the connected frame — which is the only place the decision is
// observable from outside.
func toolsStreamTopics(t *testing.T, env *Env, query string) []string {
	t.Helper()
	stream := openToolsStream(t, env, query, nil)
	var connected toolsConnectedFrame
	frame := stream.rec.next(t)
	toolsStreamPayload(t, frame, &connected)
	if connected.Type != "connected" {
		t.Fatalf("first frame is %q, want the connected frame: %q", connected.Type, frame)
	}
	if connected.RawData.ConnectionID == "" {
		t.Errorf("the connected frame carries no connectionId: %q", frame)
	}
	return connected.RawData.Topics
}

// toolsStreamFacade is an AuthTools with the stream switched on. The heartbeat
// is left at its default: nothing here waits for one.
func toolsStreamFacade(t *testing.T) *auth.AuthTools {
	t.Helper()
	tools, err := auth.NewAuthTools(context.Background(), auth.NewEventBus(), auth.AuthToolsOptions{SSE: true})
	if err != nil {
		t.Fatalf("NewAuthTools: %v", err)
	}
	return tools
}

// toolsStreamEnv mounts a tools router whose facade streams. principal, when
// true, puts a guard in front that authenticates every request as one fixed
// user — which is what the reference's authMiddleware does for this route, and
// the only way the topic rule has anything but `global` to work with.
func toolsStreamEnv(t *testing.T, mount Mounter, principal bool, opts ...func(*auth.ToolsOptions)) *Env {
	t.Helper()
	facade := toolsStreamFacade(t)
	return NewEnv(t, mount, toolsConfig(t, append([]func(*auth.ToolsOptions){func(o *auth.ToolsOptions) {
		o.AuthTools = facade
		if principal {
			o.Access = auth.ToolsProtected(toolsStreamPrincipalGuard)
		}
	}}, opts...)...))
}

// toolsStreamPrincipalGuard is a host's authMiddleware reduced to what this
// route reads: it puts a principal on the request context, where
// auth.UserFromContext finds it. The adapters' own Middleware() does the same
// thing after verifying a credential.
func toolsStreamPrincipalGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := auth.User{ID: toolsStreamUserID, TenantID: toolsStreamTenantID}
		next.ServeHTTP(w, r.WithContext(auth.ContextWithUser(r.Context(), user)))
	})
}

// waitForTools polls a condition to the failure deadline. The interval is a
// millisecond and is derived from nothing the code under test does.
func waitForTools(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(toolsStreamDeadline)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func testToolsStream(t *testing.T, mount Mounter) {
	t.Run("without a manager it is 503 and the body is the reference's", func(t *testing.T) {
		// `if (!tools.sseManager) res.status(503).json({ error: 'SSE not
		// enabled' })` (tools.router.ts:193-196). toolsConfig's facade is built
		// with SSE off, which is the reference's default, so this is the
		// ordinary answer of a mounted tools router rather than a failure.
		env := NewEnv(t, mount, toolsConfig(t))
		rec := env.Do(toolsRequest(env, http.MethodGet, auth.ToolsStreamPath))
		AssertStatus(t, rec, http.StatusServiceUnavailable)
		body := Body(t, rec)
		AssertKeys(t, body, "error")
		if body["error"] != "SSE not enabled" {
			t.Errorf("error = %v, want %q (tools.router.ts:194)", body["error"], "SSE not enabled")
		}
	})

	t.Run("DisableStream unmounts it", func(t *testing.T) {
		// The reference's `if (stream)` (tools.router.ts:184). The route is gone
		// from the mount and from the document together.
		env := toolsStreamEnv(t, mount, false, func(o *auth.ToolsOptions) { o.DisableStream = true })
		assertToolsUnrouted(t, env.Do(toolsRequest(env, http.MethodGet, auth.ToolsStreamPath)))
		paths := toolsDocumentPaths(t, toolsDocument(t, env))
		if _, ok := paths[env.Config.ToolsPath()+auth.ToolsStreamPath]; ok {
			t.Errorf("the document still describes %q with the flag off", auth.ToolsStreamPath)
		}
	})

	t.Run("the stream opens with the streaming headers and the connected frame", func(t *testing.T) {
		// The four headers Serve sets, in the reference's set
		// (sse-manager.ts:133-136). X-Accel-Buffering is the one an operator
		// notices: without it nginx buffers the response and turns the stream
		// into a batch.
		env := toolsStreamEnv(t, mount, false)
		stream := openToolsStream(t, env, "", nil)
		frame := stream.rec.next(t)
		if !strings.Contains(frame, "event: connected") {
			t.Errorf("first frame = %q, want the connected frame", frame)
		}
		header := stream.rec.committedHeader(t)
		for name, want := range map[string]string{
			"Content-Type":      "text/event-stream",
			"Cache-Control":     "no-cache",
			"Connection":        "keep-alive",
			"X-Accel-Buffering": "no",
		} {
			if got := header.Get(name); got != want {
				t.Errorf("%s = %q, want %q (sse-manager.ts:133-136)", name, got, want)
			}
		}
	})

	t.Run("the topics are the server's decision", func(t *testing.T) {
		// auth.StreamTopics is the rule (tools.router.ts:207-216) and this route
		// only parses the parameter and calls it. What is pinned here is that
		// the route passes what the client asked for and nothing else, and that
		// the answer reaches the connection — the connected frame reports the
		// topics the manager was registered with.
		authorised := []string{auth.SseTopicGlobal, auth.SseTopicTenantPrefix + toolsStreamTenantID, auth.SseTopicUserPrefix + toolsStreamUserID}
		for _, tc := range []struct {
			name      string
			principal bool
			query     string
			want      []string
		}{
			{"no principal is the single topic global", false, "", []string{auth.SseTopicGlobal}},
			{"a principal adds its tenant and its user", true, "", authorised},
			{"an empty parameter requests nothing", true, "?topics=", authorised},
			{"a subset is honoured", true, "?topics=global,user:" + toolsStreamUserID, []string{auth.SseTopicGlobal, auth.SseTopicUserPrefix + toolsStreamUserID}},
			{"whitespace is trimmed and empties dropped", true, "?topics=%20global%20,,%20", []string{auth.SseTopicGlobal}},
			{"an unauthorised topic is dropped silently", true, "?topics=global," + toolsStreamOther, []string{auth.SseTopicGlobal}},
			{"asking only for one leaves an empty list", true, "?topics=" + toolsStreamOther, []string{}},
			{"a repeated parameter requests nothing at all", true, "?topics=global&topics=" + toolsStreamOther, authorised},
			// session:<id> is published to by EventTopics and authorised by
			// nobody: the reference's two halves disagree, and the disagreement
			// is the source's. See auth.EventTopics.
			{"the session topic is not subscribable", true, "?topics=" + auth.SseTopicSessionPrefix + "s1", []string{}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				env := toolsStreamEnv(t, mount, tc.principal)
				got := toolsStreamTopics(t, env, tc.query)
				if strings.Join(got, ",") != strings.Join(tc.want, ",") {
					t.Errorf("topics = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("an event broadcast to an authorised topic reaches the connection", func(t *testing.T) {
		// The connected frame reports the topic list; this is what proves the
		// manager actually holds it. The wait is on ConnectionCount rather than
		// on a duration, because Serve writes the connected frame *before* it
		// registers the connection (sse-manager.ts:140 against :166) — an event
		// broadcast in that window reaches nobody, which is the reference's
		// order and a real race for a test that assumed the frame meant
		// registration.
		env := toolsStreamEnv(t, mount, true)
		manager := env.Config.Tools.AuthTools.SSE
		stream := openToolsStream(t, env, "", nil)
		stream.rec.next(t) // the connected frame
		waitForTools(t, func() bool { return manager.ConnectionCount() > 0 }, "the connection to be registered")

		manager.Broadcast(context.Background(), auth.SseTopicUserPrefix+toolsStreamUserID, auth.StreamEvent{
			ID:   "evt-1",
			Type: "identity.probe",
			Data: map[string]any{"k": "v"},
		})
		frame := stream.rec.next(t)
		for _, want := range []string{"id: evt-1", "event: identity.probe", `"rawData":{"k":"v"}`} {
			if !strings.Contains(frame, want) {
				t.Errorf("frame %q does not carry %q", frame, want)
			}
		}
	})

	t.Run("a reconnection resumes from now", func(t *testing.T) {
		// Last-Event-ID appears nowhere in the reference's source: the manager
		// stores a per-connection lastEventId and reads it only to deduplicate
		// against the *next* event, nothing is retained, and nothing is
		// replayed. So a reconnecting client is told nothing about what it
		// missed, and this case proves that negative the only way a negative can
		// be proved — by provoking the next frame and showing it is the new one.
		//
		// A Function URL implementor planning an event log on top should read
		// this case as the contract it is adding a guarantee to, not one it is
		// implementing.
		env := toolsStreamEnv(t, mount, true)
		manager := env.Config.Tools.AuthTools.SSE

		first := openToolsStream(t, env, "", nil)
		first.rec.next(t)
		waitForTools(t, func() bool { return manager.ConnectionCount() > 0 }, "the first connection to be registered")
		missed := auth.StreamEvent{ID: "evt-missed", Type: "identity.missed"}
		manager.Broadcast(context.Background(), auth.SseTopicGlobal, missed)
		if frame := first.rec.next(t); !strings.Contains(frame, "id: evt-missed") {
			t.Fatalf("the first connection did not receive the event it is about to miss: %q", frame)
		}
		first.close()
		waitForTools(t, func() bool { return manager.ConnectionCount() == 0 }, "the first connection to be dropped")

		second := openToolsStream(t, env, "", func(r *http.Request) { r.Header.Set("Last-Event-ID", "evt-missed") })
		if frame := second.rec.next(t); !strings.Contains(frame, "event: connected") {
			t.Fatalf("the reconnection's first frame = %q, want the connected frame", frame)
		}
		waitForTools(t, func() bool { return manager.ConnectionCount() > 0 }, "the reconnection to be registered")
		manager.Broadcast(context.Background(), auth.SseTopicGlobal, auth.StreamEvent{ID: "evt-next", Type: "identity.next"})
		if frame := second.rec.next(t); !strings.Contains(frame, "id: evt-next") {
			t.Errorf("the frame after the reconnection = %q, want the next event and not a replay", frame)
		}
	})

	t.Run("the query token reaches the guard as an Authorization header", func(t *testing.T) {
		// extractSseToken (tools.router.ts:185-190), which runs *before* the
		// guard (:192). The guard here records what it was given and refuses, so
		// no stream is opened and the case is an ordinary request/response —
		// which is also the proof that the posture is in front of the guard
		// rather than inside the handler.
		//
		// The overwrite is the security-relevant half: a request carrying both a
		// header and a query token is authenticated as the query token, and a
		// stale `?token=` therefore refuses a caller whose header was valid.
		for _, tc := range []struct {
			name   string
			query  string
			header string
			want   string
		}{
			{"a query token becomes one", "?token=abc", "", "Bearer abc"},
			{"it overwrites a header that was already there", "?token=abc", "Bearer header-token", "Bearer abc"},
			{"no token leaves the header alone", "", "Bearer header-token", "Bearer header-token"},
			{"an empty token is not a token", "?token=", "Bearer header-token", "Bearer header-token"},
			// Express parses a repeated parameter to an array, which fails its
			// `typeof === 'string'` test and writes no header at all.
			{"a repeated token is not a token", "?token=a&token=b", "Bearer header-token", "Bearer header-token"},
			{"and leaves an absent header absent", "?token=a&token=b", "", ""},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var seen string
				var calls int
				env := toolsStreamEnv(t, mount, false, func(o *auth.ToolsOptions) {
					o.Access = auth.ToolsProtected(func(http.Handler) http.Handler {
						return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							calls++
							seen = r.Header.Get("Authorization")
							w.WriteHeader(http.StatusUnauthorized)
						})
					})
				})
				req := httptest.NewRequest(http.MethodGet, env.Config.ToolsPath()+auth.ToolsStreamPath+tc.query, nil)
				if tc.header != "" {
					req.Header.Set("Authorization", tc.header)
				}
				AssertStatus(t, env.Do(req), http.StatusUnauthorized)
				if calls != 1 {
					t.Fatalf("the guard ran %d times, want 1", calls)
				}
				if seen != tc.want {
					t.Errorf("the guard saw Authorization %q, want %q (tools.router.ts:186-187)", seen, tc.want)
				}
			})
		}
	})

	t.Run("the token is copied for the guard and not into the caller's request", func(t *testing.T) {
		// The reference assigns to req.headers in place. This port hands the
		// guard a clone, so a framework's own logging middleware — which on gin
		// and echo runs after this handler returns, against the request object
		// they still hold — does not record a credential header the client never
		// sent. Nothing downstream can tell: the guard and the handler are both
		// given the clone.
		var seen string
		env := toolsStreamEnv(t, mount, false, func(o *auth.ToolsOptions) {
			o.Access = auth.ToolsProtected(func(http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					seen = r.Header.Get("Authorization")
					w.WriteHeader(http.StatusUnauthorized)
				})
			})
		})
		req := httptest.NewRequest(http.MethodGet, env.Config.ToolsPath()+auth.ToolsStreamPath+"?token=abc", nil)
		AssertStatus(t, env.Do(req), http.StatusUnauthorized)
		if seen != "Bearer abc" {
			t.Fatalf("the guard saw Authorization %q, want %q", seen, "Bearer abc")
		}
		if got := req.Header.Get("Authorization"); got != "" {
			t.Errorf("the caller's own request carries Authorization %q, want it untouched", got)
		}
	})

	t.Run("the route is read-only", func(t *testing.T) {
		// router.get registers GET alone (tools.router.ts:192); anything else
		// matches no layer and ends at the router 404.
		env := toolsStreamEnv(t, mount, false)
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			assertToolsUnrouted(t, env.Do(toolsRequest(env, method, auth.ToolsStreamPath)))
		}
	})
}
