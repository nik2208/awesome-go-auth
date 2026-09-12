package auth

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	_ WebhookStore        = (*MemoryWebhookStore)(nil)
	_ WebhookAdminStore   = (*MemoryWebhookStore)(nil)
	_ InboundWebhookStore = (*MemoryWebhookStore)(nil)
)

// The three defaults are documented on WebhookConfig and applied by the sender
// with ??, which keeps a stored 0 as 0 (webhook-sender.ts:18-19). A port that
// used bare ints would turn "deliver once, never retry" into three retries and
// an unset isActive into a silenced webhook.
func TestWebhookConfigResolvesTheReferenceDefaults(t *testing.T) {
	var unset WebhookConfig
	if !unset.Active() {
		t.Error("Active() on an unset IsActive = false, want true (webhook-store.interface.ts:17)")
	}
	if got := unset.Retries(); got != DefaultWebhookMaxRetries {
		t.Errorf("Retries() = %d, want %d", got, DefaultWebhookMaxRetries)
	}
	if got := unset.RetryDelay(); got != DefaultWebhookRetryDelay {
		t.Errorf("RetryDelay() = %v, want %v", got, DefaultWebhookRetryDelay)
	}

	zeroed := WebhookConfig{IsActive: boolPtr(false), MaxRetries: intPtr(0), RetryDelayMs: intPtr(0)}
	if zeroed.Active() {
		t.Error("Active() on an explicit false = true, want false")
	}
	if got := zeroed.Retries(); got != 0 {
		t.Errorf("Retries() on an explicit 0 = %d, want 0 — the ?? in the sender keeps it", got)
	}
	if got := zeroed.RetryDelay(); got != 0 {
		t.Errorf("RetryDelay() on an explicit 0 = %v, want 0", got)
	}

	set := WebhookConfig{IsActive: boolPtr(true), MaxRetries: intPtr(7), RetryDelayMs: intPtr(250)}
	if !set.Active() {
		t.Error("Active() on an explicit true = false")
	}
	if got := set.Retries(); got != 7 {
		t.Errorf("Retries() = %d, want 7", got)
	}
	if got := set.RetryDelay(); got != 250*time.Millisecond {
		t.Errorf("RetryDelay() = %v, want 250ms", got)
	}
}

// The matching rules are the reference's example query, read as prose
// (webhook-store.interface.ts:104-106, :114-115). Nothing downstream re-checks
// any of them: the emit loop hands every returned config to the sender
// unchanged (auth-tools.ts:264-267).
func TestWebhookConfigMatches(t *testing.T) {
	const event = "identity.auth.login.success"
	cases := []struct {
		name     string
		config   WebhookConfig
		event    string
		tenantID string
		want     bool
	}{
		{"exact event name", WebhookConfig{Events: []string{event}}, event, "", true},
		{"wildcard", WebhookConfig{Events: []string{WebhookEventWildcard}}, event, "", true},
		{"one of several", WebhookConfig{Events: []string{"a", event, "b"}}, event, "", true},
		{"other event", WebhookConfig{Events: []string{"identity.auth.logout"}}, event, "", false},
		{"empty events matches nothing", WebhookConfig{Events: []string{}}, event, "", false},
		{"nil events matches nothing", WebhookConfig{}, event, "", false},
		{
			// Only the bare "*" is a pattern; everything else is compared
			// literally, so a prefix subscription is not a thing here.
			"prefix wildcard is not a pattern",
			WebhookConfig{Events: []string{"identity.auth.*"}}, event, "", false,
		},
		{"inactive", WebhookConfig{Events: []string{WebhookEventWildcard}, IsActive: boolPtr(false)}, event, "", false},
		{"nil isActive is active", WebhookConfig{Events: []string{WebhookEventWildcard}}, event, "", true},
		{
			"global webhook fires for a tenant",
			WebhookConfig{Events: []string{WebhookEventWildcard}}, event, "acme", true,
		},
		{
			"tenant webhook fires for its tenant",
			WebhookConfig{Events: []string{WebhookEventWildcard}, TenantID: "acme"}, event, "acme", true,
		},
		{
			"tenant webhook does not fire for another tenant",
			WebhookConfig{Events: []string{WebhookEventWildcard}, TenantID: "acme"}, event, "other", false,
		},
		{
			// tenantId ?? null makes the first branch unsatisfiable and leaves
			// orWhereNull, so an untenanted event reaches global webhooks only
			// (webhook-store.interface.ts:105).
			"tenant webhook does not fire for an untenanted event",
			WebhookConfig{Events: []string{WebhookEventWildcard}, TenantID: "acme"}, event, "", false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.config.Matches(tc.event, tc.tenantID); got != tc.want {
				t.Errorf("Matches(%q, %q) = %v, want %v", tc.event, tc.tenantID, got, tc.want)
			}
		})
	}
}

// An empty events list subscribes a configuration to nothing. The removed
// WebhookDispatcher read the same emptiness as "every event", which is why it
// could not be pointed at a store rather than replaced; the store's rule is the
// reference's positive containment test (webhook-store.interface.ts:106) and is
// the only one left.
func TestEmptyEventsSubscribesToNothing(t *testing.T) {
	if (WebhookConfig{}).Matches("identity.auth.login.success", "") {
		t.Error("WebhookConfig with no events matched; the reference subscribes it to nothing")
	}
	if (WebhookConfig{Events: []string{}}).Matches("identity.auth.login.success", "") {
		t.Error("WebhookConfig with an empty events slice matched; absent and empty mean the same here")
	}
}

// The JSON key names are the reference's, so a document round-trips between
// this port and a node-auth deployment. events has no omitempty: the reference
// types it as required (webhook-store.interface.ts:14).
func TestWebhookConfigJSONIsTheReferenceShape(t *testing.T) {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	full := WebhookConfig{
		ID: "whk_1", URL: "https://example.test/hook", Events: []string{"*"},
		Secret: "s3cr3t", IsActive: boolPtr(false), TenantID: "acme",
		MaxRetries: intPtr(0), RetryDelayMs: intPtr(1000),
		Provider: "stripe", AllowedActions: []string{"billing.cancelSubscription"},
		JSScript: "result = null;",
	}
	if err := enc.Encode(full); err != nil {
		t.Fatal(err)
	}
	const wantFull = `{"id":"whk_1","url":"https://example.test/hook","events":["*"],` +
		`"secret":"s3cr3t","isActive":false,"tenantId":"acme","maxRetries":0,"retryDelayMs":1000,` +
		`"provider":"stripe","allowedActions":["billing.cancelSubscription"],"jsScript":"result = null;"}`
	if got := strings.TrimSpace(buf.String()); got != wantFull {
		t.Errorf("full config = %s\nwant %s", got, wantFull)
	}

	buf.Reset()
	if err := enc.Encode(WebhookConfig{}); err != nil {
		t.Fatal(err)
	}
	const wantEmpty = `{"id":"","url":"","events":null}`
	if got := strings.TrimSpace(buf.String()); got != wantEmpty {
		t.Errorf("zero config = %s, want %s", got, wantEmpty)
	}

	// The whole point of the pointers: an absent isActive decodes as absent and
	// stays active, where a bool would have decoded false and silenced it.
	var decoded WebhookConfig
	if err := json.Unmarshal([]byte(`{"id":"whk_2","url":"u","events":["*"]}`), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.IsActive != nil || decoded.MaxRetries != nil || decoded.RetryDelayMs != nil {
		t.Errorf("decoded optionals = %+v, want all nil", decoded)
	}
	if !decoded.Active() {
		t.Error("a config decoded without isActive is inactive; it must default to true")
	}
}

// data is written as data ?? null, so the key is always present
// (auth-tools.ts:256); metadata is an object whose undefined members
// JSON.stringify drops (:257-262).
func TestOutgoingWebhookEventJSONIsTheReferenceShape(t *testing.T) {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(OutgoingWebhookEvent{
		Event:     "identity.auth.login.success",
		Version:   OutgoingWebhookVersion,
		Timestamp: "2026-09-12T10:00:00.000Z",
	}); err != nil {
		t.Fatal(err)
	}
	const want = `{"event":"identity.auth.login.success","version":"1",` +
		`"timestamp":"2026-09-12T10:00:00.000Z","data":null}`
	if got := strings.TrimSpace(buf.String()); got != want {
		t.Errorf("event = %s\nwant %s", got, want)
	}
}

func seedWebhooks(t *testing.T, store *MemoryWebhookStore, configs ...WebhookConfig) []string {
	t.Helper()
	ctx := context.Background()
	ids := make([]string, 0, len(configs))
	for _, config := range configs {
		stored, err := store.AddWebhook(ctx, config)
		if err != nil {
			t.Fatalf("add: %v", err)
		}
		ids = append(ids, stored.ID)
	}
	return ids
}

func webhookIDs(configs []WebhookConfig) []string {
	ids := make([]string, 0, len(configs))
	for _, config := range configs {
		ids = append(ids, config.ID)
	}
	return ids
}

// AddWebhook owns the identifier, the way the reference's
// add(Omit<WebhookConfig,'id'>) does (webhook-store.interface.ts:129).
func TestMemoryWebhookStoreAddAssignsTheID(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryWebhookStore()

	first, err := store.AddWebhook(ctx, WebhookConfig{ID: "mine", URL: "https://a.test"})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if first.ID == "mine" {
		t.Error("the caller's ID survived; the store assigns it")
	}
	if !strings.HasPrefix(first.ID, "whk_") {
		t.Errorf("assigned ID = %q, want a whk_ prefix", first.ID)
	}
	second, err := store.AddWebhook(ctx, WebhookConfig{URL: "https://b.test"})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if second.ID == first.ID {
		t.Errorf("both adds returned %q", first.ID)
	}
	page, err := store.ListWebhooks(ctx, 10, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got := webhookIDs(page); !reflect.DeepEqual(got, []string{first.ID, second.ID}) {
		t.Errorf("listed %v, want the two ids in insertion order", got)
	}
}

// Insertion order is this package's normative order, and the one downstream
// stores register their own against.
func TestMemoryWebhookStoreKeepsInsertionOrder(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryWebhookStore()
	all := []string{WebhookEventWildcard}
	ids := seedWebhooks(t, store,
		WebhookConfig{URL: "https://a.test", Events: all},
		WebhookConfig{URL: "https://b.test", Events: all},
		WebhookConfig{URL: "https://c.test", Events: all},
	)

	found, err := store.FindByEvent(ctx, "identity.auth.login.success", "")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if got := webhookIDs(found); !reflect.DeepEqual(got, ids) {
		t.Errorf("FindByEvent order = %v, want %v", got, ids)
	}

	// An update leaves the configuration where it is.
	if err := store.UpdateWebhook(ctx, ids[0], WebhookPatch{URL: strPtr("https://a2.test")}); err != nil {
		t.Fatalf("update: %v", err)
	}
	found, err = store.FindByEvent(ctx, "identity.auth.login.success", "")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if got := webhookIDs(found); !reflect.DeepEqual(got, ids) {
		t.Errorf("order after update = %v, want %v", got, ids)
	}

	// A removal closes the gap; the next add goes to the end.
	if err := store.RemoveWebhook(ctx, ids[1]); err != nil {
		t.Fatalf("remove: %v", err)
	}
	fourth, err := store.AddWebhook(ctx, WebhookConfig{URL: "https://d.test", Events: all})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	found, err = store.FindByEvent(ctx, "identity.auth.login.success", "")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	want := []string{ids[0], ids[2], fourth.ID}
	if got := webhookIDs(found); !reflect.DeepEqual(got, want) {
		t.Errorf("order after remove and add = %v, want %v", got, want)
	}
}

// FindByEvent is the only filter in the chain, so every rule has to hold here.
func TestMemoryWebhookStoreFindByEventFilters(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryWebhookStore()
	const event = "identity.auth.login.success"
	ids := seedWebhooks(t, store,
		WebhookConfig{URL: "https://global-wildcard.test", Events: []string{WebhookEventWildcard}},
		WebhookConfig{URL: "https://global-exact.test", Events: []string{event}},
		WebhookConfig{URL: "https://global-other.test", Events: []string{"identity.auth.logout"}},
		WebhookConfig{URL: "https://global-inactive.test", Events: []string{WebhookEventWildcard}, IsActive: boolPtr(false)},
		WebhookConfig{URL: "https://acme.test", Events: []string{WebhookEventWildcard}, TenantID: "acme"},
		WebhookConfig{URL: "https://other.test", Events: []string{WebhookEventWildcard}, TenantID: "other"},
	)
	globalWildcard, globalExact, acme := ids[0], ids[1], ids[4]

	forTenant, err := store.FindByEvent(ctx, event, "acme")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	wantTenant := []string{globalWildcard, globalExact, acme}
	if got := webhookIDs(forTenant); !reflect.DeepEqual(got, wantTenant) {
		t.Errorf("tenant-scoped find = %v, want the two global and the acme one %v", got, wantTenant)
	}

	global, err := store.FindByEvent(ctx, event, "")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	wantGlobal := []string{globalWildcard, globalExact}
	if got := webhookIDs(global); !reflect.DeepEqual(got, wantGlobal) {
		t.Errorf("untenanted find = %v, want the global ones only %v", got, wantGlobal)
	}

	// An event nobody named still reaches the wildcards, global and
	// tenant-scoped alike.
	wildcardsOnly, err := store.FindByEvent(ctx, "identity.nothing.subscribes", "acme")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	wantWildcards := []string{globalWildcard, acme}
	if got := webhookIDs(wildcardsOnly); !reflect.DeepEqual(got, wantWildcards) {
		t.Errorf("unsubscribed event = %v, want the two wildcards %v", got, wantWildcards)
	}
}

func TestMemoryWebhookStoreListPagination(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryWebhookStore()
	ids := seedWebhooks(t, store,
		WebhookConfig{URL: "https://a.test"},
		WebhookConfig{URL: "https://b.test", IsActive: boolPtr(false)},
		WebhookConfig{URL: "https://c.test"},
	)

	cases := []struct {
		name          string
		limit, offset int
		want          []string
	}{
		// Inactive configurations are listed: the admin screen manages them.
		{"everything", 10, 0, ids},
		{"first page", 2, 0, ids[:2]},
		{"second page", 2, 2, ids[2:]},
		{"offset past the end", 10, 99, nil},
		{"limit zero returns nothing", 0, 0, nil},
		{"negative limit returns nothing", -1, 0, nil},
		{"negative offset clamps to the start", 1, -5, ids[:1]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			page, err := store.ListWebhooks(ctx, tc.limit, tc.offset)
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if page == nil {
				t.Fatal("list returned a nil slice; it must always return a slice")
			}
			got := webhookIDs(page)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("list(%d, %d) = %v, want %v", tc.limit, tc.offset, got, tc.want)
			}
		})
	}
}

// A patch is Partial<Omit<WebhookConfig,'id'>>: present replaces, absent leaves
// alone, and the ID is not part of it (webhook-store.interface.ts:141).
func TestMemoryWebhookStorePatchSemantics(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryWebhookStore()
	seeded, err := store.AddWebhook(ctx, WebhookConfig{
		URL: "https://a.test", Events: []string{"identity.auth.logout"},
		Secret: "s", TenantID: "acme", MaxRetries: intPtr(5),
		AllowedActions: []string{"one", "two"}, Provider: "stripe",
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	// isActive false is the admin toggle, and has to be distinguishable from
	// "not in this patch" — which is the whole reason IsActive is a pointer.
	if err := store.UpdateWebhook(ctx, seeded.ID, WebhookPatch{
		IsActive: boolPtr(false),
		Events:   []string{WebhookEventWildcard},
	}); err != nil {
		t.Fatalf("update: %v", err)
	}
	page, err := store.ListWebhooks(ctx, 10, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	got := page[0]
	if got.ID != seeded.ID {
		t.Errorf("ID = %q, want the assigned %q — a patch cannot move it", got.ID, seeded.ID)
	}
	if got.Active() {
		t.Error("the explicit false did not take")
	}
	if !reflect.DeepEqual(got.Events, []string{WebhookEventWildcard}) {
		t.Errorf("Events = %v, want the patch's list whole", got.Events)
	}
	if got.Secret != "s" || got.TenantID != "acme" || got.Provider != "stripe" {
		t.Errorf("an absent field was overwritten: %+v", got)
	}
	if got.MaxRetries == nil || *got.MaxRetries != 5 {
		t.Errorf("MaxRetries = %v, want the stored 5 left alone", got.MaxRetries)
	}
	if !reflect.DeepEqual(got.AllowedActions, []string{"one", "two"}) {
		t.Errorf("AllowedActions = %v, want them left alone", got.AllowedActions)
	}

	// A non-nil empty slice clears.
	if err := store.UpdateWebhook(ctx, seeded.ID, WebhookPatch{AllowedActions: []string{}}); err != nil {
		t.Fatalf("update: %v", err)
	}
	page, err = store.ListWebhooks(ctx, 10, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page[0].AllowedActions) != 0 {
		t.Errorf("AllowedActions = %v, want cleared by the empty slice", page[0].AllowedActions)
	}

	// An unknown id changes nothing and is not an error: the reference's remove
	// and update return void and its routes answer success regardless
	// (admin.router.ts:1414-1440).
	if err := store.UpdateWebhook(ctx, "whk_absent", WebhookPatch{URL: strPtr("https://z.test")}); err != nil {
		t.Errorf("update of an unknown id = %v, want nil", err)
	}
	if err := store.RemoveWebhook(ctx, "whk_absent"); err != nil {
		t.Errorf("remove of an unknown id = %v, want nil", err)
	}
	if err := store.RemoveWebhook(ctx, seeded.ID); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := store.RemoveWebhook(ctx, seeded.ID); err != nil {
		t.Errorf("second remove of the same id = %v, want nil", err)
	}
	page, err = store.ListWebhooks(ctx, 10, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page) != 0 {
		t.Errorf("store still holds %v after the remove", webhookIDs(page))
	}
}

// findByProvider does not filter on isActive: its only caller tests the result
// for a jsScript and nothing else (tools.router.ts:257-259). Reproduced, not
// corrected — M9 needs to know.
func TestMemoryWebhookStoreFindByProvider(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryWebhookStore()
	ids := seedWebhooks(t, store,
		WebhookConfig{URL: "https://outgoing.test", Events: []string{WebhookEventWildcard}},
		WebhookConfig{Provider: "stripe", JSScript: "result = null;", IsActive: boolPtr(false)},
		WebhookConfig{Provider: "stripe", JSScript: "result = 1;"},
		WebhookConfig{Provider: "github", JSScript: "result = null;"},
	)

	config, ok, err := store.FindByProvider(ctx, "stripe")
	if err != nil || !ok {
		t.Fatalf("find stripe: ok=%v err=%v", ok, err)
	}
	if config.ID != ids[1] {
		t.Errorf("found %q, want the first stripe config in insertion order %q", config.ID, ids[1])
	}
	if config.Active() {
		t.Error("the inactive stripe config was skipped; findByProvider does not filter on isActive")
	}

	if _, ok, err := store.FindByProvider(ctx, "paypal"); err != nil || ok {
		t.Errorf("unknown provider: ok=%v err=%v, want a clean miss", ok, err)
	}
	// Every outgoing-only configuration leaves provider unset, so "" must not
	// hand the router one of them.
	if _, ok, err := store.FindByProvider(ctx, ""); err != nil || ok {
		t.Errorf("empty provider: ok=%v err=%v, want a clean miss", ok, err)
	}
}

// Everything handed out is a deep copy, including the pointers: a caller that
// flips *IsActive on a returned config must not silence the stored one.
func TestMemoryWebhookStoreHandsOutCopies(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryWebhookStore()
	events := []string{WebhookEventWildcard}
	actions := []string{"one"}
	active := true
	stored, err := store.AddWebhook(ctx, WebhookConfig{
		URL: "https://a.test", Events: events, AllowedActions: actions,
		IsActive: &active, MaxRetries: intPtr(2),
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	// The caller's own inputs are copied on the way in.
	events[0] = "identity.auth.logout"
	actions[0] = "two"
	active = false

	// And the returned value is copied on the way out.
	stored.Events[0] = "identity.auth.logout"
	stored.AllowedActions[0] = "three"
	*stored.IsActive = false
	*stored.MaxRetries = 99

	found, err := store.FindByEvent(ctx, "anything.at.all", "")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("find returned %d configs, want the wildcard one", len(found))
	}
	got := found[0]
	if !reflect.DeepEqual(got.Events, []string{WebhookEventWildcard}) {
		t.Errorf("Events = %v, want the stored wildcard", got.Events)
	}
	if !reflect.DeepEqual(got.AllowedActions, []string{"one"}) {
		t.Errorf("AllowedActions = %v, want the stored list", got.AllowedActions)
	}
	if !got.Active() {
		t.Error("the stored config was deactivated through a returned pointer")
	}
	if got.MaxRetries == nil || *got.MaxRetries != 2 {
		t.Errorf("MaxRetries = %v, want the stored 2", got.MaxRetries)
	}
	if got.Events == nil {
		t.Error("a copy lost the slice")
	}
}

// copySlice preserves nil, and nil means absent in this type: a config stored
// without allowedActions must not come back holding an empty list, or a store
// that round-trips through this one would invent a key.
func TestMemoryWebhookStorePreservesNilSlices(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryWebhookStore()
	if _, err := store.AddWebhook(ctx, WebhookConfig{URL: "https://a.test"}); err != nil {
		t.Fatalf("add: %v", err)
	}
	page, err := store.ListWebhooks(ctx, 1, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if page[0].Events != nil || page[0].AllowedActions != nil {
		t.Errorf("nil slices came back as %+v, want both nil", page[0])
	}
	if page[0].IsActive != nil || page[0].MaxRetries != nil || page[0].RetryDelayMs != nil {
		t.Errorf("nil pointers came back set: %+v", page[0])
	}
}

// The store is on the emit path, which is concurrent by construction: the
// reference fires every delivery without awaiting it (auth-tools.ts:264-267).
func TestMemoryWebhookStoreIsSafeForConcurrentUse(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryWebhookStore()
	seeded := seedWebhooks(t, store,
		WebhookConfig{URL: "https://a.test", Events: []string{WebhookEventWildcard}},
		WebhookConfig{URL: "https://b.test", Events: []string{WebhookEventWildcard}, Provider: "stripe"},
	)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := store.FindByEvent(ctx, "identity.auth.login.success", "acme"); err != nil {
				t.Error(err)
			}
			if _, err := store.ListWebhooks(ctx, 10, 0); err != nil {
				t.Error(err)
			}
			if _, _, err := store.FindByProvider(ctx, "stripe"); err != nil {
				t.Error(err)
			}
			if _, err := store.AddWebhook(ctx, WebhookConfig{URL: "https://n.test"}); err != nil {
				t.Error(err)
			}
			if err := store.UpdateWebhook(ctx, seeded[0], WebhookPatch{Secret: strPtr("s")}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
}
