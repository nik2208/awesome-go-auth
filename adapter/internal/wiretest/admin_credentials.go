package wiretest

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

// The credential half of the admin console: U14b's eight routes, the four under
// /api/api-keys and the four under /api/webhooks (admin.router.ts:1250-1440).
//
// They are a file of their own rather than more cases in admin.go because they
// are their own class of risk — every one of them holds, mints or masks a secret
// — and because the assertions that matter most here are about what is *absent*
// from a body rather than about what is in it.
//
// Those assertions are made over the serialised bytes and not over a decoded
// field. A case that reads `row["keyHash"] == nil` passes for a body that spells
// the hash under another name, nests it, or leaks it through a field some later
// projection grew; a case that refuses the hash's bytes anywhere in the response
// fails on all three. The same goes for the raw key and for a webhook's signing
// secret.

// testAPIKeyStore implements auth.APIKeyStore and none of its companions: the
// deployment whose store can authenticate a key and can neither enumerate nor
// destroy one. It is what separates the two absences these routes answer
// differently — 404 for no store at all, 501 naming the single optional method
// for this one.
type testAPIKeyStore struct{ inner *auth.MemoryAPIKeyStore }

func (s testAPIKeyStore) Save(ctx context.Context, key auth.APIKeyRecord) error {
	return s.inner.Save(ctx, key)
}

func (s testAPIKeyStore) FindByPrefix(ctx context.Context, prefix string) (auth.APIKeyRecord, error) {
	return s.inner.FindByPrefix(ctx, prefix)
}

func (s testAPIKeyStore) FindByID(ctx context.Context, id string) (auth.APIKeyRecord, error) {
	return s.inner.FindByID(ctx, id)
}

func (s testAPIKeyStore) Revoke(ctx context.Context, id string) error {
	return s.inner.Revoke(ctx, id)
}

func (s testAPIKeyStore) UpdateLastUsed(ctx context.Context, id string, when time.Time) error {
	return s.inner.UpdateLastUsed(ctx, id, when)
}

// testAPIKeyListStore adds ListAll and stops there. It is the store v0.8.0 split
// the optional methods one-to-an-interface for: it can serve the listing and
// cannot hard-delete, so DELETE /api/api-keys/:id has to notice the absence of
// that one method on a store whose others are present.
type testAPIKeyListStore struct{ testAPIKeyStore }

func (s testAPIKeyListStore) ListAll(ctx context.Context, limit, offset int) ([]auth.APIKeyRecord, error) {
	return s.inner.ListAll(ctx, limit, offset)
}

// testWebhookStore implements auth.WebhookStore and not auth.WebhookAdminStore:
// outgoing deliveries work, and each management route answers the 501 naming the
// method the reference names there.
type testWebhookStore struct{ inner *auth.MemoryWebhookStore }

func (s testWebhookStore) FindByEvent(ctx context.Context, event, tenantID string) ([]auth.WebhookConfig, error) {
	return s.inner.FindByEvent(ctx, event, tenantID)
}

// adminCredentialPaths is every route U14b mounts, walked by the not-mounted
// sweep through adminAllRoutes. Like the writes, the method is part of the entry:
// /api/api-keys is a listing and a mint depending on it.
var adminCredentialPaths = []adminRoute{
	{http.MethodGet, auth.AdminAPIKeysPath},
	{http.MethodPost, auth.AdminAPIKeysPath},
	{http.MethodDelete, auth.AdminAPIKeysPath + "/a-key/revoke"},
	{http.MethodDelete, auth.AdminAPIKeysPath + "/a-key"},
	{http.MethodGet, auth.AdminWebhooksPath},
	{http.MethodPost, auth.AdminWebhooksPath},
	{http.MethodPatch, auth.AdminWebhooksPath + "/a-hook"},
	{http.MethodDelete, auth.AdminWebhooksPath + "/a-hook"},
}

// adminCredentialStores wires both stores and hands the concrete values back, so
// that a case can read what the wire was not shown — the secret a listing masked,
// the hash a projection dropped.
func adminCredentialStores() (*auth.MemoryAPIKeyStore, *auth.MemoryWebhookStore, []auth.Option) {
	keys := auth.NewMemoryAPIKeyStore()
	hooks := auth.NewMemoryWebhookStore()
	return keys, hooks, []auth.Option{auth.WithAPIKeyStore(keys), auth.WithWebhookStore(hooks)}
}

// adminCredentialEnv mounts a console with both stores under the open policy.
func adminCredentialEnv(t *testing.T, mount Mounter) (*adminEnv, *auth.MemoryAPIKeyStore, *auth.MemoryWebhookStore) {
	t.Helper()
	keys, hooks, stores := adminCredentialStores()
	return newAdminEnv(t, mount, adminEnvOptions{admin: adminOpenOptions(), options: stores}), keys, hooks
}

func testAdminCredentials(t *testing.T, mount Mounter) {
	t.Run("Guarded", func(t *testing.T) { testAdminCredentialsGuarded(t, mount) })
	t.Run("NoStore", func(t *testing.T) { testAdminCredentialsNoStore(t, mount) })
	t.Run("Features", func(t *testing.T) { testAdminCredentialFeatures(t, mount) })
	t.Run("APIKeysNotImplemented", func(t *testing.T) { testAdminAPIKeysNotImplemented(t, mount) })
	t.Run("APIKeysList", func(t *testing.T) { testAdminAPIKeysList(t, mount) })
	t.Run("APIKeysCreate", func(t *testing.T) { testAdminAPIKeysCreate(t, mount) })
	t.Run("APIKeysDelete", func(t *testing.T) { testAdminAPIKeysDelete(t, mount) })
	t.Run("WebhooksNotImplemented", func(t *testing.T) { testAdminWebhooksNotImplemented(t, mount) })
	t.Run("WebhooksList", func(t *testing.T) { testAdminWebhooksList(t, mount) })
	t.Run("WebhooksCreate", func(t *testing.T) { testAdminWebhooksCreate(t, mount) })
	t.Run("WebhooksPatch", func(t *testing.T) { testAdminWebhooksPatch(t, mount) })
	t.Run("WebhooksDelete", func(t *testing.T) { testAdminWebhooksDelete(t, mount) })
}

// testAdminCredentialsGuarded is the read and write suites' invariant applied to
// the eight that matter most: an unguarded mint is worse than an unguarded
// listing, and an unguarded listing here is the key table.
func testAdminCredentialsGuarded(t *testing.T, mount Mounter) {
	_, _, stores := adminCredentialStores()
	env := newAdminEnv(t, mount, adminEnvOptions{
		admin:   auth.AdminOptions{Enabled: true, AccessPolicy: auth.AdminIsAdminFlag()},
		options: stores,
	})
	for _, route := range adminCredentialPaths {
		rec := env.Do(env.adminRequest(route.method, route.path, "{}"))
		AssertError(t, rec, http.StatusUnauthorized, "Unauthorized", "")

		// And with the header that reads the whole admin API on the reference;
		// see the admin-unauthenticated-get-serves-only-the-login-form deviation.
		rec = env.Do(adminHTML(env.adminRequest(route.method, route.path, "{}")))
		AssertError(t, rec, http.StatusUnauthorized, "Unauthorized", "")
	}
}

// testAdminCredentialsNoStore is the first of the two absences. The routes are
// registered — they sit outside the conditional block the template routes are in
// — and each answers 404 naming the store it was not given (:1254, :1364).
func testAdminCredentialsNoStore(t *testing.T, mount Mounter) {
	env := newAdminEnv(t, mount, adminEnvOptions{admin: adminOpenOptions()})
	for _, route := range adminCredentialPaths {
		want := "API key store not configured"
		if strings.HasPrefix(route.path, auth.AdminWebhooksPath) {
			want = "Webhook store not configured"
		}
		rec := env.Do(env.adminRequest(route.method, route.path, `{"name":"x","url":"https://x.example"}`))
		AssertError(t, rec, http.StatusNotFound, want, "")
	}
}

// testAdminCredentialFeatures pins the two flags U14b earns. They are
// `!!options.apiKeyStore` and `!!options.webhookStore` (:653-654) — the store
// being configured, and deliberately not what it can do: a store that cannot
// enumerate still turns its tab on and answers 501 to the listing the tab draws.
func testAdminCredentialFeatures(t *testing.T, mount Mounter) {
	features := func(t *testing.T, env *adminEnv) map[string]any {
		t.Helper()
		body := adminGet(t, env, auth.AdminPingPath, http.StatusOK)
		AssertKeys(t, body, "ok", "features")
		flags, ok := body["features"].(map[string]any)
		if !ok {
			t.Fatalf("features = %v, want an object", body["features"])
		}
		return flags
	}

	t.Run("off without the stores", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{admin: adminOpenOptions()})
		flags := features(t, env)
		if flags["apiKeys"] != false || flags["webhooks"] != false {
			t.Errorf("features = %v, want both flags off", flags)
		}
	})

	t.Run("on with them, whatever the stores can do", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{
			admin: adminOpenOptions(),
			options: []auth.Option{
				auth.WithAPIKeyStore(testAPIKeyStore{inner: auth.NewMemoryAPIKeyStore()}),
				auth.WithWebhookStore(testWebhookStore{inner: auth.NewMemoryWebhookStore()}),
			},
		})
		flags := features(t, env)
		if flags["apiKeys"] != true || flags["webhooks"] != true {
			t.Errorf("features = %v, want both flags on for the narrowest stores there are", flags)
		}
	})
}

// testAdminAPIKeysNotImplemented is the second absence, asked per method.
func testAdminAPIKeysNotImplemented(t *testing.T, mount Mounter) {
	newEnv := func(t *testing.T, store auth.APIKeyStore) *adminEnv {
		t.Helper()
		return newAdminEnv(t, mount, adminEnvOptions{
			admin:   adminOpenOptions(),
			options: []auth.Option{auth.WithAPIKeyStore(store)},
		})
	}

	t.Run("a store that cannot list is a 501 carrying an empty page", func(t *testing.T) {
		env := newEnv(t, testAPIKeyStore{inner: auth.NewMemoryAPIKeyStore()})
		body := adminGet(t, env, auth.AdminAPIKeysPath, http.StatusNotImplemented)
		// error, keys and total (:1260) — the shape GET /api/users' 501 has, so
		// the tab renders "0 keys" instead of breaking on an absent key, and
		// deliberately not the bare 501 of the 2FA-policy walk.
		AssertKeys(t, body, "error", "keys", "total")
		if body["error"] != "IApiKeyStore.listAll is not implemented" {
			t.Errorf("error = %v, want the message naming the optional method", body["error"])
		}
		if entries := adminEntries(t, body, "keys"); len(entries) != 0 {
			t.Errorf("keys = %v, want []", entries)
		}
		if adminTotal(t, body) != 0 {
			t.Errorf("total = %v, want 0", body["total"])
		}
	})

	t.Run("minting and revoking need no optional method", func(t *testing.T) {
		// Save and Revoke are on IApiKeyStore itself, so both routes work on the
		// narrowest store there is; the reference asserts nothing before either
		// (:1296-1312, :1337).
		env := newEnv(t, testAPIKeyStore{inner: auth.NewMemoryAPIKeyStore()})
		created := adminSend(t, env, http.MethodPost, auth.AdminAPIKeysPath,
			`{"name":"ci"}`, http.StatusOK)
		AssertKeys(t, created, "rawKey", "record")
		id := created["record"].(map[string]any)["id"].(string)
		adminAssertSuccess(t, env, http.MethodDelete, auth.AdminAPIKeysPath+"/"+id+"/revoke", "")
	})
}

// adminCreateKey mints one key through the route and returns the raw key beside
// the record, which is the only moment the raw value exists at all.
func adminCreateKey(t *testing.T, env *adminEnv, body string) (string, map[string]any) {
	t.Helper()
	created := adminSend(t, env, http.MethodPost, auth.AdminAPIKeysPath, body, http.StatusOK)
	AssertKeys(t, created, "rawKey", "record")
	raw, ok := created["rawKey"].(string)
	if !ok || raw == "" {
		t.Fatalf("rawKey = %v, want the minted key", created["rawKey"])
	}
	record, ok := created["record"].(map[string]any)
	if !ok {
		t.Fatalf("record = %v, want an object", created["record"])
	}
	return raw, record
}

// testAdminAPIKeysList is GET <admin>/api/api-keys (:1253-1291): the projection,
// the paging, the filter — and the invariant, which is that no key material of
// any kind is in the bytes.
func testAdminAPIKeysList(t *testing.T, mount Mounter) {
	t.Run("the projection is the reference's ten keys and none of them is the hash", func(t *testing.T) {
		env, store, _ := adminCredentialEnv(t, mount)
		raw, record := adminCreateKey(t, env, `{"name":"billing","serviceId":"svc-1","scopes":["tools:read"],`+
			`"allowedIps":["10.0.0.0/8"],"expiresAt":"2030-01-01T00:00:00Z"}`)
		// Stamped so that all ten members have a value: lastUsedAt is null on a
		// key that has never been presented, and this port omits an absent
		// optional rather than writing null.
		if err := store.UpdateLastUsed(context.Background(), record["id"].(string), time.Now()); err != nil {
			t.Fatalf("UpdateLastUsed: %v", err)
		}

		rec := env.Do(env.adminRequest(http.MethodGet, auth.AdminAPIKeysPath, ""))
		AssertStatus(t, rec, http.StatusOK)
		serialised := rec.Body.String()
		body := Body(t, rec)
		AssertKeys(t, body, "keys", "total")

		row := adminObject(t, adminEntries(t, body, "keys"), 0)
		AssertKeys(t, row, "id", "name", "keyPrefix", "serviceId", "scopes", "allowedIps",
			"isActive", "expiresAt", "createdAt", "lastUsedAt")

		// The invariant, asserted over the bytes: neither the raw key nor the
		// bcrypt hash the store holds is anywhere in the response. A field check
		// would pass for a projection that grew a differently-named member
		// carrying either.
		if strings.Contains(serialised, raw) {
			t.Error("the listing disclosed the raw key")
		}
		stored, err := store.FindByID(context.Background(), row["id"].(string))
		if err != nil {
			t.Fatalf("FindByID: %v", err)
		}
		if stored.KeyHash == "" || stored.KeyHash == raw {
			t.Fatalf("the store must hold a hash and not the key itself (got %q)", stored.KeyHash)
		}
		if strings.Contains(serialised, stored.KeyHash) {
			t.Error("the listing disclosed the bcrypt hash")
		}
		if strings.Contains(serialised, "keyHash") {
			t.Error("the listing named keyHash — the projection must not carry the field at all")
		}

		// What it does disclose is the eleven-character prefix, which is the
		// reference's lookup index and is stored in plaintext on purpose
		// (api-key.model.ts:21-27).
		if row["keyPrefix"] != raw[:11] {
			t.Errorf("keyPrefix = %v, want the first 11 characters of the key", row["keyPrefix"])
		}
	})

	t.Run("a key with no optional fields omits them", func(t *testing.T) {
		env, _, _ := adminCredentialEnv(t, mount)
		adminCreateKey(t, env, `{"name":"bare"}`)
		row := adminObject(t, adminEntries(t,
			adminGet(t, env, auth.AdminAPIKeysPath, http.StatusOK), "keys"), 0)
		// scopes survives because the reference's own service writes `?? []`
		// (api-key.service.ts:60) and every client iterates it; the other four are
		// absent, as JSON.stringify omits an undefined member rather than writing
		// null.
		AssertKeys(t, row, "id", "name", "keyPrefix", "scopes", "isActive", "createdAt")
	})

	t.Run("newest first", func(t *testing.T) {
		// APIKeyAdminStore's declared order — CreatedAt descending, ID ascending —
		// which becomes client-visible here for the first time. See the
		// admin-credential-listings-are-ordered deviation.
		env, _, _ := adminCredentialEnv(t, mount)
		adminCreateKey(t, env, `{"name":"first"}`)
		adminCreateKey(t, env, `{"name":"second"}`)
		rows := adminEntries(t, adminGet(t, env, auth.AdminAPIKeysPath, http.StatusOK), "keys")
		if len(rows) != 2 {
			t.Fatalf("keys = %d entries, want 2", len(rows))
		}
		if adminObject(t, rows, 0)["name"] != "second" {
			t.Errorf("first row = %v, want the key minted last", adminObject(t, rows, 0))
		}
	})

	t.Run("paging and the best-effort total", func(t *testing.T) {
		env, _, _ := adminCredentialEnv(t, mount)
		for _, name := range []string{"a", "b", "c"} {
			adminCreateKey(t, env, `{"name":"`+name+`"}`)
		}
		if got := adminTotal(t, adminGet(t, env, auth.AdminAPIKeysPath, http.StatusOK)); got != 3 {
			t.Errorf("total = %d for a short page of 3, want 3", got)
		}
		// A page that happens to be exactly full adds one, and there is no fourth
		// key: the arithmetic at :1288, reproduced rather than counted honestly,
		// because a table that drew no "next" where the reference drew one would
		// be a different console.
		if got := adminTotal(t, adminGet(t, env, auth.AdminAPIKeysPath+"?limit=3", http.StatusOK)); got != 4 {
			t.Errorf("total = %d for a full page of 3 with limit=3, want 4", got)
		}
		if page := adminEntries(t, adminGet(t, env,
			auth.AdminAPIKeysPath+"?limit=1&offset=1", http.StatusOK), "keys"); len(page) != 1 {
			t.Errorf("keys = %d entries for limit=1, want 1", len(page))
		}
	})

	t.Run("the filter matches name, serviceId and keyPrefix", func(t *testing.T) {
		env, _, _ := adminCredentialEnv(t, mount)
		adminCreateKey(t, env, `{"name":"billing","serviceId":"svc-invoices"}`)
		raw, _ := adminCreateKey(t, env, `{"name":"shipping","serviceId":"svc-parcels"}`)

		for _, filter := range []string{"BILL", "invoices", raw[:11]} {
			body := adminGet(t, env, auth.AdminAPIKeysPath+"?filter="+url.QueryEscape(filter), http.StatusOK)
			rows := adminEntries(t, body, "keys")
			if len(rows) != 1 {
				t.Errorf("filter %q matched %d keys, want 1", filter, len(rows))
				continue
			}
			// total is exact under a filter: it is the count before the slice.
			if adminTotal(t, body) != 1 {
				t.Errorf("filter %q: total = %v, want 1", filter, body["total"])
			}
		}
		if rows := adminEntries(t, adminGet(t, env,
			auth.AdminAPIKeysPath+"?filter=nothing-matches", http.StatusOK), "keys"); len(rows) != 0 {
			t.Errorf("keys = %v, want []", rows)
		}
	})
}

// testAdminAPIKeysCreate is POST <admin>/api/api-keys (:1295-1331): the one route
// in the package that answers with a usable credential, and the only place the
// raw key exists.
func testAdminAPIKeysCreate(t *testing.T, mount Mounter) {
	t.Run("name is required", func(t *testing.T) {
		env, _, _ := adminCredentialEnv(t, mount)
		for _, body := range []string{"{}", `{"name":""}`, `{"serviceId":"svc"}`, ""} {
			AssertError(t, env.Do(env.adminRequest(http.MethodPost, auth.AdminAPIKeysPath, body)),
				http.StatusBadRequest, "name is required", "")
		}
	})

	t.Run("the raw key is in the body exactly once, and never again", func(t *testing.T) {
		env, store, _ := adminCredentialEnv(t, mount)
		rec := env.Do(env.adminRequest(http.MethodPost, auth.AdminAPIKeysPath, `{"name":"ci"}`))
		AssertStatus(t, rec, http.StatusOK)
		serialised := rec.Body.String()
		created := Body(t, rec)
		AssertKeys(t, created, "rawKey", "record")
		raw := created["rawKey"].(string)

		// Exactly once in the response: the rawKey member and nowhere else. A
		// record that echoed it — as a second field, or beside the prefix — counts
		// twice and fails here.
		if got := strings.Count(serialised, raw); got != 1 {
			t.Errorf("the raw key appears %d times in the response, want exactly 1:\n%s", got, serialised)
		}

		// And never again: not in the store, not in the listing.
		record := created["record"].(map[string]any)
		AssertKeys(t, record, "id", "name", "keyPrefix", "scopes", "isActive", "createdAt")
		stored, err := store.FindByID(context.Background(), record["id"].(string))
		if err != nil {
			t.Fatalf("FindByID: %v", err)
		}
		if stored.KeyHash == raw {
			t.Fatal("the store holds the raw key — it must hold its bcrypt hash")
		}
		if !strings.HasPrefix(stored.KeyHash, "$2") {
			t.Errorf("stored hash = %q, want a bcrypt hash", stored.KeyHash)
		}
		listing := env.Do(env.adminRequest(http.MethodGet, auth.AdminAPIKeysPath, ""))
		if strings.Contains(listing.Body.String(), raw) {
			t.Error("the listing disclosed the raw key after creation")
		}

		// It is the credential it claims to be: the value returned once
		// authenticates against the hash that was stored, which is what makes
		// "exactly once" a property worth having rather than a lost value.
		if _, err := auth.NewAPIKeyService(0).Verify(context.Background(), store, raw, "", nil); err != nil {
			t.Errorf("the returned key does not verify against the stored hash: %v", err)
		}
	})

	t.Run("the record echoes what was asked for", func(t *testing.T) {
		env, _, _ := adminCredentialEnv(t, mount)
		_, record := adminCreateKey(t, env, `{"name":"billing","serviceId":"svc-1",`+
			`"scopes":["tools:read","tools:write"],"allowedIps":["10.0.0.0/8"],`+
			`"expiresAt":"2030-01-01T00:00:00Z"}`)
		// Nine keys and not the listing's ten: lastUsedAt is in that projection
		// and not in this one (:1316-1326), because a key minted a microsecond ago
		// has never been used.
		AssertKeys(t, record, "id", "name", "keyPrefix", "serviceId", "scopes",
			"allowedIps", "isActive", "expiresAt", "createdAt")
		if record["isActive"] != true {
			t.Errorf("isActive = %v, want true: a new key is active", record["isActive"])
		}
		if scopes := record["scopes"].([]any); len(scopes) != 2 {
			t.Errorf("scopes = %v, want both", scopes)
		}
	})

	t.Run("an unparseable expiresAt is a key that does not expire", func(t *testing.T) {
		// `new Date('tomorrow')` is an Invalid Date there (:1312), which
		// serialises as null and compares false against every instant — so the
		// reference stores a key with no effective expiry rather than refusing the
		// request, and a refusal here would be a difference a client can see.
		env, _, _ := adminCredentialEnv(t, mount)
		_, record := adminCreateKey(t, env, `{"name":"ci","expiresAt":"tomorrow"}`)
		if _, ok := record["expiresAt"]; ok {
			t.Errorf("expiresAt = %v, want it absent", record["expiresAt"])
		}
	})
}

// testAdminAPIKeysDelete is the pair at :1334-1359: two routes, two meanings, and
// the fallback that lets a store decline to destroy its own audit trail.
func testAdminAPIKeysDelete(t *testing.T, mount Mounter) {
	t.Run("revoke keeps the row and clears isActive", func(t *testing.T) {
		env, keys, _ := adminCredentialEnv(t, mount)
		_, record := adminCreateKey(t, env, `{"name":"ci"}`)
		id := record["id"].(string)

		adminAssertSuccess(t, env, http.MethodDelete, auth.AdminAPIKeysPath+"/"+id+"/revoke", "")
		row := adminObject(t, adminEntries(t,
			adminGet(t, env, auth.AdminAPIKeysPath, http.StatusOK), "keys"), 0)
		if row["isActive"] != false {
			t.Errorf("isActive = %v after revoke, want false", row["isActive"])
		}
		if _, err := keys.FindByID(context.Background(), id); err != nil {
			t.Errorf("the row must survive a revoke: %v", err)
		}
	})

	t.Run("delete removes the row when the store can", func(t *testing.T) {
		env, keys, _ := adminCredentialEnv(t, mount)
		_, record := adminCreateKey(t, env, `{"name":"ci"}`)
		id := record["id"].(string)

		// success alone, with no note: nothing fell back.
		adminAssertSuccess(t, env, http.MethodDelete, auth.AdminAPIKeysPath+"/"+id, "")
		if rows := adminEntries(t, adminGet(t, env,
			auth.AdminAPIKeysPath, http.StatusOK), "keys"); len(rows) != 0 {
			t.Errorf("keys = %v after a hard delete, want []", rows)
		}
		if _, err := keys.FindByID(context.Background(), id); err == nil {
			t.Error("the row survived a hard delete")
		}
	})

	t.Run("a store without delete revokes instead and says so", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{
			admin: adminOpenOptions(),
			options: []auth.Option{auth.WithAPIKeyStore(
				testAPIKeyListStore{testAPIKeyStore{inner: auth.NewMemoryAPIKeyStore()}})},
		})
		_, record := adminCreateKey(t, env, `{"name":"ci"}`)

		body := adminSend(t, env, http.MethodDelete,
			auth.AdminAPIKeysPath+"/"+record["id"].(string), "", http.StatusOK)
		AssertKeys(t, body, "success", "note")
		if body["success"] != true {
			t.Errorf("success = %v, want true", body["success"])
		}
		if body["note"] != "IApiKeyStore.delete not implemented; key was revoked instead" {
			t.Errorf("note = %v, want the reference's sentence", body["note"])
		}
		row := adminObject(t, adminEntries(t,
			adminGet(t, env, auth.AdminAPIKeysPath, http.StatusOK), "keys"), 0)
		if row["isActive"] != false {
			t.Errorf("isActive = %v, want false: the fallback revoked", row["isActive"])
		}
	})
}

// adminSeedWebhook registers one webhook through the route and returns its id.
func adminSeedWebhook(t *testing.T, env *adminEnv, body string) string {
	t.Helper()
	created := adminSend(t, env, http.MethodPost, auth.AdminWebhooksPath, body, http.StatusOK)
	AssertKeys(t, created, "webhook")
	hook, ok := created["webhook"].(map[string]any)
	if !ok {
		t.Fatalf("webhook = %v, want an object", created["webhook"])
	}
	id, ok := hook["id"].(string)
	if !ok || id == "" {
		t.Fatalf("webhook.id = %v, want the id the store assigned", hook["id"])
	}
	return id
}

// adminStoredWebhooks reads the store directly, which is how a case asserts on
// the secret the wire is never shown.
func adminStoredWebhooks(t *testing.T, store *auth.MemoryWebhookStore) []auth.WebhookConfig {
	t.Helper()
	configs, err := store.ListWebhooks(context.Background(), 100, 0)
	if err != nil {
		t.Fatalf("ListWebhooks: %v", err)
	}
	return configs
}

// adminStoredWebhook is adminStoredWebhooks where exactly one row is expected.
func adminStoredWebhook(t *testing.T, store *auth.MemoryWebhookStore) auth.WebhookConfig {
	t.Helper()
	configs := adminStoredWebhooks(t, store)
	if len(configs) != 1 {
		t.Fatalf("stored = %v, want exactly one webhook", configs)
	}
	return configs[0]
}

// testAdminWebhooksNotImplemented is the per-method 501 the reference answers for
// each of the four (:1368, :1398, :1416, :1431).
func testAdminWebhooksNotImplemented(t *testing.T, mount Mounter) {
	env := newAdminEnv(t, mount, adminEnvOptions{
		admin: adminOpenOptions(),
		options: []auth.Option{
			auth.WithWebhookStore(testWebhookStore{inner: auth.NewMemoryWebhookStore()}),
		},
	})

	body := adminGet(t, env, auth.AdminWebhooksPath, http.StatusNotImplemented)
	AssertKeys(t, body, "error", "webhooks", "total")
	if body["error"] != "IWebhookStore.listAll is not implemented" {
		t.Errorf("error = %v, want the listing's message", body["error"])
	}
	if entries := adminEntries(t, body, "webhooks"); len(entries) != 0 {
		t.Errorf("webhooks = %v, want []", entries)
	}
	if adminTotal(t, body) != 0 {
		t.Errorf("total = %v, want 0", body["total"])
	}

	for _, c := range []struct {
		method, path, body, message string
	}{
		{http.MethodPost, auth.AdminWebhooksPath, `{"url":"https://hook.example"}`,
			"IWebhookStore.add is not implemented"},
		{http.MethodPatch, auth.AdminWebhooksPath + "/a-hook", `{"isActive":false}`,
			"IWebhookStore.update is not implemented"},
		{http.MethodDelete, auth.AdminWebhooksPath + "/a-hook", "",
			"IWebhookStore.remove is not implemented"},
	} {
		AssertError(t, env.Do(env.adminRequest(c.method, c.path, c.body)),
			http.StatusNotImplemented, c.message, "")
	}

	// url is checked before the capability (:1397 against :1398), so a body with
	// no url is a 400 even on a store that could not have stored it.
	AssertError(t, env.Do(env.adminRequest(http.MethodPost, auth.AdminWebhooksPath, "{}")),
		http.StatusBadRequest, "url is required", "")
}

// testAdminWebhooksList is GET <admin>/api/webhooks (:1363-1387), where the mask
// lives (:1381).
func testAdminWebhooksList(t *testing.T, mount Mounter) {
	const secret = "wiretest-webhook-signing-secret"

	t.Run("the secret is masked and its bytes are not in the response", func(t *testing.T) {
		env, _, _ := adminCredentialEnv(t, mount)
		adminSeedWebhook(t, env, `{"url":"https://hook.example","events":["user.created"],`+
			`"secret":"`+secret+`","tenantId":"acme","maxRetries":5,"retryDelayMs":250}`)

		rec := env.Do(env.adminRequest(http.MethodGet, auth.AdminWebhooksPath, ""))
		AssertStatus(t, rec, http.StatusOK)
		serialised := rec.Body.String()
		body := Body(t, rec)
		AssertKeys(t, body, "webhooks", "total")

		row := adminObject(t, adminEntries(t, body, "webhooks"), 0)
		AssertKeys(t, row, "id", "url", "events", "isActive", "tenantId",
			"maxRetries", "retryDelayMs", "secret")
		if row["secret"] != "***" {
			t.Errorf("secret = %v, want the mask", row["secret"])
		}
		if strings.Contains(serialised, secret) {
			t.Errorf("the listing disclosed the signing secret:\n%s", serialised)
		}
	})

	t.Run("an unsigned webhook has no secret member at all", func(t *testing.T) {
		env, _, _ := adminCredentialEnv(t, mount)
		adminSeedWebhook(t, env, `{"url":"https://hook.example"}`)
		row := adminObject(t, adminEntries(t,
			adminGet(t, env, auth.AdminWebhooksPath, http.StatusOK), "webhooks"), 0)
		// `w.secret ? '***' : undefined` (:1381), and JSON.stringify drops the
		// undefined — along with the three optional members the create route was
		// not given.
		AssertKeys(t, row, "id", "url", "events", "isActive")
	})

	t.Run("first-insertion order and the best-effort total", func(t *testing.T) {
		// WebhookStore's declared order; see the
		// admin-credential-listings-are-ordered deviation.
		env, _, _ := adminCredentialEnv(t, mount)
		for _, host := range []string{"first", "second", "third"} {
			adminSeedWebhook(t, env, `{"url":"https://`+host+`.example"}`)
		}
		body := adminGet(t, env, auth.AdminWebhooksPath, http.StatusOK)
		rows := adminEntries(t, body, "webhooks")
		if len(rows) != 3 {
			t.Fatalf("webhooks = %d entries, want 3", len(rows))
		}
		if adminObject(t, rows, 0)["url"] != "https://first.example" {
			t.Errorf("first row = %v, want the webhook added first", adminObject(t, rows, 0))
		}
		if adminTotal(t, body) != 3 {
			t.Errorf("total = %v for a short page of 3, want 3", body["total"])
		}
		if got := adminTotal(t, adminGet(t, env,
			auth.AdminWebhooksPath+"?limit=3", http.StatusOK)); got != 4 {
			t.Errorf("total = %d for a full page of 3 with limit=3, want 4", got)
		}
	})
}

// testAdminWebhooksCreate is POST <admin>/api/webhooks (:1390-1410): the two
// defaults the reference applies in the route, and the mask on the way back.
func testAdminWebhooksCreate(t *testing.T, mount Mounter) {
	t.Run("url is required", func(t *testing.T) {
		env, _, _ := adminCredentialEnv(t, mount)
		for _, body := range []string{"{}", `{"url":""}`, `{"events":["*"]}`, ""} {
			AssertError(t, env.Do(env.adminRequest(http.MethodPost, auth.AdminWebhooksPath, body)),
				http.StatusBadRequest, "url is required", "")
		}
	})

	t.Run("events defaults to the wildcard and isActive to true", func(t *testing.T) {
		env, _, hooks := adminCredentialEnv(t, mount)
		id := adminSeedWebhook(t, env, `{"url":"https://hook.example"}`)
		config := adminStoredWebhook(t, hooks)
		if config.ID != id {
			t.Fatalf("stored id = %q, want %q", config.ID, id)
		}
		// `events ?? ['*']` and `isActive ?? true` (:1403-1404), applied in the
		// route because they are applied in the route there — AddWebhook stores
		// what it is given and defaults nothing.
		if len(config.Events) != 1 || config.Events[0] != "*" {
			t.Errorf("events = %v, want the wildcard", config.Events)
		}
		if config.IsActive == nil || !*config.IsActive {
			t.Errorf("isActive = %v, want an explicit true", config.IsActive)
		}
	})

	t.Run("an explicit empty events list is stored empty", func(t *testing.T) {
		// `??` is nullish and not falsy: `[]` is neither null nor undefined, so it
		// survives as a subscription to nothing.
		env, _, hooks := adminCredentialEnv(t, mount)
		adminSeedWebhook(t, env, `{"url":"https://hook.example","events":[]}`)
		if events := adminStoredWebhook(t, hooks).Events; len(events) != 0 {
			t.Errorf("events = %v, want it left empty", events)
		}
	})

	t.Run("the created webhook comes back masked", func(t *testing.T) {
		const secret = "wiretest-create-secret"
		env, _, hooks := adminCredentialEnv(t, mount)
		rec := env.Do(env.adminRequest(http.MethodPost, auth.AdminWebhooksPath,
			`{"url":"https://hook.example","secret":"`+secret+`","isActive":false}`))
		AssertStatus(t, rec, http.StatusOK)
		if strings.Contains(rec.Body.String(), secret) {
			t.Errorf("the create response echoed the secret back:\n%s", rec.Body.String())
		}
		hook, ok := Body(t, rec)["webhook"].(map[string]any)
		if !ok {
			t.Fatalf("webhook = %v, want an object", Body(t, rec)["webhook"])
		}
		if hook["secret"] != "***" {
			t.Errorf("secret = %v, want the mask", hook["secret"])
		}
		if hook["isActive"] != false {
			t.Errorf("isActive = %v, want the explicit false to survive the default", hook["isActive"])
		}

		// The store holds it in the clear, because an HMAC has to be
		// reproducible: the mask is the route's and not the store's.
		if got := adminStoredWebhook(t, hooks).Secret; got != secret {
			t.Errorf("stored secret = %q, want the value as sent", got)
		}
	})
}

// testAdminWebhooksPatch is PATCH <admin>/api/webhooks/:id (:1413-1425) and its
// secret semantics, which are the half of this PR that is easiest to get wrong.
func testAdminWebhooksPatch(t *testing.T, mount Mounter) {
	const secret = "wiretest-patch-secret"

	newEnv := func(t *testing.T) (*adminEnv, *auth.MemoryWebhookStore, string) {
		t.Helper()
		env, _, hooks := adminCredentialEnv(t, mount)
		id := adminSeedWebhook(t, env, `{"url":"https://hook.example","events":["user.created"],`+
			`"secret":"`+secret+`"}`)
		return env, hooks, id
	}

	t.Run("a patch that does not name the secret leaves it alone", func(t *testing.T) {
		env, hooks, id := newEnv(t)
		rec := env.Do(env.adminRequest(http.MethodPatch, auth.AdminWebhooksPath+"/"+id,
			`{"isActive":false}`))
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		if strings.Contains(rec.Body.String(), secret) {
			t.Error("the patch response disclosed the secret")
		}
		config := adminStoredWebhook(t, hooks)
		if config.Secret != secret {
			t.Errorf("stored secret = %q, want it untouched by a patch that did not name it", config.Secret)
		}
		if config.IsActive == nil || *config.IsActive {
			t.Errorf("isActive = %v, want the toggle applied", config.IsActive)
		}
		if len(config.Events) != 1 || config.Events[0] != "user.created" {
			t.Errorf("events = %v, want them untouched as well", config.Events)
		}
	})

	t.Run("a patch that names the secret writes it, in the clear", func(t *testing.T) {
		env, hooks, id := newEnv(t)
		adminAssertSuccess(t, env, http.MethodPatch, auth.AdminWebhooksPath+"/"+id,
			`{"secret":"rotated-secret"}`)
		if got := adminStoredWebhook(t, hooks).Secret; got != "rotated-secret" {
			t.Errorf("stored secret = %q, want the rotated value", got)
		}
		// And the listing still shows nothing but the mask.
		row := adminObject(t, adminEntries(t,
			adminGet(t, env, auth.AdminWebhooksPath, http.StatusOK), "webhooks"), 0)
		if row["secret"] != "***" {
			t.Errorf("secret = %v, want the mask after a rotation", row["secret"])
		}
	})

	t.Run("an empty secret clears it and the webhook stops being signed", func(t *testing.T) {
		env, hooks, id := newEnv(t)
		adminAssertSuccess(t, env, http.MethodPatch, auth.AdminWebhooksPath+"/"+id, `{"secret":""}`)
		if got := adminStoredWebhook(t, hooks).Secret; got != "" {
			t.Errorf("stored secret = %q, want it cleared", got)
		}
		row := adminObject(t, adminEntries(t,
			adminGet(t, env, auth.AdminWebhooksPath, http.StatusOK), "webhooks"), 0)
		if _, ok := row["secret"]; ok {
			t.Errorf("secret = %v, want the member gone for an unsigned webhook", row["secret"])
		}
	})

	t.Run("an empty patch changes nothing and still succeeds", func(t *testing.T) {
		env, hooks, id := newEnv(t)
		adminAssertSuccess(t, env, http.MethodPatch, auth.AdminWebhooksPath+"/"+id, "{}")
		if got := adminStoredWebhook(t, hooks).Secret; got != secret {
			t.Errorf("stored secret = %q, want it untouched", got)
		}
	})

	t.Run("id in the body is not a rename", func(t *testing.T) {
		// The reference's own type is Partial<Omit<WebhookConfig, 'id'>>
		// (webhook-store.interface.ts:141) and WebhookPatch carries no ID, so a
		// body naming one changes nothing — where a store implemented as a spread
		// would have moved the row.
		env, hooks, id := newEnv(t)
		adminAssertSuccess(t, env, http.MethodPatch, auth.AdminWebhooksPath+"/"+id,
			`{"id":"somebody-elses-id","url":"https://moved.example"}`)
		config := adminStoredWebhook(t, hooks)
		if config.ID != id {
			t.Errorf("id = %q, want %q", config.ID, id)
		}
		if config.URL != "https://moved.example" {
			t.Errorf("url = %q, want the field that is in the patch applied", config.URL)
		}
	})
}

// testAdminWebhooksDelete is DELETE <admin>/api/webhooks/:id (:1428-1440): a hard
// delete with no soft counterpart, and no lookup first.
func testAdminWebhooksDelete(t *testing.T, mount Mounter) {
	env, _, hooks := adminCredentialEnv(t, mount)
	id := adminSeedWebhook(t, env, `{"url":"https://hook.example","secret":"gone-with-the-row"}`)

	adminAssertSuccess(t, env, http.MethodDelete, auth.AdminWebhooksPath+"/"+id, "")
	if configs := adminStoredWebhooks(t, hooks); len(configs) != 0 {
		t.Errorf("stored = %v, want the row gone", configs)
	}

	// A second delete of the same id is still a success: nothing is looked up, and
	// RemoveWebhook reads an unknown id as a no-op.
	adminAssertSuccess(t, env, http.MethodDelete, auth.AdminWebhooksPath+"/"+id, "")
}
