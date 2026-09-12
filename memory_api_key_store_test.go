package auth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// The ordering tests below are the executable half of APIKeyAdminStore's
// ordering paragraph. That comment declares an order normative for this package
// — CreatedAt descending, ID ascending — and downstream stores register their
// own as deviations against it, so it has to be asserted somewhere rather than
// merely written down.

var memAPIKeyBase = time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)

// memAPIKeyRecordAt builds an active record stamped at base + offset seconds.
func memAPIKeyRecordAt(id, prefix string, offsetSeconds int) APIKeyRecord {
	return APIKeyRecord{
		ID:        id,
		Prefix:    prefix,
		Name:      id,
		IsActive:  true,
		CreatedAt: memAPIKeyBase.Add(time.Duration(offsetSeconds) * time.Second),
	}
}

func memAPIKeyIDs(records []APIKeyRecord) string {
	out := make([]string, 0, len(records))
	for _, record := range records {
		out = append(out, record.ID)
	}
	return strings.Join(out, ",")
}

func TestMemoryAPIKeyStore_SaveAndFindByPrefix(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	ctx := context.Background()
	if err := store.Save(ctx, memAPIKeyRecordAt("key_a", "ak_aaaaaaaa", 0)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	found, err := store.FindByPrefix(ctx, "ak_aaaaaaaa")
	if err != nil {
		t.Fatalf("FindByPrefix: %v", err)
	}
	if found.ID != "key_a" {
		t.Fatalf("unexpected record: %s", found.ID)
	}
	if !found.CreatedAt.Equal(memAPIKeyBase) {
		t.Fatalf("CreatedAt did not round-trip: %v", found.CreatedAt)
	}
}

func TestMemoryAPIKeyStore_FindByPrefix_Unknown(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	_, err := store.FindByPrefix(context.Background(), "ak_nothing")
	if !errors.Is(err, ErrAPIKeyNotFound) {
		t.Fatalf("expected ErrAPIKeyNotFound, got %v", err)
	}
}

// FindByPrefix is documented active-only — "Only return records where
// `isActive = true`" (api-key-store.interface.ts:46) — so a revoked key is
// absent here even though the record itself is kept.
func TestMemoryAPIKeyStore_FindByPrefix_SkipsRevoked(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	ctx := context.Background()
	_ = store.Save(ctx, memAPIKeyRecordAt("key_a", "ak_aaaaaaaa", 0))
	if err := store.Revoke(ctx, "key_a"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := store.FindByPrefix(ctx, "ak_aaaaaaaa"); !errors.Is(err, ErrAPIKeyNotFound) {
		t.Fatalf("revoked key should not resolve by prefix, got %v", err)
	}
}

// The other half of the same rule: revocation must not make a key unmanageable,
// because the admin screens address it by id afterwards.
func TestMemoryAPIKeyStore_FindByID_ReturnsRevoked(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	ctx := context.Background()
	_ = store.Save(ctx, memAPIKeyRecordAt("key_a", "ak_aaaaaaaa", 0))
	_ = store.Revoke(ctx, "key_a")
	found, err := store.FindByID(ctx, "key_a")
	if err != nil {
		t.Fatalf("FindByID after revoke: %v", err)
	}
	if found.IsActive {
		t.Fatal("revoked key should come back inactive, not absent")
	}
}

func TestMemoryAPIKeyStore_FindByID_Unknown(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	_, err := store.FindByID(context.Background(), "key_missing")
	if !errors.Is(err, ErrAPIKeyNotFound) {
		t.Fatalf("expected ErrAPIKeyNotFound, got %v", err)
	}
}

// An unknown id is a no-op and not an error, because the reference's revoke
// route awaits the call and answers 200 with no lookup of its own
// (admin.router.ts:1337-1338).
func TestMemoryAPIKeyStore_Revoke_UnknownIDIsNoOp(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	if err := store.Revoke(context.Background(), "key_missing"); err != nil {
		t.Fatalf("revoking an unknown id should succeed, got %v", err)
	}
}

func TestMemoryAPIKeyStore_UpdateLastUsed(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	ctx := context.Background()
	_ = store.Save(ctx, memAPIKeyRecordAt("key_a", "ak_aaaaaaaa", 0))
	when := memAPIKeyBase.Add(time.Hour)
	if err := store.UpdateLastUsed(ctx, "key_a", when); err != nil {
		t.Fatalf("UpdateLastUsed: %v", err)
	}
	found, _ := store.FindByID(ctx, "key_a")
	if found.LastUsedAt == nil || !found.LastUsedAt.Equal(when) {
		t.Fatalf("LastUsedAt not stamped: %v", found.LastUsedAt)
	}
}

func TestMemoryAPIKeyStore_UpdateLastUsed_UnknownIDIsNoOp(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	if err := store.UpdateLastUsed(context.Background(), "key_missing", time.Now()); err != nil {
		t.Fatalf("stamping an unknown id should succeed, got %v", err)
	}
}

func TestMemoryAPIKeyStore_Delete(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	ctx := context.Background()
	_ = store.Save(ctx, memAPIKeyRecordAt("key_a", "ak_aaaaaaaa", 0))
	if err := store.Delete(ctx, "key_a"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.FindByID(ctx, "key_a"); !errors.Is(err, ErrAPIKeyNotFound) {
		t.Fatalf("deleted key should be gone from the id index, got %v", err)
	}
	if _, err := store.FindByPrefix(ctx, "ak_aaaaaaaa"); !errors.Is(err, ErrAPIKeyNotFound) {
		t.Fatalf("deleted key should be gone from the prefix index, got %v", err)
	}
}

func TestMemoryAPIKeyStore_Delete_UnknownIDIsNoOp(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	if err := store.Delete(context.Background(), "key_missing"); err != nil {
		t.Fatalf("deleting an unknown id should succeed, got %v", err)
	}
}

// A prefix collision is astronomically unlikely and the store still must not
// corrupt itself on one: deleting the record that lost the index entry leaves
// the record that holds it resolvable.
func TestMemoryAPIKeyStore_Delete_LeavesAForeignPrefixIndexAlone(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	ctx := context.Background()
	_ = store.Save(ctx, memAPIKeyRecordAt("key_a", "ak_shared00", 0))
	_ = store.Save(ctx, memAPIKeyRecordAt("key_b", "ak_shared00", 1))
	if err := store.Delete(ctx, "key_a"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	found, err := store.FindByPrefix(ctx, "ak_shared00")
	if err != nil {
		t.Fatalf("the surviving key should still resolve: %v", err)
	}
	if found.ID != "key_b" {
		t.Fatalf("unexpected survivor: %s", found.ID)
	}
}

// Re-saving a record under a new prefix must not leave the old prefix pointing
// at it.
func TestMemoryAPIKeyStore_Save_DropsAStalePrefixIndex(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	ctx := context.Background()
	_ = store.Save(ctx, memAPIKeyRecordAt("key_a", "ak_old00000", 0))
	_ = store.Save(ctx, memAPIKeyRecordAt("key_a", "ak_new00000", 0))
	if _, err := store.FindByPrefix(ctx, "ak_old00000"); !errors.Is(err, ErrAPIKeyNotFound) {
		t.Fatalf("the old prefix should stop resolving, got %v", err)
	}
	if _, err := store.FindByPrefix(ctx, "ak_new00000"); err != nil {
		t.Fatalf("the new prefix should resolve: %v", err)
	}
}

func TestMemoryAPIKeyStore_ListAll_OrdersNewestFirst(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	ctx := context.Background()
	_ = store.Save(ctx, memAPIKeyRecordAt("key_middle", "ak_mmmmmmmm", 10))
	_ = store.Save(ctx, memAPIKeyRecordAt("key_oldest", "ak_oooooooo", 0))
	_ = store.Save(ctx, memAPIKeyRecordAt("key_newest", "ak_nnnnnnnn", 20))
	records, err := store.ListAll(ctx, 10, 0)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if got := memAPIKeyIDs(records); got != "key_newest,key_middle,key_oldest" {
		t.Fatalf("unexpected order: %s", got)
	}
}

// The tiebreak is the load-bearing half of the order: without it a page of keys
// sharing an instant is a partial order, and limit/offset paging over one
// repeats and drops rows.
func TestMemoryAPIKeyStore_ListAll_BreaksTiesByIDAscending(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	ctx := context.Background()
	_ = store.Save(ctx, memAPIKeyRecordAt("key_c", "ak_cccccccc", 0))
	_ = store.Save(ctx, memAPIKeyRecordAt("key_a", "ak_aaaaaaaa", 0))
	_ = store.Save(ctx, memAPIKeyRecordAt("key_b", "ak_bbbbbbbb", 0))
	for i := 0; i < 8; i++ {
		records, err := store.ListAll(ctx, 10, 0)
		if err != nil {
			t.Fatalf("ListAll: %v", err)
		}
		if got := memAPIKeyIDs(records); got != "key_a,key_b,key_c" {
			t.Fatalf("order is not deterministic across calls: %s", got)
		}
	}
}

// A record with no CreatedAt sorts after every record that has one, rather than
// landing at the top because the zero time is the smallest.
func TestMemoryAPIKeyStore_ListAll_ZeroCreatedAtSortsLast(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	ctx := context.Background()
	_ = store.Save(ctx, APIKeyRecord{ID: "key_undated", Prefix: "ak_uuuuuuuu", IsActive: true})
	_ = store.Save(ctx, memAPIKeyRecordAt("key_dated", "ak_dddddddd", 0))
	records, _ := store.ListAll(ctx, 10, 0)
	if got := memAPIKeyIDs(records); got != "key_dated,key_undated" {
		t.Fatalf("unexpected order: %s", got)
	}
}

func TestMemoryAPIKeyStore_ListAll_Pages(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		id := string(rune('a' + i))
		_ = store.Save(ctx, memAPIKeyRecordAt("key_"+id, "ak_"+strings.Repeat(id, 8), i))
	}
	first, _ := store.ListAll(ctx, 2, 0)
	if got := memAPIKeyIDs(first); got != "key_e,key_d" {
		t.Fatalf("unexpected first page: %s", got)
	}
	second, _ := store.ListAll(ctx, 2, 2)
	if got := memAPIKeyIDs(second); got != "key_c,key_b" {
		t.Fatalf("unexpected second page: %s", got)
	}
	// A short page is how the reference's listing learns it reached the end
	// (admin.router.ts:1288), so it has to be short only for that reason.
	last, _ := store.ListAll(ctx, 2, 4)
	if got := memAPIKeyIDs(last); got != "key_a" {
		t.Fatalf("unexpected last page: %s", got)
	}
}

func TestMemoryAPIKeyStore_ListAll_OffsetPastEnd(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	ctx := context.Background()
	_ = store.Save(ctx, memAPIKeyRecordAt("key_a", "ak_aaaaaaaa", 0))
	records, err := store.ListAll(ctx, 10, 50)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected an empty page, got %d records", len(records))
	}
}

// A zero limit returns nothing, not everything — the one reading of it that
// keeps "a short page means the end" true.
func TestMemoryAPIKeyStore_ListAll_ZeroLimitReturnsNothing(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	ctx := context.Background()
	_ = store.Save(ctx, memAPIKeyRecordAt("key_a", "ak_aaaaaaaa", 0))
	records, _ := store.ListAll(ctx, 0, 0)
	if len(records) != 0 {
		t.Fatalf("expected no records, got %d", len(records))
	}
}

func TestMemoryAPIKeyStore_ListAll_NegativeLimitAndOffsetReadAsZero(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	ctx := context.Background()
	_ = store.Save(ctx, memAPIKeyRecordAt("key_a", "ak_aaaaaaaa", 0))
	records, err := store.ListAll(ctx, -1, -1)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("a negative limit reads as zero, so expected no records, got %d", len(records))
	}
}

// The admin listing projects isActive and shows revoked keys, so the listing
// must not filter them the way FindByPrefix does.
func TestMemoryAPIKeyStore_ListAll_IncludesRevoked(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	ctx := context.Background()
	_ = store.Save(ctx, memAPIKeyRecordAt("key_a", "ak_aaaaaaaa", 0))
	_ = store.Revoke(ctx, "key_a")
	records, _ := store.ListAll(ctx, 10, 0)
	if len(records) != 1 || records[0].IsActive {
		t.Fatalf("revoked key should still be listed, got %+v", records)
	}
}

func TestMemoryAPIKeyStore_ListByServiceID(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	ctx := context.Background()
	mine := memAPIKeyRecordAt("key_a", "ak_aaaaaaaa", 0)
	mine.ServiceID = "billing"
	newer := memAPIKeyRecordAt("key_b", "ak_bbbbbbbb", 5)
	newer.ServiceID = "billing"
	theirs := memAPIKeyRecordAt("key_c", "ak_cccccccc", 10)
	theirs.ServiceID = "search"
	_ = store.Save(ctx, mine)
	_ = store.Save(ctx, newer)
	_ = store.Save(ctx, theirs)
	records, err := store.ListByServiceID(ctx, "billing")
	if err != nil {
		t.Fatalf("ListByServiceID: %v", err)
	}
	if got := memAPIKeyIDs(records); got != "key_b,key_a" {
		t.Fatalf("unexpected result: %s", got)
	}
}

// The reference stores an absent serviceId as null (api-key.service.ts:59) and
// this port has no null, so the empty identity is a real one and owns the keys
// that were issued without one.
func TestMemoryAPIKeyStore_ListByServiceID_EmptyMatchesUnattachedKeys(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	ctx := context.Background()
	_ = store.Save(ctx, memAPIKeyRecordAt("key_a", "ak_aaaaaaaa", 0))
	attached := memAPIKeyRecordAt("key_b", "ak_bbbbbbbb", 1)
	attached.ServiceID = "billing"
	_ = store.Save(ctx, attached)
	records, _ := store.ListByServiceID(ctx, "")
	if got := memAPIKeyIDs(records); got != "key_a" {
		t.Fatalf("unexpected result: %s", got)
	}
}

func TestMemoryAPIKeyStore_ListByServiceID_NoMatches(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	ctx := context.Background()
	_ = store.Save(ctx, memAPIKeyRecordAt("key_a", "ak_aaaaaaaa", 0))
	records, err := store.ListByServiceID(ctx, "nobody")
	if err != nil {
		t.Fatalf("ListByServiceID: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected no records, got %d", len(records))
	}
}

func TestMemoryAPIKeyStore_LogUsageAndReadBack(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	ctx := context.Background()
	entries := []APIKeyAuditEntry{
		{KeyID: "key_a", Timestamp: memAPIKeyBase, IP: "10.0.0.1", Success: true},
		{KeyID: "<unknown>", Timestamp: memAPIKeyBase.Add(time.Second), Success: false, FailureReason: "INVALID_KEY"},
	}
	for _, entry := range entries {
		if err := store.LogUsage(ctx, entry); err != nil {
			t.Fatalf("LogUsage: %v", err)
		}
	}
	got := store.Usage()
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	if got[0].KeyID != "key_a" || !got[0].Success {
		t.Fatalf("unexpected first entry: %+v", got[0])
	}
	if got[1].KeyID != "<unknown>" || got[1].FailureReason != "INVALID_KEY" {
		t.Fatalf("unexpected second entry: %+v", got[1])
	}
}

func TestMemoryAPIKeyStore_Usage_ReturnsACopy(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	_ = store.LogUsage(context.Background(), APIKeyAuditEntry{KeyID: "key_a"})
	got := store.Usage()
	got[0].KeyID = "tampered"
	if store.Usage()[0].KeyID != "key_a" {
		t.Fatal("Usage handed out the store's own slice")
	}
}

// The copy-in half. A caller that keeps hold of the slices it passed to Save
// must not be able to edit the stored record through them.
func TestMemoryAPIKeyStore_Save_CopiesTheRecord(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	ctx := context.Background()
	expiresAt := memAPIKeyBase.Add(time.Hour)
	wantExpiresAt := expiresAt
	record := memAPIKeyRecordAt("key_a", "ak_aaaaaaaa", 0)
	record.Scopes = []string{"tools:read"}
	record.AllowedIPs = []string{"10.0.0.0/8"}
	record.ExpiresAt = &expiresAt
	_ = store.Save(ctx, record)

	record.Scopes[0] = "tools:write"
	record.AllowedIPs[0] = "0.0.0.0/0"
	*record.ExpiresAt = memAPIKeyBase.Add(100 * time.Hour)

	found, _ := store.FindByID(ctx, "key_a")
	if found.Scopes[0] != "tools:read" {
		t.Fatalf("scopes were mutated through the caller's slice: %v", found.Scopes)
	}
	if found.AllowedIPs[0] != "10.0.0.0/8" {
		t.Fatalf("allowed IPs were mutated through the caller's slice: %v", found.AllowedIPs)
	}
	if !found.ExpiresAt.Equal(wantExpiresAt) {
		t.Fatalf("expiry was mutated through the caller's pointer: %v", found.ExpiresAt)
	}
}

// The copy-out half.
func TestMemoryAPIKeyStore_Find_CopiesTheRecord(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	ctx := context.Background()
	record := memAPIKeyRecordAt("key_a", "ak_aaaaaaaa", 0)
	record.Scopes = []string{"tools:read"}
	_ = store.Save(ctx, record)

	first, _ := store.FindByID(ctx, "key_a")
	first.Scopes[0] = "tools:write"

	second, _ := store.FindByID(ctx, "key_a")
	if second.Scopes[0] != "tools:read" {
		t.Fatalf("a returned record aliased the stored one: %v", second.Scopes)
	}
}

// A nil scope list stays nil. Create produces one for a key issued with no
// scopes, and a store that silently turned it into an empty slice would be
// changing a value the admin listing projects.
func TestMemoryAPIKeyStore_NilSlicesRoundTripAsNil(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	ctx := context.Background()
	_ = store.Save(ctx, memAPIKeyRecordAt("key_a", "ak_aaaaaaaa", 0))
	found, _ := store.FindByID(ctx, "key_a")
	if found.Scopes != nil {
		t.Fatalf("nil scopes became %v", found.Scopes)
	}
	if found.AllowedIPs != nil {
		t.Fatalf("nil allowed IPs became %v", found.AllowedIPs)
	}
}

// End to end against the service, which is the only combination that proves the
// store's prefix index and the service's prefix extraction agree.
func TestMemoryAPIKeyStore_WithAPIKeyService(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	svc := NewAPIKeyService(testBcryptCost)
	ctx := context.Background()
	rawKey, record, err := svc.Create(ctx, store, "deploy", "ci", []string{"tools:read"}, nil, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	verified, err := svc.Verify(ctx, store, rawKey, "", []string{"tools:read"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.ID != record.ID {
		t.Fatalf("unexpected record: %s", verified.ID)
	}
	// Verify stamps the record through UpdateLastUsed and discards the error, so
	// the only way to see that it landed is to read the store back.
	stored, err := store.FindByID(ctx, record.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if stored.LastUsedAt == nil {
		t.Fatal("a successful Verify should have stamped LastUsedAt")
	}
	if stored.CreatedAt.IsZero() {
		t.Fatal("Create should have stamped CreatedAt")
	}
	if err := store.Revoke(ctx, record.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := svc.Verify(ctx, store, rawKey, "", nil); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("a revoked key should not verify, got %v", err)
	}
}

// -race has nothing to catch unless the goroutines actually overlap on the same
// records, so this writes and reads the same small set from every direction.
func TestMemoryAPIKeyStore_ConcurrentAccess(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		id := string(rune('a' + i))
		_ = store.Save(ctx, memAPIKeyRecordAt("key_"+id, "ak_"+strings.Repeat(id, 8), i))
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := string(rune('a' + i%4))
			_ = store.Save(ctx, memAPIKeyRecordAt("key_"+id, "ak_"+strings.Repeat(id, 8), i))
			_, _ = store.FindByPrefix(ctx, "ak_"+strings.Repeat(id, 8))
			_, _ = store.FindByID(ctx, "key_"+id)
			_, _ = store.ListAll(ctx, 10, 0)
			_, _ = store.ListByServiceID(ctx, "")
			_ = store.UpdateLastUsed(ctx, "key_"+id, memAPIKeyBase)
			_ = store.LogUsage(ctx, APIKeyAuditEntry{KeyID: "key_" + id})
			_ = store.Usage()
			_ = store.Revoke(ctx, "key_"+id)
		}(i)
	}
	wg.Wait()
}
