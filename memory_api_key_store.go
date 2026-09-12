package auth

import (
	"context"
	"sort"
	"sync"
	"time"
)

// MemoryAPIKeyStore is an in-process implementation of APIKeyStore and of all
// four of its companion interfaces. It is what a deployment gets before it
// writes a real one, what the examples wire, and what the tests in this package
// authenticate against.
//
// It is correct only while every request is served by the same process. Keys
// live in maps and die with the process, so a serverless or multi-instance
// deployment that used this would issue a key on one instance and reject it on
// the next; those need a store over shared storage, which is the whole point of
// APIKeyStore being an interface.
//
// Implementing all five interfaces is deliberate, and it is what makes this type
// the executable statement of APIKeyAdminStore's ordering rule: the order that
// doc comment declares normative is asserted here, in
// memory_api_key_store_test.go, rather than left as prose for the next
// implementor to interpret. A caller that needs a store which is *missing* one
// of the optional four — to exercise the reference's `501 IApiKeyStore.listAll
// is not implemented` branch, say (admin.router.ts:1259-1262) — has to write a
// narrower type; this one answers every question.
//
// Records are copied on the way in and on the way out. APIKeyRecord carries two
// slices and two time pointers, so handing the stored value back directly would
// let a caller mutate a key's scopes or its expiry without going through Save,
// and would do it without the mutex — a data race under -race, and silent
// corruption without it.
type MemoryAPIKeyStore struct {
	mu sync.RWMutex
	// byID is the record set. Every other index points into it.
	byID map[string]APIKeyRecord
	// byPrefix maps a key prefix to the record id, because FindByPrefix is on
	// the authentication path and a scan of byID there would make every request
	// linear in the number of keys ever issued.
	byPrefix map[string]string
	// usage is the audit log LogUsage appends to. Nothing in this package writes
	// to it yet; see APIKeyAuditStore and Usage.
	usage []APIKeyAuditEntry
}

// Compile-time proof that this type satisfies the whole family. Without these
// an interface could grow a method and only the callers would break, which on a
// store nothing in this package constructs would be at some host's build rather
// than at ours.
var (
	_ APIKeyStore             = (*MemoryAPIKeyStore)(nil)
	_ APIKeyAdminStore        = (*MemoryAPIKeyStore)(nil)
	_ APIKeyServiceIndexStore = (*MemoryAPIKeyStore)(nil)
	_ APIKeyDeleteStore       = (*MemoryAPIKeyStore)(nil)
	_ APIKeyAuditStore        = (*MemoryAPIKeyStore)(nil)
)

func NewMemoryAPIKeyStore() *MemoryAPIKeyStore {
	return &MemoryAPIKeyStore{
		byID:     make(map[string]APIKeyRecord),
		byPrefix: make(map[string]string),
	}
}

// cloneAPIKeyRecord deep-copies the two slices and the two time pointers, so
// that the value crossing the store boundary shares nothing mutable with the
// value inside it. A nil slice stays nil rather than becoming empty: Create
// propagates nil through `append([]string(nil), scopes...)` when the caller
// passed no scopes, so the round trip has to preserve the distinction rather
// than quietly normalise it.
func cloneAPIKeyRecord(in APIKeyRecord) APIKeyRecord {
	out := in
	if in.Scopes != nil {
		out.Scopes = append([]string(nil), in.Scopes...)
	}
	if in.AllowedIPs != nil {
		out.AllowedIPs = append([]string(nil), in.AllowedIPs...)
	}
	if in.ExpiresAt != nil {
		expiresAt := *in.ExpiresAt
		out.ExpiresAt = &expiresAt
	}
	if in.LastUsedAt != nil {
		lastUsedAt := *in.LastUsedAt
		out.LastUsedAt = &lastUsedAt
	}
	return out
}

// sortAPIKeyRecords applies the order APIKeyAdminStore declares: newest first,
// ties broken by ID ascending.
//
// sort.Slice and not sort.SliceStable, because the comparator is already a total
// order — IDs are unique within byID, so no two records compare equal — and a
// total order makes an unstable sort deterministic. That is the property the
// doc comment promises and the reason the tiebreak exists at all.
//
// Equal uses time.Time's own comparison rather than ==, which would also compare
// monotonic clock readings and wall-clock locations and would call two records
// stamped at the same instant different.
func sortAPIKeyRecords(records []APIKeyRecord) {
	sort.Slice(records, func(i, j int) bool {
		if !records[i].CreatedAt.Equal(records[j].CreatedAt) {
			return records[i].CreatedAt.After(records[j].CreatedAt)
		}
		return records[i].ID < records[j].ID
	})
}

// Save persists the record, replacing any earlier one with the same ID.
//
// The prefix index is rewritten with it. A re-save that changes a record's
// Prefix — which Create never does, but a host restoring a backup might — drops
// the stale index entry, so the old prefix stops resolving instead of resolving
// to a record that no longer claims it.
func (s *MemoryAPIKeyStore) Save(_ context.Context, key APIKeyRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if previous, ok := s.byID[key.ID]; ok && previous.Prefix != key.Prefix {
		delete(s.byPrefix, previous.Prefix)
	}
	s.byID[key.ID] = cloneAPIKeyRecord(key)
	s.byPrefix[key.Prefix] = key.ID
	return nil
}

// FindByPrefix returns the active record with this prefix, per the interface
// contract. A revoked record is ErrAPIKeyNotFound here and still readable
// through FindByID.
func (s *MemoryAPIKeyStore) FindByPrefix(_ context.Context, prefix string) (APIKeyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byPrefix[prefix]
	if !ok {
		return APIKeyRecord{}, ErrAPIKeyNotFound
	}
	record, ok := s.byID[id]
	if !ok || !record.IsActive {
		return APIKeyRecord{}, ErrAPIKeyNotFound
	}
	return cloneAPIKeyRecord(record), nil
}

// FindByID returns the record whatever its state, which is what the admin
// screens need: a revoked or expired key has to stay openable.
func (s *MemoryAPIKeyStore) FindByID(_ context.Context, id string) (APIKeyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.byID[id]
	if !ok {
		return APIKeyRecord{}, ErrAPIKeyNotFound
	}
	return cloneAPIKeyRecord(record), nil
}

// Revoke clears IsActive and keeps the record. An unknown id is a no-op
// returning nil, not ErrAPIKeyNotFound; see APIKeyStore.Revoke for why the
// reference's route depends on that.
func (s *MemoryAPIKeyStore) Revoke(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.byID[id]
	if !ok {
		return nil
	}
	record.IsActive = false
	s.byID[id] = record
	return nil
}

// UpdateLastUsed stamps the record. An unknown id is a no-op, as on Revoke.
func (s *MemoryAPIKeyStore) UpdateLastUsed(_ context.Context, id string, when time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.byID[id]
	if !ok {
		return nil
	}
	stamped := when
	record.LastUsedAt = &stamped
	s.byID[id] = record
	return nil
}

// Delete removes the record and its prefix index entry. This is the hard delete
// the reference advises against — Revoke keeps the audit trail — and it is here
// so that a host can exercise both branches of the reference's DELETE
// /admin/api/api-keys/:id (admin.router.ts:1348-1354) against a real store.
//
// The index entry is removed only when it still points at this record: a later
// key that happened to claim the same prefix owns the entry, and deleting the
// earlier record must not unhook the later one.
func (s *MemoryAPIKeyStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.byID[id]
	if !ok {
		return nil
	}
	if indexed, ok := s.byPrefix[record.Prefix]; ok && indexed == id {
		delete(s.byPrefix, record.Prefix)
	}
	delete(s.byID, id)
	return nil
}

// ListAll returns one page in the order APIKeyAdminStore declares: CreatedAt
// descending, ID ascending.
//
// The whole set is copied and sorted on every call. That is quadratic-ish
// nonsense for a table of any size and entirely fine here: this store holds what
// one process minted since it started, and a store that needs to page a real
// table is a real store with a real index.
//
// The returned slice is capped to its length, so a caller that appends to the
// page allocates rather than writing into the rows beyond it.
func (s *MemoryAPIKeyStore) ListAll(_ context.Context, limit, offset int) ([]APIKeyRecord, error) {
	if limit < 0 {
		limit = 0
	}
	if offset < 0 {
		offset = 0
	}
	records := s.snapshot(func(APIKeyRecord) bool { return true })
	if offset >= len(records) {
		return []APIKeyRecord{}, nil
	}
	end := offset + limit
	if end > len(records) {
		end = len(records)
	}
	return records[offset:end:end], nil
}

// ListByServiceID returns every key issued to one service identity, active or
// not, in the same order. There is no paging because the reference declares
// none.
//
// The empty service identity is a real one and matches records whose ServiceID
// is empty: the reference stores `serviceId ?? null` (api-key.service.ts:59) and
// this port has no null, so "no service" and "" are one value here and a caller
// that asks for it gets the unattached keys.
func (s *MemoryAPIKeyStore) ListByServiceID(_ context.Context, serviceID string) ([]APIKeyRecord, error) {
	return s.snapshot(func(record APIKeyRecord) bool { return record.ServiceID == serviceID }), nil
}

// snapshot copies every record the predicate accepts and sorts the copy. The
// lock is dropped before the sort: the comparator touches only the copies, and
// holding a read lock across it would block Save for no reason.
func (s *MemoryAPIKeyStore) snapshot(keep func(APIKeyRecord) bool) []APIKeyRecord {
	s.mu.RLock()
	records := make([]APIKeyRecord, 0, len(s.byID))
	for _, record := range s.byID {
		if keep(record) {
			records = append(records, cloneAPIKeyRecord(record))
		}
	}
	s.mu.RUnlock()
	sortAPIKeyRecords(records)
	return records
}

// LogUsage appends an audit entry. Nothing in this package calls it yet — see
// APIKeyAuditStore — so in this release it is written only by a host that
// decided to, and read only through Usage.
func (s *MemoryAPIKeyStore) LogUsage(_ context.Context, entry APIKeyAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.usage = append(s.usage, entry)
	return nil
}

// Usage returns the audit entries LogUsage has collected, oldest first.
//
// It is on this type and on no interface. APIKeyAuditStore is a write seam — the
// reference declares `logUsage` and no reader to go with it — so there is no
// contract to put this on, and inventing one would be inventing a method the
// reference does not have. It exists because a log nothing can read is not a log,
// and because the tests have to be able to assert what was written.
//
// The slice is a copy; APIKeyAuditEntry holds nothing mutable, so a shallow one
// is enough.
func (s *MemoryAPIKeyStore) Usage() []APIKeyAuditEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]APIKeyAuditEntry(nil), s.usage...)
}
