package auth

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
)

var _ SettingsStore = (*MemorySettingsStore)(nil)

func intPtr(i int) *int { return &i }

// settled is a fully populated AuthSettings, the "current" side of every merge
// case below. Every field is set and distinguishable, so a merge that keeps one
// by accident and a merge that keeps it on purpose are told apart.
func settled() AuthSettings {
	return AuthSettings{
		RequireEmailVerification:             boolPtr(true),
		EmailVerificationMode:                strPtr(EmailVerificationModeStrict),
		LazyEmailVerificationGracePeriodDays: intPtr(7),
		Require2FA:                           boolPtr(true),
		EnabledWebhookActions:                []string{"user.create"},
		UI: &UISettings{
			PrimaryColor: strPtr("#4a90d9"),
			SiteName:     strPtr("Example"),
		},
	}
}

// A store nobody has written to answers the reference empty object
// (settings-store.interface.ts:31-32), which in JSON has to be {} and not a
// document full of nulls — the omitempty tags are what make that true, and a
// client reading the settings back is entitled to the reference shape.
func TestMemorySettingsStoreStartsEmpty(t *testing.T) {
	got, err := NewMemorySettingsStore().GetSettings(context.Background())
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if !reflect.DeepEqual(got, AuthSettings{}) {
		t.Errorf("GetSettings = %+v, want the zero AuthSettings", got)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != "{}" {
		t.Errorf("encoded = %s, want {}", encoded)
	}
}

// The JSON names are the reference's (settings-store.interface.ts:45-92). They
// are what a stored document is written and read back as, so a rename is a wire
// break for every admin client and for any node-auth deployment sharing the
// store.
//
// The order is this package's own: the reference side is a TypeScript interface,
// and JSON.stringify emits the keys of the stored object in its insertion order,
// not the interface's declaration order. Pinning it here costs nothing and
// catches an accidental reordering of the struct — which, with MarshalJSON
// encoding through a second struct, would otherwise be a silent divergence
// between the two.
func TestAuthSettingsJSONNames(t *testing.T) {
	encoded, err := json.Marshal(settled())
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"requireEmailVerification":true,"emailVerificationMode":"strict",` +
		`"lazyEmailVerificationGracePeriodDays":7,"require2FA":true,` +
		`"enabledWebhookActions":["user.create"],` +
		`"ui":{"primaryColor":"#4a90d9","siteName":"Example"}}`
	if string(encoded) != want {
		t.Errorf("encoded = %s,\nwant           %s", encoded, want)
	}
}

// The cleared list has to survive an encoder. nil and empty are different
// values to MergeSettings — nil keeps the stored list, empty replaces it with
// nothing, which is how an administrator switches every inbound-webhook action
// off — and a store that persists AuthSettings as JSON is where that difference
// is most easily lost: omitempty on a []string drops the empty slice too, so the
// key would vanish, decode back as nil, and the next merge would put the old
// list back. AuthSettings.MarshalJSON is what stops that, and this is the test
// that would fail without it.
func TestClearedEnabledWebhookActionsSurvivesJSON(t *testing.T) {
	cleared := AuthSettings{EnabledWebhookActions: []string{}}

	encoded, err := json.Marshal(cleared)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"enabledWebhookActions":[]}` {
		t.Fatalf("encoded = %s, want {\"enabledWebhookActions\":[]}", encoded)
	}

	var decoded AuthSettings
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.EnabledWebhookActions == nil {
		t.Fatal("decoded enabledWebhookActions is nil: the cleared list came back as absent")
	}
	if len(decoded.EnabledWebhookActions) != 0 {
		t.Fatalf("decoded enabledWebhookActions = %v, want empty", decoded.EnabledWebhookActions)
	}

	// And the decoded value still clears, rather than keeping what is stored.
	merged := MergeSettings(settled(), decoded)
	if merged.EnabledWebhookActions == nil || len(merged.EnabledWebhookActions) != 0 {
		t.Errorf("merged enabledWebhookActions = %v, want the list cleared", merged.EnabledWebhookActions)
	}

	// A nil list is still absent, which is the other half of the distinction.
	absent, err := json.Marshal(AuthSettings{})
	if err != nil {
		t.Fatal(err)
	}
	if string(absent) != "{}" {
		t.Errorf("encoded = %s, want {}", absent)
	}
}

// The merge rule, field by field: the reference's shallow spread
// merged = {...current, ...settings} (settings-store.interface.ts:20-24,
// :36-38). A field the patch does not carry is kept; a field it carries
// replaces. Each case patches exactly one field so that a merge which
// overreached shows up as a second field changing.
func TestMergeSettingsAppliesOneFieldAtATime(t *testing.T) {
	cases := []struct {
		name  string
		patch AuthSettings
		want  func(AuthSettings) AuthSettings
	}{
		{
			name:  "an empty patch keeps everything",
			patch: AuthSettings{},
			want:  func(s AuthSettings) AuthSettings { return s },
		},
		{
			name:  "requireEmailVerification replaces",
			patch: AuthSettings{RequireEmailVerification: boolPtr(false)},
			want: func(s AuthSettings) AuthSettings {
				s.RequireEmailVerification = boolPtr(false)
				return s
			},
		},
		{
			name:  "emailVerificationMode replaces",
			patch: AuthSettings{EmailVerificationMode: strPtr(EmailVerificationModeLazy)},
			want: func(s AuthSettings) AuthSettings {
				s.EmailVerificationMode = strPtr(EmailVerificationModeLazy)
				return s
			},
		},
		{
			name:  "lazyEmailVerificationGracePeriodDays replaces",
			patch: AuthSettings{LazyEmailVerificationGracePeriodDays: intPtr(30)},
			want: func(s AuthSettings) AuthSettings {
				s.LazyEmailVerificationGracePeriodDays = intPtr(30)
				return s
			},
		},
		{
			name:  "require2FA replaces",
			patch: AuthSettings{Require2FA: boolPtr(false)},
			want: func(s AuthSettings) AuthSettings {
				s.Require2FA = boolPtr(false)
				return s
			},
		},
		{
			name:  "enabledWebhookActions replaces",
			patch: AuthSettings{EnabledWebhookActions: []string{"user.delete", "user.update"}},
			want: func(s AuthSettings) AuthSettings {
				s.EnabledWebhookActions = []string{"user.delete", "user.update"}
				return s
			},
		},
		{
			// A JSON body of {"enabledWebhookActions": []} decodes to a non-nil
			// empty slice, which is a value and therefore replaces: it is how an
			// administrator switches every action off. Only nil keeps.
			name:  "an empty enabledWebhookActions clears the list",
			patch: AuthSettings{EnabledWebhookActions: []string{}},
			want: func(s AuthSettings) AuthSettings {
				s.EnabledWebhookActions = []string{}
				return s
			},
		},
		{
			// The shallow half of the shallow merge. ui is one key of the
			// spread, so a patch carrying it replaces the stored block whole and
			// the siteName set above is gone. The reference relies on exactly
			// this: its admin PATCH route merges the ui sub-object itself before
			// writing it back (admin.router.ts:979-981).
			name:  "ui replaces the whole block rather than merging into it",
			patch: AuthSettings{UI: &UISettings{PrimaryColor: strPtr("#000000")}},
			want: func(s AuthSettings) AuthSettings {
				s.UI = &UISettings{PrimaryColor: strPtr("#000000")}
				return s
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := MergeSettings(settled(), tc.patch)
			if want := tc.want(settled()); !reflect.DeepEqual(got, want) {
				t.Errorf("MergeSettings = %s,\nwant                %s", mustJSON(t, got), mustJSON(t, want))
			}
		})
	}
}

// Merging onto nothing is the first write to a fresh store: the patch is the
// whole of the result, and no field the patch omits appears.
func TestMergeSettingsOntoAnEmptyValue(t *testing.T) {
	got := MergeSettings(AuthSettings{}, AuthSettings{Require2FA: boolPtr(true)})
	want := AuthSettings{Require2FA: boolPtr(true)}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("MergeSettings = %s, want %s", mustJSON(t, got), mustJSON(t, want))
	}
}

// Nothing crosses the store boundary by reference. A caller that mutates what
// it was handed, or the patch it sent, must not reach the stored value — the
// stored settings are read by a route that refuses to disable a second factor,
// so an alias is a way to flip that from outside.
func TestMemorySettingsStoreCopiesInAndOut(t *testing.T) {
	ctx := context.Background()
	store := NewMemorySettingsStore()

	patch := settled()
	stored, err := store.UpdateSettings(ctx, patch)
	if err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}

	// Mutating the patch after the write.
	*patch.Require2FA = false
	patch.EnabledWebhookActions[0] = "mutated"
	*patch.UI.PrimaryColor = "#ffffff"
	// Mutating what the write returned.
	*stored.Require2FA = false
	stored.EnabledWebhookActions[0] = "mutated"
	*stored.UI.SiteName = "mutated"

	got, err := store.GetSettings(ctx)
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if !reflect.DeepEqual(got, settled()) {
		t.Errorf("stored settings = %s, want %s", mustJSON(t, got), mustJSON(t, settled()))
	}

	// And the read is a copy too.
	*got.Require2FA = false
	again, err := store.GetSettings(ctx)
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if again.Require2FA == nil || !*again.Require2FA {
		t.Error("mutating a read reached the store")
	}
}

// Concurrent readers and writers. The race detector is the main instrument here
// — an unsynchronised map or a copy taken outside the lock shows up there and
// nowhere else — but the assertions are real ones rather than decoration: half
// the writers write require2FA true and half write false, each alongside a
// siteName that names which half wrote it, and a reader must see one writer's
// whole value and never a mixture of the two.
func TestMemorySettingsStoreIsConcurrencySafe(t *testing.T) {
	ctx := context.Background()
	store := NewMemorySettingsStore()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		required := i%2 == 0
		siteName := "off"
		if required {
			siteName = "on"
		}

		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if _, err := store.UpdateSettings(ctx, AuthSettings{
					Require2FA:            boolPtr(required),
					EnabledWebhookActions: []string{"user.create"},
					UI:                    &UISettings{SiteName: strPtr(siteName)},
				}); err != nil {
					t.Errorf("UpdateSettings: %v", err)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				got, err := store.GetSettings(ctx)
				if err != nil {
					t.Errorf("GetSettings: %v", err)
					return
				}
				if got.Require2FA == nil {
					// Only before the first write lands.
					continue
				}
				want := "off"
				if *got.Require2FA {
					want = "on"
				}
				siteName := "<absent>"
				if got.UI != nil && got.UI.SiteName != nil {
					siteName = *got.UI.SiteName
				}
				if siteName != want {
					t.Errorf("read require2FA=%v with ui.siteName=%q, want %q: "+
						"the two halves of one writer's value came apart",
						*got.Require2FA, siteName, want)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// errSettingsStore is a SettingsStore that only fails, for the fail-closed case.
type errSettingsStore struct{ err error }

func (s errSettingsStore) GetSettings(context.Context) (AuthSettings, error) {
	return AuthSettings{}, s.err
}

func (s errSettingsStore) UpdateSettings(context.Context, AuthSettings) (AuthSettings, error) {
	return AuthSettings{}, s.err
}

// TwoFactorPolicy is Config.Require2FA OR the stored require2FA, and the store
// term is the reference's (auth.router.ts:890-896). A store that cannot answer
// is an error, not a false: the route above it answers 500 rather than letting
// the factor be turned off.
func TestTwoFactorPolicy(t *testing.T) {
	errStore := errors.New("settings unavailable")

	cases := []struct {
		name    string
		opts    []Option
		want    bool
		wantErr bool
	}{
		{
			name: "no config term and no store",
			want: false,
		},
		{
			name: "the config term alone",
			opts: []Option{WithRequire2FA(true)},
			want: true,
		},
		{
			name: "a store holding nothing",
			opts: []Option{WithSettingsStore(NewMemorySettingsStore())},
			want: false,
		},
		{
			name: "a store holding require2FA false",
			opts: []Option{WithSettingsStore(seededSettings(t, AuthSettings{Require2FA: boolPtr(false)}))},
			want: false,
		},
		{
			name: "the store term alone",
			opts: []Option{WithSettingsStore(seededSettings(t, AuthSettings{Require2FA: boolPtr(true)}))},
			want: true,
		},
		{
			// Other settings in the store do not make a policy.
			name: "a store holding only the email-verification settings",
			opts: []Option{WithSettingsStore(seededSettings(t, AuthSettings{
				RequireEmailVerification: boolPtr(true),
				EmailVerificationMode:    strPtr(EmailVerificationModeStrict),
			}))},
			want: false,
		},
		{
			name:    "a store that fails",
			opts:    []Option{WithSettingsStore(errSettingsStore{err: errStore})},
			wantErr: true,
		},
		{
			// The config term short-circuits, so a broken store cannot turn a
			// deployment that already requires the factor into a 500.
			name: "the config term short-circuits a failing store",
			opts: []Option{WithRequire2FA(true), WithSettingsStore(errSettingsStore{err: errStore})},
			want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := newTestAuth(tc.opts...)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			got, err := a.TwoFactorPolicy(context.Background())
			switch {
			case tc.wantErr && !errors.Is(err, errStore):
				t.Fatalf("TwoFactorPolicy error = %v, want %v", err, errStore)
			case !tc.wantErr && err != nil:
				t.Fatalf("TwoFactorPolicy: %v", err)
			}
			if got != tc.want {
				t.Errorf("TwoFactorPolicy = %v, want %v", got, tc.want)
			}
		})
	}
}

// A nil store is refused at construction, as every other With*Store is.
func TestWithSettingsStoreRefusesNil(t *testing.T) {
	if _, err := newTestAuth(WithSettingsStore(nil)); err == nil {
		t.Fatal("WithSettingsStore(nil) built an Auth")
	}
}

func seededSettings(t *testing.T, settings AuthSettings) SettingsStore {
	t.Helper()
	store := NewMemorySettingsStore()
	if _, err := store.UpdateSettings(context.Background(), settings); err != nil {
		t.Fatalf("seeding the settings store: %v", err)
	}
	return store
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
