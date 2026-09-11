package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"
)

var _ TemplateStore = (*MemoryTemplateStore)(nil)

// A missing template starts as {id, "", "", {}} and the patch is spread on top
// (memory-template.store.ts:16-22); the JSON shape is the reference's.
func TestMemoryTemplateStoreUpsertsFromAnEmptyTemplate(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryTemplateStore()

	if _, ok, err := store.GetMailTemplate(ctx, TemplateWelcome); err != nil || ok {
		t.Fatalf("empty store: ok=%v err=%v, want a clean miss", ok, err)
	}
	got, err := store.UpdateMailTemplate(ctx, TemplateWelcome, MailTemplatePatch{BaseHTML: strPtr("<p>{{T.hi}}</p>")})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	// Encoded without encoding/json's HTML escaping, which would spell the tags
	// as <p> and hide the shape under test: the four keys, in the
	// reference's order and spelling, with the untouched bodies as "" and the
	// translations as {} rather than null.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(got); err != nil {
		t.Fatal(err)
	}
	const want = `{"id":"welcome","baseHtml":"<p>{{T.hi}}</p>","baseText":"","translations":{}}`
	if encoded := strings.TrimSpace(buf.String()); encoded != want {
		t.Errorf("stored = %s, want %s", encoded, want)
	}
	again, ok, err := store.GetMailTemplate(ctx, TemplateWelcome)
	if err != nil || !ok {
		t.Fatalf("get after update: ok=%v err=%v", ok, err)
	}
	if !reflect.DeepEqual(again, got) {
		t.Errorf("get = %+v, want what update returned %+v", again, got)
	}
}

func TestMemoryTemplateStorePatchSemantics(t *testing.T) {
	ctx := context.Background()
	seed := func(t *testing.T) *MemoryTemplateStore {
		t.Helper()
		store := NewMemoryTemplateStore()
		if _, err := store.UpdateMailTemplate(ctx, TemplateInvitation, MailTemplatePatch{
			BaseHTML: strPtr("<p>h</p>"), BaseText: strPtr("t"),
			Translations: map[string]map[string]string{"en": {"subject": "S"}, "it": {"subject": "O"}},
		}); err != nil {
			t.Fatal(err)
		}
		return store
	}
	get := func(t *testing.T, store *MemoryTemplateStore) MailTemplate {
		t.Helper()
		tpl, ok, err := store.GetMailTemplate(ctx, TemplateInvitation)
		if err != nil || !ok {
			t.Fatalf("get: ok=%v err=%v", ok, err)
		}
		return tpl
	}

	t.Run("nil fields keep the stored values", func(t *testing.T) {
		store := seed(t)
		before := get(t, store)
		if _, err := store.UpdateMailTemplate(ctx, TemplateInvitation, MailTemplatePatch{}); err != nil {
			t.Fatal(err)
		}
		if after := get(t, store); !reflect.DeepEqual(after, before) {
			t.Errorf("an empty patch changed the template: %+v -> %+v", before, after)
		}
	})

	t.Run("a pointer to the empty string clears a body", func(t *testing.T) {
		store := seed(t)
		if _, err := store.UpdateMailTemplate(ctx, TemplateInvitation, MailTemplatePatch{BaseHTML: strPtr("")}); err != nil {
			t.Fatal(err)
		}
		if got := get(t, store); got.BaseHTML != "" || got.BaseText != "t" {
			t.Errorf("bodies = %q / %q, want the HTML cleared and the text kept", got.BaseHTML, got.BaseText)
		}
	})

	// {...existing, ...template}: translations is one field of the partial, so
	// a supplied map replaces the stored one — languages it does not name are
	// gone, as they are in the reference (memory-template.store.ts:22).
	t.Run("translations replace the whole map", func(t *testing.T) {
		store := seed(t)
		if _, err := store.UpdateMailTemplate(ctx, TemplateInvitation, MailTemplatePatch{
			Translations: map[string]map[string]string{"fr": {"subject": "F"}},
		}); err != nil {
			t.Fatal(err)
		}
		want := map[string]map[string]string{"fr": {"subject": "F"}}
		if got := get(t, store); !reflect.DeepEqual(got.Translations, want) || got.BaseHTML != "<p>h</p>" {
			t.Errorf("after the patch: %+v, want translations %v and the bodies kept", got, want)
		}
	})

	t.Run("an empty translations map clears every language", func(t *testing.T) {
		store := seed(t)
		if _, err := store.UpdateMailTemplate(ctx, TemplateInvitation, MailTemplatePatch{
			Translations: map[string]map[string]string{},
		}); err != nil {
			t.Fatal(err)
		}
		if got := get(t, store); len(got.Translations) != 0 || got.Translations == nil {
			t.Errorf("translations = %v, want an empty, non-nil map", got.Translations)
		}
	})
}

// Everything crosses the store boundary as a copy, in both directions.
func TestMemoryTemplateStoreHandsOutCopies(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryTemplateStore()
	patch := map[string]map[string]string{"en": {"subject": "S"}}
	returned, err := store.UpdateMailTemplate(ctx, TemplateWelcome, MailTemplatePatch{BaseHTML: strPtr("h"), BaseText: strPtr("t"), Translations: patch})
	if err != nil {
		t.Fatal(err)
	}
	patch["en"]["subject"] = "mutated through the patch"
	returned.Translations["en"]["subject"] = "mutated through the return value"
	returned.BaseHTML = "mutated"

	fetched, _, err := store.GetMailTemplate(ctx, TemplateWelcome)
	if err != nil {
		t.Fatal(err)
	}
	if fetched.BaseHTML != "h" || fetched.Translations["en"]["subject"] != "S" {
		t.Errorf("the store was mutated from outside: %+v", fetched)
	}
	fetched.Translations["en"]["subject"] = "mutated through get"
	listed, err := store.ListMailTemplates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if listed[0].Translations["en"]["subject"] != "S" {
		t.Errorf("the store was mutated through a Get result: %+v", listed[0])
	}
	listed[0].Translations["en"]["subject"] = "mutated through list"
	if again, _, _ := store.GetMailTemplate(ctx, TemplateWelcome); again.Translations["en"]["subject"] != "S" {
		t.Errorf("the store was mutated through a List result: %+v", again)
	}

	ui, err := store.UpdateUITranslations(ctx, "login", map[string]map[string]string{"en": {"title": "Sign in"}})
	if err != nil {
		t.Fatal(err)
	}
	ui.Translations["en"]["title"] = "mutated"
	if fetched, _, _ := store.GetUITranslations(ctx, "login"); fetched.Translations["en"]["title"] != "Sign in" {
		t.Errorf("the UI translations were mutated from outside: %+v", fetched)
	}
}

// Lists come back in first-insertion order, as the reference's Map iteration
// does (memory-template.store.ts:11-13, 29-31); an update keeps the position.
func TestMemoryTemplateStoreListsInInsertionOrder(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryTemplateStore()
	ids := []string{TemplateWelcome, TemplateInvitation, TemplatePasswordReset}
	for _, id := range ids {
		if _, err := store.UpdateMailTemplate(ctx, id, MailTemplatePatch{BaseText: strPtr(id)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.UpdateMailTemplate(ctx, TemplateWelcome, MailTemplatePatch{BaseHTML: strPtr("updated")}); err != nil {
		t.Fatal(err)
	}
	listed, err := store.ListMailTemplates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, tpl := range listed {
		got = append(got, tpl.ID)
	}
	if !reflect.DeepEqual(got, ids) {
		t.Errorf("listed %v, want insertion order %v", got, ids)
	}

	pages := []string{"register", "login", "forgot-password"}
	for _, page := range pages {
		if _, err := store.UpdateUITranslations(ctx, page, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.UpdateUITranslations(ctx, "register", map[string]map[string]string{"en": {"x": "y"}}); err != nil {
		t.Fatal(err)
	}
	uis, err := store.ListUITranslations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got = got[:0]
	for _, ui := range uis {
		got = append(got, ui.Page)
	}
	if !reflect.DeepEqual(got, pages) {
		t.Errorf("listed %v, want insertion order %v", got, pages)
	}
}

// A page is set wholesale (memory-template.store.ts:33-35), never patched.
func TestMemoryTemplateStoreUITranslations(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryTemplateStore()

	if _, ok, err := store.GetUITranslations(ctx, "login"); err != nil || ok {
		t.Fatalf("empty store: ok=%v err=%v, want a clean miss", ok, err)
	}
	first := map[string]map[string]string{"en": {"title": "Sign in"}, "it": {"title": "Accedi"}}
	got, err := store.UpdateUITranslations(ctx, "login", first)
	if err != nil {
		t.Fatal(err)
	}
	if got.Page != "login" || !reflect.DeepEqual(got.Translations, first) {
		t.Errorf("stored %+v", got)
	}

	second := map[string]map[string]string{"en": {"title": "Log in"}}
	if _, err := store.UpdateUITranslations(ctx, "login", second); err != nil {
		t.Fatal(err)
	}
	fetched, ok, err := store.GetUITranslations(ctx, "login")
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if !reflect.DeepEqual(fetched.Translations, second) {
		t.Errorf("after the second set: %v, want %v (it must be gone)", fetched.Translations, second)
	}

	// nil translations are stored as the reference's empty object, never null.
	empty, err := store.UpdateUITranslations(ctx, "register", nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(empty)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"page":"register","translations":{}}` {
		t.Errorf("encoded %s", encoded)
	}
}

// The store is shared by every request; the race detector is the assertion.
func TestMemoryTemplateStoreConcurrentUse(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryTemplateStore()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if _, err := store.UpdateMailTemplate(ctx, TemplateMagicLink, MailTemplatePatch{
					BaseHTML: strPtr("<p>h</p>"), Translations: map[string]map[string]string{"en": {"subject": "S"}},
				}); err != nil {
					t.Error(err)
					return
				}
				if _, err := store.UpdateUITranslations(ctx, "login", map[string]map[string]string{"en": {"title": "T"}}); err != nil {
					t.Error(err)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if _, _, err := store.GetMailTemplate(ctx, TemplateMagicLink); err != nil {
					t.Error(err)
					return
				}
				if _, _, err := store.GetUITranslations(ctx, "login"); err != nil {
					t.Error(err)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if _, err := store.ListMailTemplates(ctx); err != nil {
					t.Error(err)
					return
				}
				if _, err := store.ListUITranslations(ctx); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
