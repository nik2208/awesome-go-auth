package auth

import (
	"context"
	"sync"
)

// This file is the template store seam: the reference's ITemplateStore
// (awesome-node-auth src/interfaces/template-store.interface.ts:13-43), through
// which a deployment overrides the built-in mail templates at run time and keeps
// UI translations, plus the in-memory implementation
// (src/stores/memory-template.store.ts).
//
// How a stored template is used is MailTemplater's business (mailer.go); this
// file only defines what is stored and how it is patched.

// MailTemplate is a stored mail template (template-store.interface.ts:1-6). The
// JSON tags are the reference's key names.
//
// BaseHTML and BaseText are the bodies, with two kinds of placeholder:
// {{T.key}} is looked up in Translations for the rendering language, and
// {{key}} is looked up in the data the mailer supplies — link, token, newEmail
// and the rest; see MailTemplater.RenderMail for the rule and the keys. A
// template is only used when both bodies are non-empty
// (mailer.service.ts:158); until then the built-in one keeps rendering.
//
// Placeholders are substituted as they are, in BaseHTML included: no HTML
// escaping, as the reference does none (mailer.service.ts:163-167). BaseHTML is
// the deployment's own markup; the values are not all its own — newEmail is
// the address a user typed, lowercased and trimmed, and an Extra entry is
// whatever the caller passed — and a stored template that shows them mails
// them verbatim, exactly as the reference's does. The built-in templates,
// rendered by html/template, escape them.
type MailTemplate struct {
	// ID is one of the six reference ids — TemplatePasswordReset and its
	// siblings — or any id of the deployment's own.
	ID       string `json:"id"`
	BaseHTML string `json:"baseHtml"`
	BaseText string `json:"baseText"`
	// Translations is lang -> key -> value. The key "subject" is the mail's
	// subject; every other key is what {{T.key}} resolves to.
	Translations map[string]map[string]string `json:"translations"`
}

// UITranslation is the stored translation set of one UI page
// (template-store.interface.ts:8-11): lang -> key -> value.
type UITranslation struct {
	Page         string                       `json:"page"`
	Translations map[string]map[string]string `json:"translations"`
}

// MailTemplatePatch is what TemplateStore.UpdateMailTemplate applies: the
// reference's Partial<MailTemplate> (template-store.interface.ts:27), where a
// field that is present replaces the stored one and a field that is absent
// leaves it alone — the shallow spread of memory-template.store.ts:22,
// {...existing, ...template}.
//
// So a nil BaseHTML or BaseText keeps the stored body, and a pointer to ""
// clears it. A nil Translations keeps every language; a non-nil one replaces
// the whole lang -> key -> value map — languages it does not name are dropped,
// as the reference drops them, because translations is one field of the
// partial and not a map the store merges into. A caller that wants to change
// one language reads the template first and sends the map back whole.
type MailTemplatePatch struct {
	BaseHTML     *string
	BaseText     *string
	Translations map[string]map[string]string
}

// TemplateStore keeps mail templates and UI translations
// (template-store.interface.ts:13-43). It is optional: without one the
// built-in templates render, exactly as the reference without a templateStore.
//
// The Get methods answer (value, false, nil) for an id or page the store does
// not hold — the reference's null — and reserve the error for the store itself
// failing. Update is an upsert in both halves: a missing id is created from an
// empty template (memory-template.store.ts:16-21) and a page is created on its
// first translations. Both Update methods return what is stored afterwards,
// which the reference's void methods leave the caller to read back.
//
// A store is wired once with WithTemplateStore (Config.Templates) and reaches
// every ready-made mailer the service calls; a MailTemplater used outside a
// service call reads its own Store field. The UI half — GetUITranslations and
// its siblings — is kept for the UI router, which is what reads it in the
// reference (ui.router.ts); nothing in this package serves it yet.
type TemplateStore interface {
	GetMailTemplate(ctx context.Context, id string) (MailTemplate, bool, error)
	ListMailTemplates(ctx context.Context) ([]MailTemplate, error)
	UpdateMailTemplate(ctx context.Context, id string, patch MailTemplatePatch) (MailTemplate, error)
	GetUITranslations(ctx context.Context, page string) (UITranslation, bool, error)
	ListUITranslations(ctx context.Context) ([]UITranslation, error)
	UpdateUITranslations(ctx context.Context, page string, translations map[string]map[string]string) (UITranslation, error)
}

// MemoryTemplateStore is the in-memory TemplateStore
// (memory-template.store.ts), safe for concurrent use. Everything handed out is
// a copy: mutating a returned template does not reach the store. Lists come
// back in first-insertion order, as the reference's Map iteration does
// (memory-template.store.ts:11-13, 29-31).
type MemoryTemplateStore struct {
	mu        sync.RWMutex
	mail      map[string]MailTemplate
	mailOrder []string
	ui        map[string]UITranslation
	uiOrder   []string
}

// NewMemoryTemplateStore returns an empty MemoryTemplateStore.
func NewMemoryTemplateStore() *MemoryTemplateStore {
	return &MemoryTemplateStore{
		mail: make(map[string]MailTemplate),
		ui:   make(map[string]UITranslation),
	}
}

func (s *MemoryTemplateStore) GetMailTemplate(_ context.Context, id string) (MailTemplate, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tpl, ok := s.mail[id]
	if !ok {
		return MailTemplate{}, false, nil
	}
	return copyMailTemplate(tpl), true, nil
}

// ListMailTemplates returns every stored template in the order the ids were
// first written.
func (s *MemoryTemplateStore) ListMailTemplates(_ context.Context) ([]MailTemplate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]MailTemplate, 0, len(s.mailOrder))
	for _, id := range s.mailOrder {
		out = append(out, copyMailTemplate(s.mail[id]))
	}
	return out, nil
}

// UpdateMailTemplate upserts: a template the store does not hold starts as
// {id, "", "", {}} (memory-template.store.ts:16-21) and the patch is spread on
// top (:22), as MailTemplatePatch describes. The stored result is returned.
func (s *MemoryTemplateStore) UpdateMailTemplate(_ context.Context, id string, patch MailTemplatePatch) (MailTemplate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.mail[id]
	if !ok {
		current = MailTemplate{ID: id, Translations: map[string]map[string]string{}}
		s.mailOrder = append(s.mailOrder, id)
	}
	if patch.BaseHTML != nil {
		current.BaseHTML = *patch.BaseHTML
	}
	if patch.BaseText != nil {
		current.BaseText = *patch.BaseText
	}
	if patch.Translations != nil {
		current.Translations = copyTranslations(patch.Translations)
	}
	s.mail[id] = current
	return copyMailTemplate(current), nil
}

func (s *MemoryTemplateStore) GetUITranslations(_ context.Context, page string) (UITranslation, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ui, ok := s.ui[page]
	if !ok {
		return UITranslation{}, false, nil
	}
	return copyUITranslation(ui), true, nil
}

// ListUITranslations returns every stored page in the order the pages were
// first written.
func (s *MemoryTemplateStore) ListUITranslations(_ context.Context) ([]UITranslation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]UITranslation, 0, len(s.uiOrder))
	for _, page := range s.uiOrder {
		out = append(out, copyUITranslation(s.ui[page]))
	}
	return out, nil
}

// UpdateUITranslations replaces the page's translations wholesale
// (memory-template.store.ts:33-35): a page is set, not patched.
func (s *MemoryTemplateStore) UpdateUITranslations(_ context.Context, page string, translations map[string]map[string]string) (UITranslation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.ui[page]; !ok {
		s.uiOrder = append(s.uiOrder, page)
	}
	ui := UITranslation{Page: page, Translations: copyTranslations(translations)}
	s.ui[page] = ui
	return copyUITranslation(ui), nil
}

func copyMailTemplate(tpl MailTemplate) MailTemplate {
	tpl.Translations = copyTranslations(tpl.Translations)
	return tpl
}

func copyUITranslation(ui UITranslation) UITranslation {
	ui.Translations = copyTranslations(ui.Translations)
	return ui
}

// copyTranslations deep-copies a lang -> key -> value map. A nil input yields
// an empty map rather than nil, so a stored value always encodes as {} — the
// reference's empty object — and never as null.
func copyTranslations(in map[string]map[string]string) map[string]map[string]string {
	out := make(map[string]map[string]string, len(in))
	for lang, values := range in {
		if values == nil {
			continue
		}
		out[lang] = copyStrings(values)
	}
	return out
}

func copyStrings(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// templateStoreKey carries Config.Templates on the context the service hands
// every sender, which is how the store configured once with WithTemplateStore
// reaches ready-made mailers the host built before the service existed. A
// MailTemplater whose Store field is nil reads it from there.
type templateStoreKey struct{}

func withTemplateStore(ctx context.Context, store TemplateStore) context.Context {
	if store == nil {
		return ctx
	}
	return context.WithValue(ctx, templateStoreKey{}, store)
}

func templateStoreFromContext(ctx context.Context) TemplateStore {
	if ctx == nil {
		return nil
	}
	store, _ := ctx.Value(templateStoreKey{}).(TemplateStore)
	return store
}
