package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"
)

// MailMessage is a single email to be sent.
type MailMessage struct {
	To      string
	Subject string
	Body    string
	IsHTML  bool
}

// MailerTransport delivers email messages.
type MailerTransport interface {
	Send(ctx context.Context, msg MailMessage) error
}

// HTTPMailerTransport sends mail via any HTTP endpoint (no SMTP needed).
type HTTPMailerTransport struct {
	EndpointURL string
	Secret      string
	client      *http.Client
}

// NewHTTPMailerTransport creates a transport that POSTs to a webhook-style HTTP endpoint.
func NewHTTPMailerTransport(endpointURL, secret string) *HTTPMailerTransport {
	return &HTTPMailerTransport{
		EndpointURL: endpointURL,
		Secret:      secret,
		client:      &http.Client{Timeout: 10 * time.Second},
	}
}

func (t *HTTPMailerTransport) Send(ctx context.Context, msg MailMessage) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.EndpointURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if t.Secret != "" {
		req.Header.Set("X-Mailer-Secret", t.Secret)
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("auth: mailer http send: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("auth: mailer http status %d", resp.StatusCode)
	}
	return nil
}

// MailTemplateData holds the common variables injected into mail templates.
type MailTemplateData struct {
	AppName  string
	UserName string
	Token    string
	URL      string
	Code     string
	Extra    map[string]any
}

// MailTemplater renders localized mail templates.
type MailTemplater struct {
	appName string
	tmpls   map[string]*template.Template
}

// NewMailTemplater creates a templater with built-in en and it templates.
func NewMailTemplater(appName string) *MailTemplater {
	m := &MailTemplater{appName: appName, tmpls: make(map[string]*template.Template)}

	// Built-in English templates
	m.addTemplate("en/reset_password", `<!DOCTYPE html><html><body>
<h2>Password Reset - {{.AppName}}</h2>
<p>Hello {{.UserName}},</p>
<p>Click the link below to reset your password. This link expires in 1 hour.</p>
<p><a href="{{.URL}}">Reset Password</a></p>
<p>If you did not request this, please ignore this email.</p>
</body></html>`)

	m.addTemplate("en/magic_link", `<!DOCTYPE html><html><body>
<h2>Magic Link Login - {{.AppName}}</h2>
<p>Hello {{.UserName}},</p>
<p>Click the link below to sign in. This link expires in 15 minutes.</p>
<p><a href="{{.URL}}">Sign In</a></p>
</body></html>`)

	m.addTemplate("en/verify_email", `<!DOCTYPE html><html><body>
<h2>Verify Your Email - {{.AppName}}</h2>
<p>Hello {{.UserName}},</p>
<p>Please verify your email address by clicking the link below.</p>
<p><a href="{{.URL}}">Verify Email</a></p>
</body></html>`)

	m.addTemplate("en/email_change", `<!DOCTYPE html><html><body>
<h2>Confirm Email Change - {{.AppName}}</h2>
<p>Hello {{.UserName}},</p>
<p>Click the link below to confirm your new email address.</p>
<p><a href="{{.URL}}">Confirm Email Change</a></p>
</body></html>`)

	// Built-in Italian templates
	m.addTemplate("it/reset_password", `<!DOCTYPE html><html><body>
<h2>Reimpostazione Password - {{.AppName}}</h2>
<p>Ciao {{.UserName}},</p>
<p>Clicca sul link sottostante per reimpostare la tua password. Il link scade tra 1 ora.</p>
<p><a href="{{.URL}}">Reimposta Password</a></p>
<p>Se non hai richiesto questo, ignora questa email.</p>
</body></html>`)

	m.addTemplate("it/magic_link", `<!DOCTYPE html><html><body>
<h2>Accesso Magic Link - {{.AppName}}</h2>
<p>Ciao {{.UserName}},</p>
<p>Clicca sul link sottostante per accedere. Il link scade tra 15 minuti.</p>
<p><a href="{{.URL}}">Accedi</a></p>
</body></html>`)

	m.addTemplate("it/verify_email", `<!DOCTYPE html><html><body>
<h2>Verifica Email - {{.AppName}}</h2>
<p>Ciao {{.UserName}},</p>
<p>Verifica il tuo indirizzo email cliccando sul link sottostante.</p>
<p><a href="{{.URL}}">Verifica Email</a></p>
</body></html>`)

	m.addTemplate("it/email_change", `<!DOCTYPE html><html><body>
<h2>Conferma Cambio Email - {{.AppName}}</h2>
<p>Ciao {{.UserName}},</p>
<p>Clicca sul link per confermare il tuo nuovo indirizzo email.</p>
<p><a href="{{.URL}}">Conferma Cambio Email</a></p>
</body></html>`)

	return m
}

func (m *MailTemplater) addTemplate(key, body string) {
	t, err := template.New(key).Parse(body)
	if err == nil {
		m.tmpls[key] = t
	}
}

// Render produces the subject and HTML body for the given locale and template name.
func (m *MailTemplater) Render(locale, name string, data MailTemplateData) (subject, body string, err error) {
	data.AppName = m.appName
	key := locale + "/" + name
	t, ok := m.tmpls[key]
	if !ok {
		// Fall back to English
		key = "en/" + name
		t, ok = m.tmpls[key]
		if !ok {
			return "", "", fmt.Errorf("auth: mail template %q not found", name)
		}
	}
	var buf strings.Builder
	if err := t.Execute(&buf, data); err != nil {
		return "", "", fmt.Errorf("auth: render mail template %q: %w", name, err)
	}

	enSubjects := map[string]string{
		"reset_password": m.appName + " - Password Reset",
		"magic_link":     m.appName + " - Magic Link Login",
		"verify_email":   m.appName + " - Verify Your Email",
		"email_change":   m.appName + " - Confirm Email Change",
	}
	itSubjects := map[string]string{
		"reset_password": m.appName + " - Reimposta Password",
		"magic_link":     m.appName + " - Magic Link Accesso",
		"verify_email":   m.appName + " - Verifica Email",
		"email_change":   m.appName + " - Conferma Cambio Email",
	}

	subjects := enSubjects
	if locale == "it" {
		subjects = itSubjects
	}
	subject = subjects[name]
	if subject == "" {
		subject = m.appName + " - " + name
	}
	return subject, buf.String(), nil
}
