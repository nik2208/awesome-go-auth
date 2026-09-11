package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// MailMessage is a single email to be sent.
type MailMessage struct {
	To      string
	Subject string
	// Body is the message: HTML when IsHTML is set, plain text otherwise.
	Body   string
	IsHTML bool
	// Text is the plain-text alternative of an HTML Body — the reference's
	// `text` payload field (mailer.service.ts:133-141). It is read only when
	// IsHTML is set; a plain-text Body already is the text. Left empty, the
	// gateway transport sends the HTML in its place, as the reference's
	// sendCustom does (`text ?? html`, mailer.service.ts:246).
	//
	// omitempty keeps the deprecated HTTPMailerTransport's body byte-identical
	// for the callers that never set it.
	Text string `json:",omitempty"`
}

// MailerTransport delivers email messages.
type MailerTransport interface {
	Send(ctx context.Context, msg MailMessage) error
}

// HTTPMailerTransport sends mail via any HTTP endpoint (no SMTP needed).
//
// Deprecated: it POSTs MailMessage as PascalCase JSON ({"To", "Subject",
// "Body", "IsHTML"}) under an X-Mailer-Secret header — a request of this port's
// own that no gateway built for the reference accepts. NewGatewayMailerTransport
// sends the reference's contract instead. This type keeps its 0.3.0 behaviour
// unchanged for the gateways built against it and is scheduled for removal in
// v1.0.0.
type HTTPMailerTransport struct {
	EndpointURL string
	Secret      string
	client      *http.Client
}

// NewHTTPMailerTransport creates a transport that POSTs to a webhook-style HTTP endpoint.
//
// Deprecated: use NewGatewayMailerTransport; see HTTPMailerTransport for why.
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

// MailerConfig is the reference's email.mailer block (awesome-node-auth
// src/models/auth-config.model.ts:19-36): the settings of the mail gateway
// NewGatewayMailerTransport talks to. The JSON tags are the reference's key
// names, so a deployment that already holds that block for the reference can
// decode it and hand it over as is.
type MailerConfig struct {
	// Endpoint is the full URL the gateway accepts a POST at
	// (auth-config.model.ts:20-21). It must be an absolute http or https URL;
	// NewGatewayMailerTransport refuses anything else.
	Endpoint string `json:"endpoint"`
	// APIKey travels in the X-API-Key header (auth-config.model.ts:22-23).
	APIKey string `json:"apiKey"`
	// From is the sender address, sent as `from` (auth-config.model.ts:24-25).
	From string `json:"from"`
	// FromName is the sender's display name, sent as `fromName` when set
	// (auth-config.model.ts:26-27).
	FromName string `json:"fromName,omitempty"`
	// Provider names the gateway-side provider, sent as `provider` when set
	// (auth-config.model.ts:28-29).
	Provider string `json:"provider,omitempty"`
	// DefaultLang is the reference's default template language, "en" or "it"
	// (auth-config.model.ts:30-35; read by resolveLang, mailer.service.ts:255-259).
	// The transport does not read it: which template set a mail is rendered
	// from is the mailers' decision (MagicLinkMailer.Locale and its siblings).
	// It is carried so the block decodes as one unit and can be passed on.
	DefaultLang string `json:"defaultLang,omitempty"`
	// Client makes the request. Nil means a client with a 10-second timeout,
	// the same bound HTTPMailerTransport and HTTPSMSTransport use.
	Client *http.Client `json:"-"`
}

// NewGatewayMailerTransport builds the transport for the family's mail gateway,
// the contract the reference's built-in mailer speaks (awesome-node-auth
// src/services/mailer.service.ts:261-291):
//
//	POST {endpoint}
//	Content-Type: application/json
//	X-API-Key: {apiKey}
//
//	{"to": …, "subject": …, "html": …, "text": …, "from": …, "fromName": …, "provider": …}
//
// Any status outside 2xx is a failure (mailer.service.ts:280-284). The
// endpoint's own path and query are kept, as the reference keeps them
// (mailer.service.ts:269).
//
// It fails when cfg.Endpoint is empty or not an absolute http(s) URL, so that a
// misconfiguration surfaces at start-up rather than as a 500 on the first send.
// The reference has no such check — `new URL(endpoint)` throws inside send — so
// the constructor is the port's only addition, and it adds no request.
func NewGatewayMailerTransport(cfg MailerConfig) (MailerTransport, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("auth: mailer gateway endpoint is required")
	}
	endpoint, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("auth: mailer gateway endpoint: %w", err)
	}
	if (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" {
		return nil, fmt.Errorf("auth: mailer gateway endpoint %q must be an absolute http or https URL", cfg.Endpoint)
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &gatewayMailerTransport{cfg: cfg, client: client}, nil
}

// gatewayMailerTransport is what NewGatewayMailerTransport returns. It is not
// exported: the constructor is the only way to obtain one because it is where
// the endpoint is validated.
type gatewayMailerTransport struct {
	cfg    MailerConfig
	client *http.Client
}

// gatewayMailPayload is the reference's MailPayload (mailer.service.ts:133-141),
// key for key. fromName and provider are optional there and JSON.stringify
// drops an undefined value, so they are omitted when empty rather than sent
// blank.
type gatewayMailPayload struct {
	To       string `json:"to"`
	Subject  string `json:"subject"`
	HTML     string `json:"html"`
	Text     string `json:"text"`
	From     string `json:"from"`
	FromName string `json:"fromName,omitempty"`
	Provider string `json:"provider,omitempty"`
}

func (t *gatewayMailerTransport) Send(ctx context.Context, msg MailMessage) error {
	payload := gatewayMailPayload{
		To:       msg.To,
		Subject:  msg.Subject,
		From:     t.cfg.From,
		FromName: t.cfg.FromName,
		Provider: t.cfg.Provider,
	}
	if msg.IsHTML {
		payload.HTML = msg.Body
		payload.Text = msg.Text
	} else {
		// A plain-text message has no HTML to offer. The reference has no
		// text-only path, so html goes out empty rather than filled with a
		// body that is not HTML.
		payload.Text = msg.Body
	}
	if payload.Text == "" {
		// text ?? html: the reference sends the HTML as the text when none was
		// supplied (mailer.service.ts:246).
		payload.Text = payload.HTML
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	// Set unconditionally, empty value included, as HTTPSMSTransport does and
	// for the same reason: the reference always sends the header
	// (mailer.service.ts:274).
	req.Header.Set("X-API-Key", t.cfg.APIKey)

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("auth: mailer gateway send: %w", err)
	}
	resp.Body.Close()
	// 2xx only (mailer.service.ts:280-284). The status is all the error carries:
	// the response body is discarded unread, as the reference's res.resume()
	// discards it, and nothing the request was sent with — the key least of
	// all — is repeated back.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("auth: mailer gateway status %d", resp.StatusCode)
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
