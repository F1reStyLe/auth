package notify

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

type SMTPConfig struct {
	Host      string
	Port      string
	Username  string
	Password  string
	FromEmail string
	FromName  string
}

type SMTPMailer struct {
	cfg SMTPConfig
}

func NewSMTPMailer(cfg SMTPConfig) (*SMTPMailer, error) {
	switch {
	case strings.TrimSpace(cfg.Host) == "":
		return nil, fmt.Errorf("smtp host is required")
	case strings.TrimSpace(cfg.Port) == "":
		return nil, fmt.Errorf("smtp port is required")
	case strings.TrimSpace(cfg.Username) == "":
		return nil, fmt.Errorf("smtp username is required")
	case strings.TrimSpace(cfg.Password) == "":
		return nil, fmt.Errorf("smtp password is required")
	case strings.TrimSpace(cfg.FromEmail) == "":
		return nil, fmt.Errorf("smtp from email is required")
	}

	if strings.TrimSpace(cfg.FromName) == "" {
		cfg.FromName = "Auth Service"
	}

	return &SMTPMailer{cfg: cfg}, nil
}

func (m *SMTPMailer) SendEmailVerification(ctx context.Context, recipientEmail, verificationURL string, expiresAt time.Time) error {
	subject := "Verify your email"
	plain := fmt.Sprintf("Verify your email by opening this link before %s: %s", expiresAt.Format(time.RFC1123), verificationURL)
	html := fmt.Sprintf(`<p>Verify your email by opening the link below before <strong>%s</strong>.</p><p><a href="%s">%s</a></p>`, expiresAt.Format(time.RFC1123), verificationURL, verificationURL)
	return m.send(ctx, recipientEmail, subject, plain, html)
}

func (m *SMTPMailer) SendPasswordReset(ctx context.Context, recipientEmail, resetURL string, expiresAt time.Time) error {
	subject := "Reset your password"
	plain := fmt.Sprintf("Reset your password by opening this link before %s: %s", expiresAt.Format(time.RFC1123), resetURL)
	html := fmt.Sprintf(`<p>Reset your password by opening the link below before <strong>%s</strong>.</p><p><a href="%s">%s</a></p>`, expiresAt.Format(time.RFC1123), resetURL, resetURL)
	return m.send(ctx, recipientEmail, subject, plain, html)
}

func (m *SMTPMailer) send(ctx context.Context, recipientEmail, subject, plainBody, htmlBody string) error {
	message := buildMessage(m.cfg.FromName, m.cfg.FromEmail, recipientEmail, subject, plainBody, htmlBody)
	addr := net.JoinHostPort(m.cfg.Host, m.cfg.Port)

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial smtp: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		return fmt.Errorf("create smtp client: %w", err)
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: m.cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}

	auth := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}

	if err := client.Mail(m.cfg.FromEmail); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	if err := client.Rcpt(recipientEmail); err != nil {
		return fmt.Errorf("smtp rcpt to: %w", err)
	}

	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := writer.Write([]byte(message)); err != nil {
		_ = writer.Close()
		return fmt.Errorf("write smtp message: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("close smtp writer: %w", err)
	}

	if err := client.Quit(); err != nil {
		return fmt.Errorf("smtp quit: %w", err)
	}

	return nil
}

func buildMessage(fromName, fromEmail, toEmail, subject, plainBody, htmlBody string) string {
	boundary := fmt.Sprintf("mixed_%d", time.Now().UnixNano())

	headers := []string{
		fmt.Sprintf("From: %s <%s>", fromName, fromEmail),
		fmt.Sprintf("To: %s", toEmail),
		fmt.Sprintf("Subject: %s", subject),
		"MIME-Version: 1.0",
		fmt.Sprintf(`Content-Type: multipart/alternative; boundary="%s"`, boundary),
		"",
	}

	parts := []string{
		fmt.Sprintf("--%s", boundary),
		`Content-Type: text/plain; charset="UTF-8"`,
		"",
		plainBody,
		fmt.Sprintf("--%s", boundary),
		`Content-Type: text/html; charset="UTF-8"`,
		"",
		htmlBody,
		fmt.Sprintf("--%s--", boundary),
		"",
	}

	return strings.Join(append(headers, parts...), "\r\n")
}
