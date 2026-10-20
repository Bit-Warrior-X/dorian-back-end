package mailer

import (
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"vue-project-backend/internal/config"
)

var ErrNotConfigured = errors.New("email delivery is not configured")

type Mailer struct {
	host     string
	port     string
	user     string
	password string
	from     string
	tlsMode  string
}

func New(cfg config.Config) *Mailer {
	return &Mailer{
		host:     strings.TrimSpace(cfg.SMTPHost),
		port:     strings.TrimSpace(cfg.SMTPPort),
		user:     strings.TrimSpace(cfg.SMTPUser),
		password: cfg.SMTPPassword,
		from:     strings.TrimSpace(cfg.SMTPFrom),
		tlsMode:  strings.ToLower(strings.TrimSpace(cfg.SMTPTLSMode)),
	}
}

func (m *Mailer) Enabled() bool {
	return m != nil && m.host != "" && m.from != ""
}

// Send delivers a plain-text message. tlsMode: "starttls" (default, port 587),
// "tls" (implicit TLS, port 465), or "none" (local relay only).
func (m *Mailer) Send(to, subject, body string) error {
	if !m.Enabled() {
		return ErrNotConfigured
	}
	fromAddr, err := mail.ParseAddress(m.from)
	if err != nil {
		return fmt.Errorf("invalid SMTP_FROM: %w", err)
	}
	toAddr, err := mail.ParseAddress(strings.TrimSpace(to))
	if err != nil {
		return fmt.Errorf("invalid recipient: %w", err)
	}
	port := m.port
	if port == "" {
		port = "587"
	}
	addr := net.JoinHostPort(m.host, port)

	var msg strings.Builder
	msg.WriteString("From: " + fromAddr.String() + "\r\n")
	msg.WriteString("To: " + toAddr.String() + "\r\n")
	msg.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", subject) + "\r\n")
	msg.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n")
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	msg.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	msg.WriteString(strings.ReplaceAll(body, "\n", "\r\n"))

	tlsConfig := &tls.Config{ServerName: m.host, MinVersion: tls.VersionTLS12}
	var client *smtp.Client
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	if m.tlsMode == "tls" {
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("smtp connect: %w", err)
		}
		client, err = smtp.NewClient(conn, m.host)
		if err != nil {
			conn.Close()
			return fmt.Errorf("smtp handshake: %w", err)
		}
	} else {
		conn, err := dialer.Dial("tcp", addr)
		if err != nil {
			return fmt.Errorf("smtp connect: %w", err)
		}
		client, err = smtp.NewClient(conn, m.host)
		if err != nil {
			conn.Close()
			return fmt.Errorf("smtp handshake: %w", err)
		}
		if m.tlsMode != "none" {
			if err := client.StartTLS(tlsConfig); err != nil {
				client.Close()
				return fmt.Errorf("smtp starttls: %w", err)
			}
		}
	}
	defer client.Close()

	if m.user != "" {
		if err := client.Auth(smtp.PlainAuth("", m.user, m.password, m.host)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := client.Mail(fromAddr.Address); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	if err := client.Rcpt(toAddr.Address); err != nil {
		return fmt.Errorf("smtp rcpt: %w", err)
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := writer.Write([]byte(msg.String())); err != nil {
		writer.Close()
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("smtp send: %w", err)
	}
	return client.Quit()
}
