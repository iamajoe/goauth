package sender

import (
	"errors"
	"fmt"
	"html/template"
	"net/smtp"
	"strings"
)

const (
	SenderEmailSubjectSignUpTmpl = "Confirm your signup"
	SenderEmailBodySignUpTmpl    = `
	<body style="padding: 30px;">
		<h2>Confirm your signup</h2>

		<p>Follow this link to confirm your user:</p>
		<p><a href="{{ .baseURL }}/signup/verify/{{ .code }}">Confirm your mail</a></p>
	</body>
	`

	SenderEmailSubjectResetPasswordTmpl = "Reset your password"
	SenderEmailBodyResetPasswordTmpl    = `
	<body style="padding: 30px;">
		<h2>Reset Password</h2>

		<p>Follow this link to reset the password for your user:</p>
		<p><a href="{{ .baseURL }}/reset/verify/{{ .code }}">Reset Password</a></p>
	</body>
	`
)

type senderEmail struct {
	smtpHost  string
	smtpPort  string
	fromEmail string
	username  string
	password  string

	subjectTemplates map[Template]*template.Template
	bodyTemplates    map[Template]*template.Template
}

type senderEmailMail struct {
	Sender  string
	To      []string
	Subject string
	Body    string
}

type senderEmailOptFn func(*senderEmail) *senderEmail

func NewSenderEmail(
	smtpHost string,
	smtpPort string,
	username string,
	password string,
	fromEmail string,
	opts ...senderEmailOptFn,
) *senderEmail {
	sender := &senderEmail{
		smtpHost:  smtpHost,
		smtpPort:  smtpPort,
		username:  username,
		password:  password,
		fromEmail: fromEmail,
	}

	// set defaults for the templates
	sender = WithEmailTemplates(
		map[Template]string{
			TemplateSignUp:        SenderEmailSubjectSignUpTmpl,
			TemplateResetPassword: SenderEmailSubjectResetPasswordTmpl,
		},
		map[Template]string{
			TemplateSignUp:        SenderEmailBodySignUpTmpl,
			TemplateResetPassword: SenderEmailBodyResetPasswordTmpl,
		},
	)(sender)

	return sender.SetOpts(opts...)
}

// SetOpts gives a simple way upon creation to change some of the options
func (sender *senderEmail) SetOpts(opts ...senderEmailOptFn) *senderEmail {
	for _, opt := range opts {
		sender = opt(sender)
	}

	return sender
}

// Send sends the templated content to a single recipient
func (sender *senderEmail) Send(kind Template, userData map[string]string) error {
	if len(sender.smtpHost) == 0 {
		return errors.New("smtp host is required")
	}

	if len(sender.smtpPort) == 0 {
		return errors.New("smtp port is required")
	}

	if len(sender.fromEmail) == 0 {
		return errors.New("from email is required")
	}

	if len(sender.username) == 0 {
		return errors.New("username is required")
	}

	if len(sender.password) == 0 {
		return errors.New("password is required")
	}

	subject, body, err := sender.template(kind, userData)
	if err != nil {
		return err
	}

	// figure where to is
	toEmail := []string{}
	for key, value := range userData {
		if key == "email" {
			toEmail = append(toEmail, value)
			break
		}
	}

	msg := sender.buildMessage(senderEmailMail{
		Sender:  sender.fromEmail,
		To:      toEmail,
		Subject: subject,
		Body:    body,
	})

	return sender.write(toEmail, []byte(msg))
}

// SendBulk sends a bulk of templated content to a list of recipients
func (i *senderEmail) SendBulk(kind Template, list []map[string]string) error {
	for _, userData := range list {
		err := i.Send(kind, userData)
		if err != nil {
			return err
		}
	}

	return nil
}

func (sender *senderEmail) buildMessage(mail senderEmailMail) string {
	msg := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\r\n"
	msg += fmt.Sprintf("From: %s\r\n", mail.Sender)
	msg += fmt.Sprintf("To: %s\r\n", strings.Join(mail.To, ";"))
	msg += fmt.Sprintf("Subject: %s\r\n", mail.Subject)
	msg += fmt.Sprintf("\r\n%s\r\n", mail.Body)

	return msg
}

func (sender *senderEmail) template(
	kind Template,
	params map[string]string,
) (string, string, error) {
	// build templated subject
	subjectTmpl, ok := sender.subjectTemplates[kind]
	if !ok {
		return "", "", fmt.Errorf("template %d not supported", kind)
	}
	subject := new(strings.Builder)
	err := subjectTmpl.Execute(subject, params)
	if err != nil {
		return "", "", err
	}

	// build templated body
	bodyTmpl, ok := sender.bodyTemplates[kind]
	if !ok {
		return "", "", fmt.Errorf("template %d not supported", kind)
	}
	body := new(strings.Builder)
	err = bodyTmpl.Execute(body, params)
	if err != nil {
		return "", "", err
	}

	return subject.String(), body.String(), nil
}

func (sender *senderEmail) write(toEmail []string, msg []byte) error {
	auth := smtp.PlainAuth("", sender.fromEmail, sender.password, sender.smtpHost)
	return smtp.SendMail(sender.smtpHost+":"+sender.smtpPort, auth, sender.fromEmail, toEmail, msg)
}

// WithEmailTemplates sets the templates for the sender
func WithEmailTemplates(
	subjectTemplates map[Template]string,
	bodyTemplates map[Template]string,
) senderEmailOptFn {
	// pre compile subject templates
	subjectTmpls := make(map[Template]*template.Template)
	for kind, raw := range subjectTemplates {
		tmpl, err := template.New(fmt.Sprintf("email_subject_template_%d", kind)).Parse(raw)
		if err == nil {
			subjectTmpls[kind] = tmpl
		}
	}

	// pre compile body templates
	bodyTmpls := make(map[Template]*template.Template)
	for kind, raw := range bodyTemplates {
		tmpl, err := template.New(fmt.Sprintf("email_body_template_%d", kind)).Parse(raw)
		if err == nil {
			bodyTmpls[kind] = tmpl
		}
	}

	return func(sender *senderEmail) *senderEmail {
		sender.subjectTemplates = subjectTmpls
		sender.bodyTemplates = bodyTmpls
		return sender
	}
}
