package goauth

import (
	"io"
	"text/template"

	"github.com/iamajoe/goauth/entity"
)

type Template int

const (
	TemplateSignUp Template = iota
	TemplateResetPassword
)

type sender interface {
	io.Writer
	GetTemplate(tmpl Template) string
	SetReceiver(user entity.AuthUser)
}

func sendNotification(
	user entity.AuthUser,
	list []sender,
	kind Template,
	data map[string]string,
) []error {
	errors := []error{}

	for _, sender := range list {
		tmplRaw := sender.GetTemplate(kind)
		if len(tmplRaw) == 0 {
			continue
		}

		tmpl, err := template.New("tmpl_send").Parse(tmplRaw)
		if err != nil {
			errors = append(errors, err)
			continue
		}

		sender.SetReceiver(user)
		err = tmpl.Execute(sender, data)
		if err != nil {
			errors = append(errors, err)
		}
	}

	return errors
}
