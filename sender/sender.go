package sender

type Template int

const (
	TemplateSignUp Template = iota
	TemplateResetPassword
)

type Sender interface {
	SendBulk(kind Template, list []map[string]string) error
}

// SendBulk send a bulk of notifications
// data is a slice of notifications with the data needed for templates
//
//		map[string]string{
//			"userID":    user.ID.String(),
//			"email":     user.Email,
//			"phone":     user.PhoneNumber,
//	    "firstName": user.FirstName,
//	    "lastName":  user.LastName,
//			"code":      token.Value,
//		},
func SendBulk(list []Sender, kind Template, data []map[string]string) []error {
	errors := []error{}

	for _, sender := range list {
		err := sender.SendBulk(kind, data)
		if err != nil {
			errors = append(errors, err)
		}
	}

	return errors
}
