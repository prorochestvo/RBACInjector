package rbacinjector

import (
	"net/http"
	"strings"
)

// RoleExtractor is a function that extracts the role from the request.
type RoleExtractor[T RoleID] func(w http.ResponseWriter, r *http.Request) (role Role[T], exists bool)

// RoleID is the interface that wraps the basic ID method.
// The ID is an uint64 or a string.
type RoleID interface {
	uint64 | string
}

// Role is the interface that wraps the basic methods.
// A role is an uint64 or a string.
type Role[RID RoleID] interface {
	ID() RID
	//Name() string
	//IN(roles ...Role) bool
}

// newRoleValidator returns a new roleValidator based on the roles.
// The roles can be a string or an uint64.
// The Role is checked bitwise for the uint64 roles.
// The Role is case-sensitive for the string roles.
func newRoleValidator[RID RoleID](roles []Role[RID]) roleValidator {
	if len(roles) > 0 {
		switch interface{}(roles[0].ID()).(type) {
		case string:
			var a = ""
			for _, r := range roles {
				if s, ok := interface{}(r.ID()).(string); ok {
					a += "{{" + s + "}}"
				}
			}
			c := strValidator(a)
			return &c
		case uint64:
			var a uint64 = 0
			for _, r := range roles {
				if i, ok := interface{}(r.ID()).(uint64); ok {
					a |= i
				}
			}
			c := intValidator(a)
			return &c
		}
	}
	c := stubValidator(true)
	return &c
}

// roleValidator is the interface that wraps the basic IN method.
// The IN method checks if the Role is in the roles.
type roleValidator interface {
	IN(RoleID interface{}) bool
}

// strValidator is a roleValidator for the string roles.
type strValidator string

// IN checks if the Role is in the roles.
// The Role must be a string.
// The Role is case-sensitive.
func (s strValidator) IN(RoleID interface{}) bool {
	if v, ok := RoleID.(string); ok {
		return strings.Contains(string(s), "{{"+v+"}}")
	}
	return false
}

// intValidator is a roleValidator for the uint64 roles.
type intValidator uint64

// IN checks if the Role is in the roles.
// The Role must be an uint64.
// The Role is checked bitwise.
func (i intValidator) IN(RoleID interface{}) bool {
	if v, ok := RoleID.(uint64); ok {
		return (uint64(i) & v) == v
	}
	return false
}

// stubValidator is a roleValidator for pass through any roles
type stubValidator bool

// IN grants access for any roles.
func (v *stubValidator) IN(_ interface{}) bool {
	return true
}
