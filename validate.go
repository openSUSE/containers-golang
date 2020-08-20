// +build seccomp

package seccomp

import (
	"encoding/json"

	"github.com/pkg/errors"
)

// ValidateProfile does a basic validation for the provided seccomp profile
// string.
func ValidateProfile(content string) error {
	profile := &Seccomp{}
	if err := json.Unmarshal([]byte(content), &profile); err != nil {
		return errors.Wrap(err, "decoding seccomp profile")
	}

	if _, err := BuildFilter(profile); err != nil {
		return errors.Wrap(err, "build seccomp filter")
	}

	return nil
}
