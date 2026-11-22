//go:build !linux

package watch

import (
	"errors"
	"io"

	"github.com/brunoborges/agent-smith/internal/policy"
)

func Run(r io.Reader, host policy.Host, emit policy.Emit) error {
	return errors.New("auditd watchdog requires Linux")
}
