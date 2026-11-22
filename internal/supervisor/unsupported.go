//go:build !linux || (!amd64 && !arm64)

package supervisor

import (
	"errors"

	"github.com/brunoborges/agent-smith/internal/policy"
)

func Run(string, []string, []policy.Rule, policy.Emit) (int, error) {
	return 1, errors.New("supervised launch requires Linux amd64 or arm64")
}
