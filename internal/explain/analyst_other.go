//go:build !linux

package explain

import "errors"

func requireAnalyst() error { return errors.New("explain: requires an unprivileged Linux sandbox") }
