//go:build linux && (amd64 || arm64)

package main

import "github.com/brunoborges/agent-smith/internal/supervisor"

func init() { supervisor.BootstrapIfRequested() }
