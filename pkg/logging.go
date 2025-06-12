package pkg

import (
	"github.com/go-oidfed/lib/internal"
)

// EnableDebugLogging enables debug logging
func EnableDebugLogging() {
	internal.EnableDebugLogging()
}

// DisableDebugLogging disables debug logging
func DisableDebugLogging() {
	internal.DisableDebugLogging()
}
