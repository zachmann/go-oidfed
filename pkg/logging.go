package pkg

import (
	"github.com/zachmann/go-oidfed/internal"
)

// EnableDebugLogging enables debug logging
func EnableDebugLogging() {
	internal.EnableDebugLogging()
}

// DisableDebugLogging disables debug logging
func DisableDebugLogging() {
	internal.DisableDebugLogging()
}
