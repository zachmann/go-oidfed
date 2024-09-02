package internal

import l "log"

var debugLogging bool

// EnableDebugLogging enables debug logging
func EnableDebugLogging() {
	debugLogging = true
}

// DisableDebugLogging disables debug logging
func DisableDebugLogging() {
	debugLogging = false
}

// Log logs
func Log(v ...any) {
	if debugLogging {
		l.Println(v...)
	}
}

// Logf logs with format string
func Logf(format string, v ...any) {
	if debugLogging {
		l.Printf(format, v...)
	}
}
