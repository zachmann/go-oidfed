package internal

import l "log"

var debugLogging bool

func EnableDebugLogging() {
	debugLogging = true
}
func DisableDebugLogging() {
	debugLogging = false
}

func Log(v ...any) {
	if debugLogging {
		l.Println(v...)
	}
}

func Logf(format string, v ...any) {
	if debugLogging {
		l.Printf(format, v...)
	}
}
