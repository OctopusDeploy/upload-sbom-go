package main

import (
	"fmt"
	"strings"
)

const (
	colorGray  = "\033[90m"
	colorReset = "\033[0m"
)

// httpLogger implements retryablehttp.LeveledLogger, printing DEBUG lines in gray.
type httpLogger struct{}

func (l *httpLogger) formatKV(keysAndValues []interface{}) string {
	var sb strings.Builder
	for i := 0; i+1 < len(keysAndValues); i += 2 {
		sb.WriteString(fmt.Sprintf(" %v=%v", keysAndValues[i], keysAndValues[i+1]))
	}
	return sb.String()
}

func (l *httpLogger) Error(msg string, keysAndValues ...interface{}) {
	fmt.Printf("[ERROR] %s%s\n", msg, l.formatKV(keysAndValues))
}
func (l *httpLogger) Warn(msg string, keysAndValues ...interface{}) {
	fmt.Printf("[WARN]  %s%s\n", msg, l.formatKV(keysAndValues))
}
func (l *httpLogger) Info(msg string, keysAndValues ...interface{}) {
	fmt.Printf("[INFO]  %s%s\n", msg, l.formatKV(keysAndValues))
}
func (l *httpLogger) Debug(msg string, keysAndValues ...interface{}) {
	fmt.Printf("%s[DEBUG] %s%s%s\n", colorGray, msg, l.formatKV(keysAndValues), colorReset)
}
