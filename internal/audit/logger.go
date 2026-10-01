package audit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// Event captures the end-to-end security audit record for every access attempt.
type Event struct {
	EventID        string    `json:"event_id"`
	Timestamp      time.Time `json:"timestamp"`
	ClientIP       string    `json:"client_ip"`
	Subject        string    `json:"subject"`
	Email          string    `json:"email,omitempty"`
	Roles          []string  `json:"roles,omitempty"`
	Method         string    `json:"method"`
	Path           string    `json:"path"`
	UserAgent      string    `json:"user_agent,omitempty"`
	DeviceID       string    `json:"device_id,omitempty"`
	DeviceTrust    string    `json:"device_trust,omitempty"`
	Allowed        bool      `json:"allowed"`
	RuleID         string    `json:"rule_id,omitempty"`
	Reason         string    `json:"reason"`
	StatusCode     int       `json:"status_code"`
	DurationMicros int64     `json:"duration_micros"`
}

// Logger handles structured, thread-safe audit telemetry.
type Logger struct {
	mu     sync.Mutex
	writer io.Writer
}

// NewLogger creates an audit logger writing to the provided io.Writer.
func NewLogger(w io.Writer) *Logger {
	if w == nil {
		w = os.Stdout
	}
	return &Logger{writer: w}
}

// Log records an audit event safely as a single line JSON.
func (l *Logger) Log(ev Event) error {
	if ev.EventID == "" {
		ev.EventID = newUUID()
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}

	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = l.writer.Write(data)
	return err
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
