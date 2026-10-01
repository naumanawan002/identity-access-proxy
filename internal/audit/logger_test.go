package audit

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestAuditLogger_Log(t *testing.T) {
	buf := new(bytes.Buffer)
	logger := NewLogger(buf)

	event := Event{
		ClientIP:       "192.168.1.15",
		Subject:        "user:test",
		Roles:          []string{"analyst"},
		Method:         "POST",
		Path:           "/api/v1/query",
		Allowed:        true,
		RuleID:         "analyst-rule",
		Reason:         "authorized by rule",
		StatusCode:     200,
		DurationMicros: 1250,
	}

	if err := logger.Log(event); err != nil {
		t.Fatalf("failed to write audit log: %v", err)
	}

	var parsed Event
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to parse logged json: %v", err)
	}

	if parsed.Subject != "user:test" || !parsed.Allowed || parsed.StatusCode != 200 {
		t.Errorf("mismatched parsed audit event: %+v", parsed)
	}
	if parsed.EventID == "" {
		t.Error("expected generated EventID, got empty")
	}
	if parsed.Timestamp.IsZero() {
		t.Error("expected generated Timestamp, got zero")
	}
	if parsed.DurationMicros != 1250 {
		t.Errorf("expected 1250 duration, got %d", parsed.DurationMicros)
	}
}
