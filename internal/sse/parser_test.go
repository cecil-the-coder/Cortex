package sse

import (
	"io"
	"strings"
	"testing"
)

func TestParser_Next_BasicEvent(t *testing.T) {
	input := "data: hello world\n\n"
	parser := NewParser(strings.NewReader(input))
	defer parser.Close()

	event, err := parser.Next()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.Data != "hello world" {
		t.Errorf("expected data 'hello world', got '%s'", event.Data)
	}
}

func TestParser_Next_MultiLineData(t *testing.T) {
	input := "data: line 1\ndata: line 2\ndata: line 3\n\n"
	parser := NewParser(strings.NewReader(input))
	defer parser.Close()

	event, err := parser.Next()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "line 1\nline 2\nline 3"
	if event.Data != expected {
		t.Errorf("expected data '%s', got '%s'", expected, event.Data)
	}
}

func TestParser_Next_AllFields(t *testing.T) {
	input := "event: message\nid: 123\nretry: 5000\ndata: test data\n\n"
	parser := NewParser(strings.NewReader(input))
	defer parser.Close()

	event, err := parser.Next()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.Event != "message" {
		t.Errorf("expected event 'message', got '%s'", event.Event)
	}
	if event.ID != "123" {
		t.Errorf("expected id '123', got '%s'", event.ID)
	}
	if event.Retry != 5000 {
		t.Errorf("expected retry 5000, got %d", event.Retry)
	}
	if event.Data != "test data" {
		t.Errorf("expected data 'test data', got '%s'", event.Data)
	}
}

func TestParser_Next_Comments(t *testing.T) {
	input := ": this is a comment\ndata: actual data\n\n"
	parser := NewParser(strings.NewReader(input))
	defer parser.Close()

	event, err := parser.Next()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.Data != "actual data" {
		t.Errorf("expected data 'actual data', got '%s'", event.Data)
	}
}

func TestParser_Next_MultipleEvents(t *testing.T) {
	input := "data: first\n\ndata: second\n\ndata: third\n\n"
	parser := NewParser(strings.NewReader(input))
	defer parser.Close()

	events := []string{"first", "second", "third"}
	for i, expected := range events {
		event, err := parser.Next()
		if err != nil {
			t.Fatalf("event %d: unexpected error: %v", i, err)
		}
		if event.Data != expected {
			t.Errorf("event %d: expected data '%s', got '%s'", i, expected, event.Data)
		}
	}

	// Should get EOF after all events
	_, err := parser.Next()
	if err != io.EOF {
		t.Errorf("expected EOF, got %v", err)
	}
}

func TestParser_Next_DoneSentinel(t *testing.T) {
	input := "data: [DONE]\n\n"
	parser := NewParser(strings.NewReader(input))
	defer parser.Close()

	event, err := parser.Next()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !event.IsDone() {
		t.Error("expected IsDone() to return true")
	}
	if event.Data != "[DONE]" {
		t.Errorf("expected data '[DONE]', got '%s'", event.Data)
	}
}

func TestParser_Next_EmptyLines(t *testing.T) {
	input := "\n\ndata: hello\n\n\n\ndata: world\n\n"
	parser := NewParser(strings.NewReader(input))
	defer parser.Close()

	event, err := parser.Next()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Data != "hello" {
		t.Errorf("expected data 'hello', got '%s'", event.Data)
	}

	event, err = parser.Next()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Data != "world" {
		t.Errorf("expected data 'world', got '%s'", event.Data)
	}
}

func TestParser_Next_IDWithNullByte(t *testing.T) {
	input := "id: contains\x00null\ndata: test\n\n"
	parser := NewParser(strings.NewReader(input))
	defer parser.Close()

	event, err := parser.Next()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// ID with null byte should be ignored per spec
	if event.ID != "" {
		t.Errorf("expected empty ID, got '%s'", event.ID)
	}
}

func TestParser_Next_InvalidRetry(t *testing.T) {
	input := "retry: invalid\ndata: test\n\n"
	parser := NewParser(strings.NewReader(input))
	defer parser.Close()

	event, err := parser.Next()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Invalid retry should be ignored
	if event.Retry != 0 {
		t.Errorf("expected retry 0, got %d", event.Retry)
	}
}

func TestParser_Next_NegativeRetry(t *testing.T) {
	input := "retry: -100\ndata: test\n\n"
	parser := NewParser(strings.NewReader(input))
	defer parser.Close()

	event, err := parser.Next()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Negative retry should be ignored
	if event.Retry != 0 {
		t.Errorf("expected retry 0, got %d", event.Retry)
	}
}

func TestParser_LastEventID(t *testing.T) {
	input := "id: 1\ndata: first\n\nid: 2\ndata: second\n\n"
	parser := NewParser(strings.NewReader(input))
	defer parser.Close()

	parser.Next()
	if parser.LastEventID() != "1" {
		t.Errorf("expected last event ID '1', got '%s'", parser.LastEventID())
	}

	parser.Next()
	if parser.LastEventID() != "2" {
		t.Errorf("expected last event ID '2', got '%s'", parser.LastEventID())
	}
}

func TestParser_ReadAll(t *testing.T) {
	input := "data: first\n\ndata: second\n\ndata: third\n\n"
	parser := NewParser(strings.NewReader(input))
	defer parser.Close()

	events, err := parser.ReadAll()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	expected := []string{"first", "second", "third"}
	for i, exp := range expected {
		if events[i].Data != exp {
			t.Errorf("event %d: expected data '%s', got '%s'", i, exp, events[i].Data)
		}
	}
}

func TestParseEvent(t *testing.T) {
	input := "event: test\ndata: hello"
	event, err := ParseEvent(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.Event != "test" {
		t.Errorf("expected event 'test', got '%s'", event.Event)
	}
	if event.Data != "hello" {
		t.Errorf("expected data 'hello', got '%s'", event.Data)
	}
}

func TestEvent_IsEmpty(t *testing.T) {
	tests := []struct {
		name  string
		event Event
		want  bool
	}{
		{
			name:  "completely empty",
			event: Event{},
			want:  true,
		},
		{
			name:  "has data",
			event: Event{Data: "test"},
			want:  false,
		},
		{
			name:  "has event type",
			event: Event{Event: "message"},
			want:  false,
		},
		{
			name:  "has ID",
			event: Event{ID: "123"},
			want:  false,
		},
		{
			name:  "has retry",
			event: Event{Retry: 1000},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.event.IsEmpty(); got != tt.want {
				t.Errorf("IsEmpty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParser_FieldWithNoValue(t *testing.T) {
	input := "data:\n\n"
	parser := NewParser(strings.NewReader(input))
	defer parser.Close()

	event, err := parser.Next()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Field with no value should result in empty data
	if event.Data != "" {
		t.Errorf("expected empty data, got '%s'", event.Data)
	}
}

func TestParser_LeadingSpace(t *testing.T) {
	input := "data: no space\ndata:  with space\n\n"
	parser := NewParser(strings.NewReader(input))
	defer parser.Close()

	event, err := parser.Next()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Leading space after colon should be removed
	expected := "no space\n with space"
	if event.Data != expected {
		t.Errorf("expected data '%s', got '%s'", expected, event.Data)
	}
}
