package sse

import (
	"bytes"
	"strings"
	"testing"
)

func TestSerializer_Write_BasicEvent(t *testing.T) {
	var buf bytes.Buffer
	serializer := NewSerializer(&buf)
	defer serializer.Close()

	event := &Event{Data: "hello world"}
	if err := serializer.Write(event); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "data: hello world\n\n"
	if buf.String() != expected {
		t.Errorf("expected output '%s', got '%s'", expected, buf.String())
	}
}

func TestSerializer_Write_AllFields(t *testing.T) {
	var buf bytes.Buffer
	serializer := NewSerializer(&buf)
	defer serializer.Close()

	event := &Event{
		Event: "message",
		ID:    "123",
		Retry: 5000,
		Data:  "test data",
	}

	if err := serializer.Write(event); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// Check that all fields are present
	if !strings.Contains(output, "event: message\n") {
		t.Error("output missing event field")
	}
	if !strings.Contains(output, "id: 123\n") {
		t.Error("output missing id field")
	}
	if !strings.Contains(output, "retry: 5000\n") {
		t.Error("output missing retry field")
	}
	if !strings.Contains(output, "data: test data\n") {
		t.Error("output missing data field")
	}
	if !strings.HasSuffix(output, "\n\n") {
		t.Error("output should end with double newline")
	}
}

func TestSerializer_Write_MultiLineData(t *testing.T) {
	var buf bytes.Buffer
	serializer := NewSerializer(&buf)
	defer serializer.Close()

	event := &Event{Data: "line 1\nline 2\nline 3"}
	if err := serializer.Write(event); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "data: line 1\ndata: line 2\ndata: line 3\n\n"
	if buf.String() != expected {
		t.Errorf("expected output '%s', got '%s'", expected, buf.String())
	}
}

func TestSerializer_WriteData(t *testing.T) {
	var buf bytes.Buffer
	serializer := NewSerializer(&buf)
	defer serializer.Close()

	if err := serializer.WriteData("test"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "data: test\n\n"
	if buf.String() != expected {
		t.Errorf("expected output '%s', got '%s'", expected, buf.String())
	}
}

func TestSerializer_WriteEvent(t *testing.T) {
	var buf bytes.Buffer
	serializer := NewSerializer(&buf)
	defer serializer.Close()

	if err := serializer.WriteEvent("ping", "keepalive"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "event: ping\n") {
		t.Error("output missing event field")
	}
	if !strings.Contains(output, "data: keepalive\n") {
		t.Error("output missing data field")
	}
}

func TestSerializer_WriteDone(t *testing.T) {
	var buf bytes.Buffer
	serializer := NewSerializer(&buf)
	defer serializer.Close()

	if err := serializer.WriteDone(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "data: [DONE]\n\n"
	if buf.String() != expected {
		t.Errorf("expected output '%s', got '%s'", expected, buf.String())
	}
}

func TestSerializer_WriteComment(t *testing.T) {
	var buf bytes.Buffer
	serializer := NewSerializer(&buf)
	defer serializer.Close()

	if err := serializer.WriteComment("keepalive"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := ": keepalive\n\n"
	if buf.String() != expected {
		t.Errorf("expected output '%s', got '%s'", expected, buf.String())
	}
}

func TestSerializer_WriteMany(t *testing.T) {
	var buf bytes.Buffer
	serializer := NewSerializer(&buf)
	defer serializer.Close()

	events := []*Event{
		{Data: "first"},
		{Data: "second"},
		{Data: "third"},
	}

	if err := serializer.WriteMany(events); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "data: first\n\ndata: second\n\ndata: third\n\n"
	if buf.String() != expected {
		t.Errorf("expected output '%s', got '%s'", expected, buf.String())
	}
}

func TestSerializer_WriteMany_WithNil(t *testing.T) {
	var buf bytes.Buffer
	serializer := NewSerializer(&buf)
	defer serializer.Close()

	events := []*Event{
		{Data: "first"},
		nil,
		{Data: "second"},
	}

	if err := serializer.WriteMany(events); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Nil events should be skipped
	expected := "data: first\n\ndata: second\n\n"
	if buf.String() != expected {
		t.Errorf("expected output '%s', got '%s'", expected, buf.String())
	}
}

func TestSerializeEvent(t *testing.T) {
	event := &Event{
		Event: "test",
		Data:  "hello",
	}

	output, err := SerializeEvent(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(output, "event: test\n") {
		t.Error("output missing event field")
	}
	if !strings.Contains(output, "data: hello\n") {
		t.Error("output missing data field")
	}
}

func TestSerializer_Closed(t *testing.T) {
	var buf bytes.Buffer
	serializer := NewSerializer(&buf)
	serializer.Close()

	// Writing to closed serializer should fail
	err := serializer.Write(&Event{Data: "test"})
	if err != ErrStreamClosed {
		t.Errorf("expected ErrStreamClosed, got %v", err)
	}
}

func TestRoundTrip(t *testing.T) {
	// Test that we can serialize and parse back the same event
	original := &Event{
		Event: "message",
		ID:    "42",
		Retry: 3000,
		Data:  "multi\nline\ndata",
	}

	// Serialize
	var buf bytes.Buffer
	serializer := NewSerializer(&buf)
	if err := serializer.Write(original); err != nil {
		t.Fatalf("serialize error: %v", err)
	}
	serializer.Close()

	// Parse back
	parser := NewParser(&buf)
	parsed, err := parser.Next()
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	parser.Close()

	// Compare
	if parsed.Event != original.Event {
		t.Errorf("event mismatch: got '%s', want '%s'", parsed.Event, original.Event)
	}
	if parsed.ID != original.ID {
		t.Errorf("id mismatch: got '%s', want '%s'", parsed.ID, original.ID)
	}
	if parsed.Retry != original.Retry {
		t.Errorf("retry mismatch: got %d, want %d", parsed.Retry, original.Retry)
	}
	if parsed.Data != original.Data {
		t.Errorf("data mismatch: got '%s', want '%s'", parsed.Data, original.Data)
	}
}

func TestStreamCopier(t *testing.T) {
	input := "data: first\n\ndata: second\n\ndata: third\n\n"
	reader := strings.NewReader(input)
	var buf bytes.Buffer

	copier := NewStreamCopier(reader, &buf, nil)
	if err := copier.Copy(); err != nil {
		t.Fatalf("copy error: %v", err)
	}

	if buf.String() != input {
		t.Errorf("output mismatch: got '%s', want '%s'", buf.String(), input)
	}
}

func TestStreamCopier_WithTransform(t *testing.T) {
	input := "data: 1\n\ndata: 2\n\ndata: 3\n\n"
	reader := strings.NewReader(input)
	var buf bytes.Buffer

	// Transform that filters out "2"
	transform := func(e *Event) (*Event, error) {
		if e.Data == "2" {
			return nil, nil // Filter out
		}
		return e, nil
	}

	copier := NewStreamCopier(reader, &buf, transform)
	if err := copier.Copy(); err != nil {
		t.Fatalf("copy error: %v", err)
	}

	expected := "data: 1\n\ndata: 3\n\n"
	if buf.String() != expected {
		t.Errorf("output mismatch: got '%s', want '%s'", buf.String(), expected)
	}
}

func TestStreamCopier_DoneSentinel(t *testing.T) {
	input := "data: first\n\ndata: [DONE]\n\ndata: after\n\n"
	reader := strings.NewReader(input)
	var buf bytes.Buffer

	copier := NewStreamCopier(reader, &buf, nil)
	if err := copier.Copy(); err != nil {
		t.Fatalf("copy error: %v", err)
	}

	// Should stop at [DONE]
	expected := "data: first\n\ndata: [DONE]\n\n"
	if buf.String() != expected {
		t.Errorf("output mismatch: got '%s', want '%s'", buf.String(), expected)
	}
}
