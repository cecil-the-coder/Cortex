package sse

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"sync"
)

// Serializer writes SSE events to an io.Writer
type Serializer struct {
	writer *bufio.Writer
	mu     sync.Mutex
	closed bool
}

// NewSerializer creates a new SSE serializer that writes to the provided writer
func NewSerializer(w io.Writer) *Serializer {
	return &Serializer{
		writer: bufio.NewWriter(w),
	}
}

// Write serializes and writes an Event to the underlying writer
// The event is automatically flushed to ensure immediate delivery
func (s *Serializer) Write(event *Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStreamClosed
	}

	if event == nil {
		return nil
	}

	// Write event type if present
	if event.Event != "" {
		if _, err := fmt.Fprintf(s.writer, "event: %s\n", event.Event); err != nil {
			return fmt.Errorf("error writing event field: %w", err)
		}
	}

	// Write ID if present
	if event.ID != "" {
		if _, err := fmt.Fprintf(s.writer, "id: %s\n", event.ID); err != nil {
			return fmt.Errorf("error writing id field: %w", err)
		}
	}

	// Write retry if present (and non-zero)
	if event.Retry > 0 {
		if _, err := fmt.Fprintf(s.writer, "retry: %d\n", event.Retry); err != nil {
			return fmt.Errorf("error writing retry field: %w", err)
		}
	}

	// Write data field(s)
	// Multi-line data should be split across multiple data: lines
	if event.Data != "" {
		lines := strings.Split(event.Data, "\n")
		for _, line := range lines {
			if _, err := fmt.Fprintf(s.writer, "data: %s\n", line); err != nil {
				return fmt.Errorf("error writing data field: %w", err)
			}
		}
	}

	// Empty line to signal end of event
	if _, err := s.writer.WriteString("\n"); err != nil {
		return fmt.Errorf("error writing event terminator: %w", err)
	}

	// Flush to ensure immediate delivery (critical for streaming)
	if err := s.writer.Flush(); err != nil {
		return fmt.Errorf("error flushing event: %w", err)
	}

	return nil
}

// WriteData is a convenience method to write a simple data-only event
func (s *Serializer) WriteData(data string) error {
	return s.Write(&Event{Data: data})
}

// WriteEvent is a convenience method to write an event with type and data
func (s *Serializer) WriteEvent(eventType, data string) error {
	return s.Write(&Event{
		Event: eventType,
		Data:  data,
	})
}

// WriteDone writes the [DONE] sentinel event
// This is commonly used by OpenAI and Anthropic APIs to signal stream completion
func (s *Serializer) WriteDone() error {
	return s.Write(&Event{Data: "[DONE]"})
}

// WriteComment writes an SSE comment line
// Comments are useful for keep-alive heartbeats
func (s *Serializer) WriteComment(comment string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStreamClosed
	}

	if _, err := fmt.Fprintf(s.writer, ": %s\n\n", comment); err != nil {
		return fmt.Errorf("error writing comment: %w", err)
	}

	if err := s.writer.Flush(); err != nil {
		return fmt.Errorf("error flushing comment: %w", err)
	}

	return nil
}

// Flush manually flushes any buffered data to the underlying writer
func (s *Serializer) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStreamClosed
	}

	if err := s.writer.Flush(); err != nil {
		return fmt.Errorf("error flushing serializer: %w", err)
	}

	return nil
}

// Close closes the serializer and flushes any remaining data
func (s *Serializer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true

	if err := s.writer.Flush(); err != nil {
		return fmt.Errorf("error flushing on close: %w", err)
	}

	return nil
}

// SerializeEvent serializes a single event to a string
// Useful for testing or generating SSE payloads
func SerializeEvent(event *Event) (string, error) {
	var buf strings.Builder
	serializer := NewSerializer(&buf)

	if err := serializer.Write(event); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// WriteMany writes multiple events in sequence
// This is more efficient than calling Write repeatedly
func (s *Serializer) WriteMany(events []*Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStreamClosed
	}

	for _, event := range events {
		if event == nil {
			continue
		}

		// Write event fields (same logic as Write but without lock)
		if event.Event != "" {
			if _, err := fmt.Fprintf(s.writer, "event: %s\n", event.Event); err != nil {
				return fmt.Errorf("error writing event field: %w", err)
			}
		}

		if event.ID != "" {
			if _, err := fmt.Fprintf(s.writer, "id: %s\n", event.ID); err != nil {
				return fmt.Errorf("error writing id field: %w", err)
			}
		}

		if event.Retry > 0 {
			if _, err := fmt.Fprintf(s.writer, "retry: %d\n", event.Retry); err != nil {
				return fmt.Errorf("error writing retry field: %w", err)
			}
		}

		if event.Data != "" {
			lines := strings.Split(event.Data, "\n")
			for _, line := range lines {
				if _, err := fmt.Fprintf(s.writer, "data: %s\n", line); err != nil {
					return fmt.Errorf("error writing data field: %w", err)
				}
			}
		}

		if _, err := s.writer.WriteString("\n"); err != nil {
			return fmt.Errorf("error writing event terminator: %w", err)
		}
	}

	// Flush once at the end
	if err := s.writer.Flush(); err != nil {
		return fmt.Errorf("error flushing events: %w", err)
	}

	return nil
}

// StreamCopier provides a high-level interface for copying SSE streams
type StreamCopier struct {
	parser     *Parser
	serializer *Serializer
	transform  TransformFunc
}

// NewStreamCopier creates a new stream copier
func NewStreamCopier(source io.Reader, dest io.Writer, transform TransformFunc) *StreamCopier {
	return &StreamCopier{
		parser:     NewParser(source),
		serializer: NewSerializer(dest),
		transform:  transform,
	}
}

// Copy copies events from source to destination, applying the transform function
func (sc *StreamCopier) Copy() error {
	defer sc.parser.Close()
	defer sc.serializer.Close()

	for {
		event, err := sc.parser.Next()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		if event.IsEmpty() {
			continue
		}

		// Apply transformation if provided
		if sc.transform != nil {
			event, err = sc.transform(event)
			if err != nil {
				return err
			}
			// Skip if transform returns nil (filtered out)
			if event == nil {
				continue
			}
		}

		if err := sc.serializer.Write(event); err != nil {
			return err
		}

		if event.IsDone() {
			break
		}
	}

	return nil
}
