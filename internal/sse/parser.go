package sse

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
)

var (
	// ErrInvalidEvent indicates the event format is invalid
	ErrInvalidEvent = errors.New("invalid SSE event format")
	// ErrStreamClosed indicates the stream has been closed
	ErrStreamClosed = errors.New("SSE stream closed")
)

// Event represents a Server-Sent Event with its fields
type Event struct {
	// Event is the event type (e.g., "message", "ping")
	Event string
	// Data is the event payload
	Data string
	// ID is the event identifier for resuming connections
	ID string
	// Retry is the reconnection time in milliseconds
	Retry int
}

// IsDone returns true if this is a [DONE] sentinel event
func (e *Event) IsDone() bool {
	return e.Data == "[DONE]"
}

// IsEmpty returns true if the event has no meaningful content
func (e *Event) IsEmpty() bool {
	return e.Event == "" && e.Data == "" && e.ID == "" && e.Retry == 0
}

// Parser reads and parses SSE streams into Event objects
type Parser struct {
	reader  *bufio.Reader
	mu      sync.Mutex
	buffer  []string // Buffer for incomplete event fields
	closed  bool
	lastID  string // Track last event ID for resumption
}

// NewParser creates a new SSE parser from an io.Reader
func NewParser(r io.Reader) *Parser {
	return &Parser{
		reader: bufio.NewReader(r),
		buffer: make([]string, 0, 8),
	}
}

// Next reads and returns the next event from the stream
// Returns io.EOF when the stream ends, or ErrStreamClosed if closed
func (p *Parser) Next() (*Event, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil, ErrStreamClosed
	}

	event := &Event{}
	hasData := false

	for {
		line, err := p.reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				// If we have buffered data, process it first
				if len(p.buffer) > 0 {
					if e := p.processBuffer(event, &hasData); e != nil {
						return nil, e
					}
					if hasData {
						return event, nil
					}
				}
				return nil, io.EOF
			}
			return nil, fmt.Errorf("error reading SSE stream: %w", err)
		}

		// Trim the newline characters
		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")

		// Empty line signals end of event
		if line == "" {
			if len(p.buffer) > 0 {
				if err := p.processBuffer(event, &hasData); err != nil {
					return nil, err
				}
				if hasData {
					if event.ID != "" {
						p.lastID = event.ID
					}
					return event, nil
				}
			}
			continue
		}

		// Lines starting with : are comments, ignore them
		if strings.HasPrefix(line, ":") {
			continue
		}

		// Add line to buffer for processing
		p.buffer = append(p.buffer, line)
	}
}

// processBuffer processes buffered lines into an Event
func (p *Parser) processBuffer(event *Event, hasData *bool) error {
	dataLines := make([]string, 0, len(p.buffer))

	for _, line := range p.buffer {
		// Parse field:value format
		colonIdx := strings.Index(line, ":")
		if colonIdx == -1 {
			// Field with no value
			field := line
			switch field {
			case "data":
				*hasData = true
			}
			continue
		}

		field := line[:colonIdx]
		value := line[colonIdx+1:]

		// Remove leading space from value if present
		if len(value) > 0 && value[0] == ' ' {
			value = value[1:]
		}

		switch field {
		case "event":
			event.Event = value
		case "data":
			dataLines = append(dataLines, value)
			*hasData = true
		case "id":
			// The spec says ID should not contain null bytes
			if !strings.Contains(value, "\x00") {
				event.ID = value
			}
		case "retry":
			// Parse retry as integer milliseconds
			if retry, err := strconv.Atoi(value); err == nil && retry >= 0 {
				event.Retry = retry
			}
		default:
			// Unknown fields are ignored per SSE spec
		}
	}

	// Join data lines with newlines
	if len(dataLines) > 0 {
		event.Data = strings.Join(dataLines, "\n")
	}

	// Clear buffer for next event
	p.buffer = p.buffer[:0]

	return nil
}

// LastEventID returns the ID of the last successfully parsed event
func (p *Parser) LastEventID() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastID
}

// Close closes the parser and releases resources
func (p *Parser) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	p.buffer = nil
	return nil
}

// ReadAll reads all events from the stream until EOF or error
func (p *Parser) ReadAll() ([]*Event, error) {
	events := make([]*Event, 0)
	for {
		event, err := p.Next()
		if err != nil {
			if err == io.EOF {
				return events, nil
			}
			return events, err
		}
		if !event.IsEmpty() {
			events = append(events, event)
		}
	}
}

// TransformFunc is a function that transforms an event
// Return nil to filter out the event, or a modified event to include it
type TransformFunc func(*Event) (*Event, error)

// Transform reads events from a source reader, applies a transformation function,
// and writes the transformed events to a writer. This enables stream processing.
func Transform(source io.Reader, dest io.Writer, transform TransformFunc) error {
	parser := NewParser(source)
	defer parser.Close()

	serializer := NewSerializer(dest)

	for {
		event, err := parser.Next()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("error reading event: %w", err)
		}

		// Skip empty events
		if event.IsEmpty() {
			continue
		}

		// Apply transformation
		transformed, err := transform(event)
		if err != nil {
			return fmt.Errorf("error transforming event: %w", err)
		}

		// Nil means filter out this event
		if transformed == nil {
			continue
		}

		// Write transformed event
		if err := serializer.Write(transformed); err != nil {
			return fmt.Errorf("error writing event: %w", err)
		}

		// Handle [DONE] sentinel
		if transformed.IsDone() {
			break
		}
	}

	return nil
}

// ParseEvent parses a single SSE event from a string
// Useful for testing or parsing individual events
func ParseEvent(data string) (*Event, error) {
	reader := strings.NewReader(data + "\n\n")
	parser := NewParser(reader)
	defer parser.Close()

	event, err := parser.Next()
	if err != nil {
		return nil, err
	}

	return event, nil
}
