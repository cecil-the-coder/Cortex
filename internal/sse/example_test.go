package sse_test

import (
	"bytes"
	"fmt"
	"log"
	"strings"

	"github.com/cecil-the-coder/Cortex/internal/sse"
)

// ExampleParser demonstrates basic SSE parsing
func ExampleParser() {
	input := `data: Hello
data: World

event: ping
data: keepalive

data: [DONE]

`

	parser := sse.NewParser(strings.NewReader(input))
	defer parser.Close()

	for {
		event, err := parser.Next()
		if err != nil {
			break
		}

		if event.IsDone() {
			fmt.Println("Stream completed")
			break
		}

		if event.Event != "" {
			fmt.Printf("Event: %s, Data: %s\n", event.Event, event.Data)
		} else {
			fmt.Printf("Data: %s\n", event.Data)
		}
	}

	// Output:
	// Data: Hello
	// World
	// Event: ping, Data: keepalive
	// Stream completed
}

// ExampleSerializer demonstrates basic SSE serialization
func ExampleSerializer() {
	var buf bytes.Buffer
	serializer := sse.NewSerializer(&buf)
	defer serializer.Close()

	// Write a simple data event
	serializer.WriteData("Hello World")

	// Write an event with type
	serializer.WriteEvent("ping", "keepalive")

	// Write a complex event
	serializer.Write(&sse.Event{
		ID:    "42",
		Event: "message",
		Data:  "Complex event",
		Retry: 3000,
	})

	// Write completion signal
	serializer.WriteDone()

	fmt.Print(buf.String())

	// Output:
	// data: Hello World
	//
	// event: ping
	// data: keepalive
	//
	// event: message
	// id: 42
	// retry: 3000
	// data: Complex event
	//
	// data: [DONE]
	//
}

// ExampleTransform demonstrates stream transformation
func ExampleTransform() {
	// Source SSE stream (e.g., from OpenAI API)
	input := `data: {"delta": "Hello"}

data: {"delta": " World"}

data: [DONE]

`

	var output bytes.Buffer

	// Transform function that modifies events
	transform := func(event *sse.Event) (*sse.Event, error) {
		// Pass [DONE] through unchanged
		if event.IsDone() {
			return event, nil
		}

		// Modify the data (e.g., add prefix)
		event.Data = "transformed: " + event.Data
		return event, nil
	}

	// Apply transformation
	err := sse.Transform(strings.NewReader(input), &output, transform)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Print(output.String())

	// Output:
	// data: transformed: {"delta": "Hello"}
	//
	// data: transformed: {"delta": " World"}
	//
	// data: [DONE]
	//
}

// ExampleStreamCopier demonstrates high-level stream copying
func ExampleStreamCopier() {
	input := `data: message 1

data: message 2

data: message 3

data: [DONE]

`

	var output bytes.Buffer

	// Filter function that removes every other message
	counter := 0
	filter := func(event *sse.Event) (*sse.Event, error) {
		if event.IsDone() {
			return event, nil
		}

		counter++
		if counter%2 == 0 {
			return nil, nil // Filter out even-numbered messages
		}
		return event, nil
	}

	copier := sse.NewStreamCopier(strings.NewReader(input), &output, filter)
	if err := copier.Copy(); err != nil {
		log.Fatal(err)
	}

	fmt.Print(output.String())

	// Output:
	// data: message 1
	//
	// data: message 3
	//
	// data: [DONE]
	//
}

// ExampleParser_multipleEvents demonstrates parsing multiple events
func ExampleParser_multipleEvents() {
	input := `event: start
data: Stream starting

data: First message

data: Second message

event: end
data: Stream ending

`

	parser := sse.NewParser(strings.NewReader(input))
	defer parser.Close()

	events, err := parser.ReadAll()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Received %d events\n", len(events))
	for i, event := range events {
		if event.Event != "" {
			fmt.Printf("Event %d: type=%s, data=%s\n", i+1, event.Event, event.Data)
		} else {
			fmt.Printf("Event %d: data=%s\n", i+1, event.Data)
		}
	}

	// Output:
	// Received 4 events
	// Event 1: type=start, data=Stream starting
	// Event 2: data=First message
	// Event 3: data=Second message
	// Event 4: type=end, data=Stream ending
}

// ExampleSerializer_WriteMany demonstrates batch writing
func ExampleSerializer_WriteMany() {
	var buf bytes.Buffer
	serializer := sse.NewSerializer(&buf)
	defer serializer.Close()

	events := []*sse.Event{
		{Data: "First"},
		{Data: "Second"},
		{Data: "Third"},
	}

	if err := serializer.WriteMany(events); err != nil {
		log.Fatal(err)
	}

	fmt.Print(buf.String())

	// Output:
	// data: First
	//
	// data: Second
	//
	// data: Third
	//
}
