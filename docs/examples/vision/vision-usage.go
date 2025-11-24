//go:build example
// +build example

// This example demonstrates vision routing concepts.
// To run this example, copy it to your main application or use it as a reference.
//
// The vision detection logic is implemented in the internal/router package.
// This file shows how to construct requests that will be routed to vision-capable providers.
//
// To build: go build -tags=example ./docs/examples/vision

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// Vision detection helper function - this would normally be in the internal/router package
func hasVisionContent(messages []interface{}) bool {
	for _, message := range messages {
		msgMap, ok := message.(map[string]interface{})
		if !ok {
			continue
		}

		content, exists := msgMap["content"]
		if !exists {
			continue
		}

		switch c := content.(type) {
		case string:
			// Simple text content - no vision
			continue

		case []interface{}:
			// Array of content items - check for vision content
			for _, item := range c {
				itemMap, ok := item.(map[string]interface{})
				if !ok {
					continue
				}

				contentType, exists := itemMap["type"].(string)
				if !exists {
					continue
				}

				if contentType == "image" {
					return true
				}
			}
		}
	}
	return false
}

// Example demonstrating vision routing capabilities
func main() {
	// Configuration for different vision routing scenarios
	examples := []struct {
		name     string
		request  map[string]interface{}
		expected string
	}{
		{
			name: "Text-only request (routes to default)",
			request: map[string]interface{}{
				"model":      "claude-3-5-sonnet-20241022",
				"max_tokens": 1000,
				"messages": []map[string]interface{}{
					{
						"role":    "user",
						"content": "Hello, can you help me with a text analysis task?",
					},
				},
			},
			expected: "default routing",
		},
		{
			name: "Vision request with image (routes to vision provider)",
			request: map[string]interface{}{
				"model":      "claude-3-5-sonnet-20241022",
				"max_tokens": 1000,
				"messages": []map[string]interface{}{
					{
						"role": "user",
						"content": []interface{}{
							map[string]interface{}{
								"type": "text",
								"text": "What do you see in this image?",
							},
							map[string]interface{}{
								"type": "image",
								"source": map[string]interface{}{
									"type":       "base64",
									"media_type": "image/jpeg",
									"data":       "/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/2wBDAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/wAARCAABAAEDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAv/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/8QAFQEBAQAAAAAAAAAAAAAAAAAAAAX/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIRAxEAPwA/8A8A",
								},
							},
						},
					},
				},
			},
			expected: "vision content detected",
		},
		{
			name: "Multiple images (routes to vision provider)",
			request: map[string]interface{}{
				"model":      "claude-3-5-sonnet-20241022",
				"max_tokens": 1000,
				"messages": []map[string]interface{}{
					{
						"role": "user",
						"content": []interface{}{
							map[string]interface{}{
								"type": "text",
								"text": "Compare these two images:",
							},
							map[string]interface{}{
								"type": "image",
								"source": map[string]interface{}{
									"type":       "base64",
									"media_type": "image/png",
									"data":       "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
								},
							},
							map[string]interface{}{
								"type": "image",
								"source": map[string]interface{}{
									"type":       "base64",
									"media_type": "image/jpeg",
									"data":       "/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/2wBDAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/wAARCAABAAEDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAv/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/8QAFQEBAQAAAAAAAAAAAAAAAAAAAAX/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIRAxEAPwA/8A8A",
								},
							},
						},
					},
				},
			},
			expected: "vision content detected",
		},
		{
			name: "Empty messages (routes to default)",
			request: map[string]interface{}{
				"model":      "claude-3-5-sonnet-20241022",
				"max_tokens": 1000,
				"messages":   []map[string]interface{}{},
			},
			expected: "default routing",
		},
	}

	// Test vision detection function
	fmt.Println("=== Vision Detection Tests ===")
	for _, test := range examples {
		messages, ok := test.request["messages"].([]interface{})
		hasVision := ok && hasVisionContent(messages)
		fmt.Printf("Test: %s - Vision detected: %v\n", test.name, hasVision)
	}

	// Example HTTP client usage
	fmt.Println("\n=== HTTP API Usage Examples ===")

	// Example 1: Text-only request
	textRequest := map[string]interface{}{
		"model": "claude-sonnet",
		"max_tokens": 1000,
		"messages": []map[string]interface{}{
			{
				"role": "user",
				"content": "Describe the principles of machine learning.",
			},
		},
	}

	fmt.Println("1. Text-only request (will route to default provider):")
	makeAPICall("http://localhost:8080/v1/messages", textRequest)

	// Example 2: Vision request
	visionRequest := map[string]interface{}{
		"model": "claude-sonnet",
		"max_tokens": 1000,
		"messages": []map[string]interface{}{
			{
				"role": "user",
				"content": []interface{}{
					map[string]interface{}{
						"type": "text",
						"text": "What do you see in this image?",
					},
					map[string]interface{}{
						"type": "image",
						"source": map[string]interface{}{
							"type":      "base64",
							"media_type": "image/jpeg",
							"data":      "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
						},
					},
				},
			},
		},
	}

	fmt.Println("\n2. Vision request (will route to vision provider):")
	makeAPICall("http://localhost:8080/v1/messages", visionRequest)

	// Example 3: Mix of text and vision in conversation
	mixedRequest := map[string]interface{}{
		"model": "gpt4o",
		"max_tokens": 1000,
		"messages": []map[string]interface{}{
			{
				"role": "user",
				"content": "Can you explain quantum computing?",
			},
			{
				"role": "assistant",
				"content": "Quantum computing is a revolutionary computing paradigm...",
			},
			{
				"role": "user",
				"content": []interface{}{
					map[string]interface{}{
						"type": "text",
						"text": "Now, can you analyze this quantum circuit diagram?",
					},
					map[string]interface{}{
						"type": "image",
						"source": map[string]interface{}{
							"type":      "base64",
							"media_type": "image/png",
							"data":      "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
						},
					},
				},
			},
		},
	}

	fmt.Println("\n3. Mixed conversation (final message has vision, routes to vision provider):")
	makeAPICall("http://localhost:8080/v1/messages", mixedRequest)
}

func makeAPICall(url string, request map[string]interface{}) {
	jsonData, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		log.Printf("Error marshaling request: %v", err)
		return
	}

	fmt.Printf("Request:\n%s\n", string(jsonData))

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Create request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Error creating request: %v", err)
		return
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+os.Getenv("ROUTER_API_KEY"))

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error making request: %v", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("Response Status: %s\n", resp.Status)
	fmt.Printf("Response Headers:\n")
	for key, values := range resp.Header {
		for _, value := range values {
			fmt.Printf("  %s: %s\n", key, value)
		}
	}

	// Note: In a real scenario, you would read and process the response body
	// For this example, we're just showing the routing behavior
	fmt.Println("Note: Set ROUTER_API_KEY environment variable to test actual API calls")
	fmt.Println()
}