package providers

import (
	"github.com/cecil-the-coder/ai-provider-kit/pkg/types"
)

// StandardToLegacyStreamAdapter converts StandardStream to legacy ChatCompletionStream
type StandardToLegacyStreamAdapter struct {
	standardStream types.StandardStream
	providerName   string
}

// Next returns the next chunk from the stream in legacy format
func (s *StandardToLegacyStreamAdapter) Next() (types.ChatCompletionChunk, error) {
	chunk, err := s.standardStream.Next()
	if err != nil {
		return types.ChatCompletionChunk{}, err
	}

	var choices []types.ChatChoice
	if len(chunk.Choices) > 0 {
		for _, choice := range chunk.Choices {
			legacyChoice := types.ChatChoice{
				Index: choice.Index,
				Delta: types.ChatMessage{
					Role:    choice.Delta.Role,
					Content: choice.Delta.Content,
				},
				FinishReason: choice.FinishReason,
			}

			// Copy tool calls if present
			if len(choice.Delta.ToolCalls) > 0 {
				legacyChoice.Delta.ToolCalls = choice.Delta.ToolCalls
			}

			choices = append(choices, legacyChoice)
		}
	} else {
		// Create empty choice if none exist
		choices = []types.ChatChoice{{
			Index: 0,
			Delta: types.ChatMessage{
				Role:    "assistant",
				Content: "",
			},
		}}
	}

	// Handle usage information
	var usage types.Usage
	if chunk.Usage != nil {
		usage = *chunk.Usage
	}

	// Convert standard chunk to legacy format
	legacyChunk := types.ChatCompletionChunk{
		Content: func() string {
			if len(chunk.Choices) > 0 {
				return chunk.Choices[0].Delta.Content
			}
			return ""
		}(),
		Done:    chunk.Done,
		ID:      chunk.ID,
		Model:   chunk.Model,
		Object:  chunk.Object,
		Created: chunk.Created,
		Choices: choices,
		Usage:   usage,
	}

	return legacyChunk, nil
}

// Close closes the stream
func (s *StandardToLegacyStreamAdapter) Close() error {
	return s.standardStream.Close()
}

// LegacyToStandardStreamAdapter converts legacy ChatCompletionStream to StandardStream
type LegacyToStandardStreamAdapter struct {
	legacyStream types.ChatCompletionStream
	providerName string
}

// Next returns the next chunk from the stream in Standard format
func (s *LegacyToStandardStreamAdapter) Next() (*types.StandardStreamChunk, error) {
	chunk, err := s.legacyStream.Next()
	if err != nil {
		return nil, err
	}

	var choices []types.StandardStreamChoice
	if len(chunk.Choices) > 0 {
		for _, choice := range chunk.Choices {
			standardChoice := types.StandardStreamChoice{
				Index: choice.Index,
				Delta: types.ChatMessage{
					Role:    choice.Delta.Role,
					Content: choice.Delta.Content,
				},
				FinishReason: choice.FinishReason,
			}

			// Copy tool calls if present
			if len(choice.Delta.ToolCalls) > 0 {
				standardChoice.Delta.ToolCalls = choice.Delta.ToolCalls
			}

			choices = append(choices, standardChoice)
		}
	} else {
		// Create empty choice if none exist
		choices = []types.StandardStreamChoice{{
			Index: 0,
			Delta: types.ChatMessage{
				Role:    "assistant",
				Content: chunk.Content,
			},
		}}
	}

	// Convert legacy chunk to standard format
	standardChunk := &types.StandardStreamChunk{
		Done:     chunk.Done,
		ID:       chunk.ID,
		Model:    chunk.Model,
		Object:   chunk.Object,
		Created:  chunk.Created,
		Choices:  choices,
		Usage:    &chunk.Usage,
		ProviderMetadata: map[string]interface{}{
			"provider": s.providerName,
		},
	}

	return standardChunk, nil
}

// Close closes the stream
func (s *LegacyToStandardStreamAdapter) Close() error {
	return s.legacyStream.Close()
}

// Done returns whether the stream is finished
func (s *LegacyToStandardStreamAdapter) Done() bool {
	// For legacy streams, we don't always have a reliable way to check if done
	// without calling Next(), so we'll return false and let Next() handle EOF
	return false
}