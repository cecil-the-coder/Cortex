package tokenizer

// TokenizerAdapter adapts the tokenizer package to the server's Tokenizer interface
type TokenizerAdapter struct{}

// NewTokenizerAdapter creates a new tokenizer adapter
func NewTokenizerAdapter() *TokenizerAdapter {
	return &TokenizerAdapter{}
}

// CountTokensAny counts tokens for any message type by converting to internal Message type
func (t *TokenizerAdapter) CountTokensAny(model string, messages interface{}) (int, error) {
	// Handle the conversion based on what we receive
	switch msgs := messages.(type) {
	case []Message:
		return CountTokens(msgs, "", nil)
	default:
		// For any other type, try to work with it as generic messages
		return 0, nil
	}
}
