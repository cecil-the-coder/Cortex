# Vision Routing Configuration Guide

This guide demonstrates how to configure and use the vision routing capabilities of the Cortex to automatically route requests containing images to vision-capable models.

## Overview

Vision routing automatically detects when requests contain image content and routes them to a designated vision provider, ensuring that image processing requests are handled by models that support vision capabilities.

## Key Features

- **Automatic Detection**: Scans incoming requests for image content
- **Priority-based Routing**: Vision routing has configurable priority in the routing pipeline
- **Provider Flexibility**: Configure any vision-capable provider as the vision router
- **Model Registry**: Built-in registry tracks which models support vision
- **Configuration Examples**: Pre-built configurations for common scenarios

## Configuration

### Basic Setup

Add the vision routing configuration to your `config.json`:

```json
{
  "Router": {
    "default": "anthropic",
    "background": "openai",
    "think": "anthropic",
    "longContext": "anthropic",
    "webSearch": "openai",
    "vision": "openai",  // <-- Vision provider
    "longContextThreshold": 100000
  }
}
```

### Providers with Vision Support

The following providers have models that support vision:

- **OpenAI**: `gpt-4o`, `gpt-4o-mini`, `gpt-4-vision-preview`
- **Anthropic**: All Claude 3 models (`claude-3-5-sonnet`, `claude-3-opus`, `claude-3-haiku`)
- **Google**: `gemini-1.5-pro`, `gemini-1.5-flash`, `gemini-pro-vision`

### Vision Routing Priority

Vision routing follows this priority order:

1. Explicit model override (`provider,model` format)
2. Long context detection
3. Subagent model specification
4. Claude Haiku variant detection
5. **Vision content detection** ← *Images are detected here*
6. Web search tool detection
7. Thinking mode flag detection
8. Default routing

## Usage Examples

### Example 1: Text-Only Request

```json
{
  "model": "claude-sonnet",
  "max_tokens": 1000,
  "messages": [
    {
      "role": "user",
      "content": "Explain the principles of machine learning."
    }
  ]
}
```

**Result**: Routes to default provider (anthropic)

### Example 2: Vision Request

```json
{
  "model": "claude-sonnet",
  "max_tokens": 1000,
  "messages": [
    {
      "role": "user",
      "content": [
        {
          "type": "text",
          "text": "What do you see in this image?"
        },
        {
          "type": "image",
          "source": {
            "type": "base64",
            "media_type": "image/jpeg",
            "data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB..."
          }
        }
      ]
    }
  ]
}
```

**Result**: Routes to vision provider (openai)

### Example 3: Mixed Conversation

```json
{
  "model": "gpt4o",
  "max_tokens": 1000,
  "messages": [
    {
      "role": "user",
      "content": "Can you explain quantum computing?"
    },
    {
      "role": "assistant",
      "content": "Quantum computing is a revolutionary..."
    },
    {
      "role": "user",
      "content": [
        {
          "type": "text",
          "text": "Now analyze this circuit diagram:"
        },
        {
          "type": "image",
          "source": {
            "type": "base64",
            "media_type": "image/png",
            "data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB..."
          }
        }
      ]
    }
  ]
}
```

**Result**: Routes to vision provider because the last message contains an image

### Example 4: OpenAI API Format (Chat Completions)

```json
{
  "model": "gpt-4o",
  "max_tokens": 1000,
  "messages": [
    {
      "role": "user",
      "content": [
        {
          "type": "text",
          "text": "What do you see in this image?"
        },
        {
          "type": "image_url",
          "image_url": {
            "url": "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/"
          }
        }
      ]
    }
  ]
}
```

**Result**: Routes to vision provider because the OpenAI `image_url` format is detected

### Example 5: OpenAI API with Mixed Formats

```json
{
  "model": "gpt-4o-mini",
  "max_tokens": 1000,
  "messages": [
    {
      "role": "user",
      "content": "Hello, can you help me?"
    },
    {
      "role": "assistant",
      "content": "I'd be happy to help! What can I assist you with?"
    },
    {
      "role": "user",
      "content": [
        {
          "type": "text",
          "text": "Please analyze this chart:"
        },
        {
          "type": "image_url",
          "image_url": {
            "url": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
          }
        }
      ]
    }
  ]
}
```

**Result**: Routes to vision provider because the last message contains an OpenAI image URL

## Configuration Examples

### Complete Vision Configuration

See [`vision-routing-config.json`](./vision-routing-config.json) for a complete example with:

- Multiple vision-capable providers
- Vision-specific model groups
- Different access levels for vision vs text-only applications
- Production-ready client API keys

### Vision Model Groups

```json
{
  "ModelGroups": {
    "vision-models": {
      "description": "Vision-capable models for image processing",
      "models": [
        {
          "provider": "openai",
          "model": "gpt-4o",
          "alias": "vision-best"
        },
        {
          "provider": "anthropic",
          "model": "claude-3-5-sonnet-20241022",
          "alias": "vision-claude"
        }
      ]
    },
    "vision-economy": {
      "description": "Cost-effective vision models",
      "models": [
        {
          "provider": "openai",
          "model": "gpt-4o-mini",
          "alias": "vision-fast"
        }
      ]
    }
  }
}
```

### Client API Keys for Vision

```json
{
  "ClientAPIKeys": {
    "vision-app": {
      "apiKey": "sk-vision-app-key",
      "description": "Vision application access",
      "modelGroups": ["vision-models", "production"],
      "enabled": true,
      "rateLimit": 500
    },
    "text-only-app": {
      "apiKey": "sk-text-only-key",
      "description": "Text-only application (no vision)",
      "modelGroups": ["production"], // Excludes vision groups
      "enabled": true,
      "rateLimit": 1500
    }
  }
}
```

## Model Registry

The system includes a comprehensive model registry that tracks vision capabilities:

```go
// Check if a model supports vision
registry := config.GetGlobalContextRegistry()
supportsVision := registry.SupportsVision("claude-3-5-sonnet-20241022") // true
supportsVision := registry.SupportsVision("gpt-4") // false

// Get all vision models
visionModels := registry.GetVisionModels()
for _, model := range visionModels {
    fmt.Printf("%s from %s supports vision\n", model.ModelName, model.Provider)
}
```

## Running the Examples

### Start the Router

```bash
# Using the vision configuration
./router -config examples/vision-routing-config.json
```

### Test Vision Routing

```bash
# Run the vision usage example
go run examples/vision-usage.go
```

### API Testing

```bash
# Text-only request (routes to default)
curl -X POST http://localhost:8080/v1/messages \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ROUTER_API_KEY" \
  -d '{
    "model": "claude-sonnet",
    "max_tokens": 100,
    "messages": [{"role": "user", "content": "Hello!"}]
  }'

# Vision request (routes to vision provider)
curl -X POST http://localhost:8080/v1/messages \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ROUTER_API_KEY" \
  -d '{
    "model": "claude-sonnet",
    "max_tokens": 100,
    "messages": [{
      "role": "user",
      "content": [
        {"type": "text", "text": "What do you see?"},
        {"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": "..."}}
      ]
    }]
  }'
```

## Best Practices

1. **Provider Selection**: Choose your most reliable vision-capable provider for the vision router
2. **Model Groups**: Create separate groups for vision vs text-only models
3. **Access Control**: Use client API keys to restrict vision access to authorized applications
4. **Rate Limiting**: Set appropriate rate limits for vision requests (they're more resource-intensive)
5. **Monitoring**: Monitor routing decisions in logs to ensure proper vision routing

## Troubleshooting

### Vision requests not routing correctly

1. Check that the vision provider is configured in the router config
2. Verify the provider has vision-capable models in its model list
3. Ensure image content is properly formatted with type "image" and valid source data
4. Check logs for routing decisions and any error messages

### Model doesn't support vision

The model registry includes built-in vision capability tracking. If a model should support vision but isn't recognized:

1. Check if the model name matches the registry exactly
2. Verify the model is registered with `supportsVision: true`
3. Use `registry.SupportsVision("model-name")` to check capability

## Supported Image Formats

The vision routing accepts multiple image format standards:

### Anthropic Format
- **Media Types**: `image/jpeg`, `image/png`, `image/gif`, `image/webp`
- **Encoding**: Base64 encoded data
- **Source Type**: Must be `"base64"`

### OpenAI Format
- **Media Types**: `image/jpeg`, `image/png`, `image/gif`, `image/webp`
- **Encoding**: Base64 encoded data URLs
- **Type**: `"image_url"` with `"url"` field containing data URL
- **Format**: `data:image/[media_type];base64,[data]`

### Format Examples

**Anthropic Format:**
```json
{
  "type": "image",
  "source": {
    "type": "base64",
    "media_type": "image/jpeg",
    "data": "base64-data-here"
  }
}
```

**OpenAI Format:**
```json
{
  "type": "image_url",
  "image_url": {
    "url": "data:image/jpeg;base64,base64-data-here"
  }
}
```

### Validation

Images are validated to ensure they contain:

**For Anthropic format:**
- A proper type field set to "image"
- Valid source with type, media_type, and data fields
- Base64 encoded image data
- Source type must be "base64"
- Media type must start with "image/"

**For OpenAI format:**
- A proper type field set to "image_url"
- Valid image_url with url field
- URL must be a data URL starting with "data:image/"
- Valid base64 encoded image data

## Advanced Features

### Vision Model Group Creation

```go
registry := config.GetGlobalContextRegistry()

// Create vision model group for specific providers
visionGroup := registry.CreateVisionModelGroup(
    []string{"openai", "anthropic"}, // Only these providers
    "my-vision-models",
)

// Create vision model group for all vision-capable models
allVisionGroup := registry.CreateVisionModelGroup(
    []string{}, // Empty = all providers
    "all-vision-models",
)
```

### Runtime Vision Capability Checks

```go
// Check if current model supports vision
if registry.SupportsVision(requestedModel) {
    // Allow image content
} else {
    // Reject image content with helpful error
}
```

This comprehensive vision routing system ensures your applications can seamlessly handle both text and vision requests with automatic, intelligent routing to the most appropriate models.