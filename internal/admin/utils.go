package admin

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Global WebSocket hub instance
var wsHub *WebSocketHub
var wsHubOnce sync.Once

// getWebSocketHub returns the singleton WebSocket hub instance
func getWebSocketHub() *WebSocketHub {
	wsHubOnce.Do(func() {
		wsHub = NewWebSocketHub()
		wsHub.Start()
	})
	return wsHub
}

// generateRandomString generates a random string of specified length
func generateRandomString(length int) string {
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to time-based generation
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

// generateUUID generates a UUID v4 string (simplified version)
func generateUUID() string {
	// This is a simplified UUID generation for demonstration
	// In production, use a proper UUID library
	bytes := make([]byte, 16)
	rand.Read(bytes)

	// Set version (4) and variant bits
	bytes[6] = (bytes[6] & 0x0f) | 0x40 // Version 4
	bytes[8] = (bytes[8] & 0x3f) | 0x80 // Variant 10

	return fmt.Sprintf("%x-%x-%x-%x-%x", bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:16])
}

// generateAPIKey generates a secure API key
func generateAPIKey(prefix string) string {
	if prefix == "" {
		prefix = "sk"
	}

	// Generate 32 random bytes (256 bits)
	randomBytes := make([]byte, 32)
	rand.Read(randomBytes)

	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(randomBytes))
}

// parseDuration parses a duration string with fallback to seconds
func parseDuration(durationStr string) (time.Duration, error) {
	if durationStr == "" {
		return 0, nil
	}

	// Try to parse as time.Duration
	duration, err := time.ParseDuration(durationStr)
	if err == nil {
		return duration, nil
	}

	// Try to parse as seconds
	if seconds, err := strconv.ParseInt(durationStr, 10, 64); err == nil {
		return time.Duration(seconds) * time.Second, nil
	}

	return 0, fmt.Errorf("invalid duration format: %s", durationStr)
}

// sanitizeFilename sanitizes a string for use as a filename
func sanitizeFilename(filename string) string {
	// Replace undesirable characters with underscores
	replacements := map[string]string{
		"/": "_",
		"\\": "_",
		":": "_",
		"*": "_",
		"?": "_",
		"\"": "_",
		"<": "_",
		">": "_",
		"|": "_",
		" ": "_",
		"\t": "_",
		"\n": "_",
		"\r": "_",
	}

	result := filename
	for old, new := range replacements {
		result = strings.ReplaceAll(result, old, new)
	}

	// Remove consecutive underscores
	for strings.Contains(result, "__") {
		result = strings.ReplaceAll(result, "__", "_")
	}

	// Remove leading/trailing underscores
	result = strings.Trim(result, "_")

	// Limit length
	if len(result) > 100 {
		result = result[:100]
	}

	return result
}

// calculateChecksum calculates a simple checksum for data
func calculateChecksum(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// Simple hash using XOR of all bytes
	var checksum byte
	for _, b := range data {
		checksum ^= b
	}

	return fmt.Sprintf("%02x", checksum)
}

// formatBytes formats byte counts in human-readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// formatDuration formats duration in human-readable format
func formatDuration(duration time.Duration) string {
	if duration < time.Millisecond {
		return fmt.Sprintf("%.2f μs", float64(duration.Nanoseconds())/1000)
	}
	if duration < time.Second {
		return fmt.Sprintf("%.2f ms", float64(duration.Nanoseconds())/1000000)
	}
	if duration < time.Minute {
		return fmt.Sprintf("%.2f s", duration.Seconds())
	}
	if duration < time.Hour {
		return fmt.Sprintf("%.2f m", duration.Minutes())
	}
	return fmt.Sprintf("%.2f h", duration.Hours())
}

// validateEmail validates an email address format
func validateEmail(email string) bool {
	if len(email) < 3 || len(email) > 254 {
		return false
	}

	// Basic validation - in production use proper email validation
	at := strings.LastIndex(email, "@")
	if at <= 0 || at >= len(email)-1 {
		return false
	}

	dot := strings.LastIndex(email[at:], ".")
	if dot <= 0 || dot >= len(email[at:])-1 {
		return false
	}

	return true
}

// safeIntToString safely converts int to string
func safeIntToString(i int) string {
	if i == 0 {
		return "0"
	}
	return strconv.Itoa(i)
}

// safeFloatToString safely converts float to string with precision
func safeFloatToString(f float64, precision int) string {
	return fmt.Sprintf(fmt.Sprintf(".%df", precision), f)
}

// safeTimeToString safely converts time to string in consistent format
func safeTimeToString(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// filterEmptyStrings removes empty strings from a slice
func filterEmptyStrings(slice []string) []string {
	var result []string
	for _, s := range slice {
		if strings.TrimSpace(s) != "" {
			result = append(result, s)
		}
	}
	return result
}

// uniqueStrings removes duplicates from a string slice
func uniqueStrings(slice []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	return result
}

// containsString checks if a string slice contains a specific string
func containsString(slice []string, target string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}

// interpolateMap interpolates values in a map using environment variables
func interpolateMap(m map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	for key, value := range m {
		switch v := value.(type) {
		case string:
			result[key] = os.ExpandEnv(v)
		case map[string]interface{}:
			result[key] = interpolateMap(v)
		case []interface{}:
			var slice []interface{}
			for _, item := range v {
				if s, ok := item.(string); ok {
					slice = append(slice, os.ExpandEnv(s))
				} else {
					slice = append(slice, item)
				}
			}
			result[key] = slice
		default:
			result[key] = value
		}
	}

	return result
}

// deepCopyMap creates a deep copy of a map
func deepCopyMap(original map[string]interface{}) map[string]interface{} {
	copy := make(map[string]interface{})

	for key, value := range original {
		switch v := value.(type) {
		case map[string]interface{}:
			copy[key] = deepCopyMap(v)
		case []interface{}:
			var slice []interface{}
			for _, item := range v {
				if m, ok := item.(map[string]interface{}); ok {
					slice = append(slice, deepCopyMap(m))
				} else {
					slice = append(slice, item)
				}
			}
			copy[key] = slice
		default:
			copy[key] = value
		}
	}

	return copy
}

// mergeMaps merges two maps with the second map taking precedence
func mergeMaps(base, overlay map[string]interface{}) map[string]interface{} {
	result := deepCopyMap(base)

	for key, value := range overlay {
		if baseValue, exists := result[key]; exists {
			if baseMap, ok := baseValue.(map[string]interface{}); ok {
				if overlayMap, ok := value.(map[string]interface{}); ok {
					result[key] = mergeMaps(baseMap, overlayMap)
					continue
				}
			}
		}
		result[key] = value
	}

	return result
}

// mapKeysToSnakeCase converts map keys from camelCase to snake_case
func mapKeysToSnakeCase(m map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	for key, value := range m {
		snakeKey := camelToSnakeCase(key)
		result[snakeKey] = value
	}

	return result
}

// camelToSnakeCase converts camelCase to snake_case
func camelToSnakeCase(s string) string {
	var result []rune
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result = append(result, '_')
		}
		result = append(result, r)
	}
	return strings.ToLower(string(result))
}

// snakeCaseToCamel converts snake_case to camelCase
func snakeCaseToCamel(s string) string {
	parts := strings.Split(s, "_")
	for i := 1; i < len(parts); i++ {
		if len(parts[i]) > 0 {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return strings.Join(parts, "")
}

// validateJSONSchema validates data against a simple schema
func validateJSONSchema(data interface{}, schema map[string]interface{}) error {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return fmt.Errorf("data must be an object")
	}

	for key, schemaDef := range schema {
		if required, ok := schemaDef.(map[string]interface{})["required"].(bool); ok && required {
			if _, exists := dataMap[key]; !exists {
				return fmt.Errorf("required field '%s' is missing", key)
			}
		}

		if valueType, ok := schemaDef.(map[string]interface{})["type"].(string); ok {
			if value := dataMap[key]; value != nil {
				switch valueType {
				case "string":
					if _, ok := value.(string); !ok {
						return fmt.Errorf("field '%s' must be a string", key)
					}
				case "number":
					_, isFloat64 := value.(float64)
					_, isInt := value.(int)
					if !isFloat64 && !isInt {
						return fmt.Errorf("field '%s' must be a number", key)
					}
				case "boolean":
					if _, ok := value.(bool); !ok {
						return fmt.Errorf("field '%s' must be a boolean", key)
					}
				case "array":
					if _, ok := value.([]interface{}); !ok {
						return fmt.Errorf("field '%s' must be an array", key)
					}
				case "object":
					if _, ok := value.(map[string]interface{}); !ok {
						return fmt.Errorf("field '%s' must be an object", key)
					}
				}
			}
		}
	}

	return nil
}

// getSystemInfo returns basic system information
func getSystemInfo() map[string]interface{} {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return map[string]interface{}{
		"go_version":      runtime.Version(),
		"os":             runtime.GOOS,
		"arch":           runtime.GOARCH,
		"num_cpu":        runtime.NumCPU(),
		"num_goroutines": runtime.NumGoroutine(),
		"mem_alloc":      m.Alloc,
		"mem_total_alloc": m.TotalAlloc,
		"mem_sys":        m.Sys,
		"num_gc":         m.NumGC,
		"uptime":         time.Since(time.Now()), // Would track actual start time
	}
}