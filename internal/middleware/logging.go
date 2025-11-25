package middleware

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// LogConfig holds logging configuration
type LogConfig struct {
	LogToFile      bool
	LogDirectory   string
	MaxFileSize    int64 // in bytes
	MaxBackups     int
	EnableRotation bool
}

// Logger wraps multiple writers for logging
type Logger struct {
	mu      sync.Mutex
	writers []io.Writer
	config  *LogConfig

	currentFile *os.File
	currentSize int64
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	bytes      int
}

// WriteHeader captures the status code
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Write captures the response size
func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytes += n
	return n, err
}

// NewLogger creates a new Logger instance
func NewLogger(config *LogConfig) (*Logger, error) {
	if config == nil {
		config = &LogConfig{
			LogToFile:      false,
			LogDirectory:   "logs",
			MaxFileSize:    100 * 1024 * 1024, // 100MB
			MaxBackups:     5,
			EnableRotation: true,
		}
	}

	logger := &Logger{
		config:  config,
		writers: []io.Writer{os.Stdout},
	}

	// Setup file logging if enabled
	if config.LogToFile {
		if err := logger.setupFileLogging(); err != nil {
			return nil, fmt.Errorf("failed to setup file logging: %w", err)
		}
	}

	return logger, nil
}

// setupFileLogging configures file-based logging
func (l *Logger) setupFileLogging() error {
	// Create log directory if it doesn't exist
	if err := os.MkdirAll(l.config.LogDirectory, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Open log file
	filename := filepath.Join(l.config.LogDirectory, fmt.Sprintf("server-%s.log",
		time.Now().Format("2006-01-02")))

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	// Get current file size
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return fmt.Errorf("failed to stat log file: %w", err)
	}

	l.currentFile = file
	l.currentSize = info.Size()
	l.writers = append(l.writers, file)

	return nil
}

// Write implements io.Writer
func (l *Logger) Write(p []byte) (n int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Check if rotation is needed
	if l.config.EnableRotation && l.config.LogToFile && l.currentFile != nil {
		l.currentSize += int64(len(p))
		if l.currentSize > l.config.MaxFileSize {
			if err := l.rotate(); err != nil {
				log.Printf("Failed to rotate log file: %v", err)
			}
		}
	}

	// Write to all writers
	for _, w := range l.writers {
		n, err = w.Write(p)
		if err != nil {
			return n, err
		}
	}

	return n, nil
}

// rotate rotates the log file
func (l *Logger) rotate() error {
	// Close current file
	if l.currentFile != nil {
		l.currentFile.Close()
	}

	// Rename existing files
	baseFilename := filepath.Join(l.config.LogDirectory, fmt.Sprintf("server-%s.log",
		time.Now().Format("2006-01-02")))

	// Delete oldest backup if we exceed max backups
	oldestBackup := fmt.Sprintf("%s.%d", baseFilename, l.config.MaxBackups)
	os.Remove(oldestBackup) // Ignore error - file might not exist

	// Rotate existing backups
	for i := l.config.MaxBackups - 1; i > 0; i-- {
		oldName := fmt.Sprintf("%s.%d", baseFilename, i)
		newName := fmt.Sprintf("%s.%d", baseFilename, i+1)
		if err := os.Rename(oldName, newName); err != nil {
			// Ignore errors - files might not exist, continue with rotation
			continue
		}
	}

	// Rotate current file to .1
	if err := os.Rename(baseFilename, fmt.Sprintf("%s.1", baseFilename)); err != nil {
		// If rename fails, the file might not exist or be locked
		return err
	}

	// Open new file
	file, err := os.OpenFile(baseFilename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	l.currentFile = file
	l.currentSize = 0

	// Update writers
	l.writers = []io.Writer{os.Stdout, file}

	return nil
}

// Close closes the logger
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.currentFile != nil {
		return l.currentFile.Close()
	}

	return nil
}

// LoggingMiddleware creates a logging middleware
func LoggingMiddleware(logger *Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger, _ = NewLogger(nil)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Create response writer wrapper
			rw := &responseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			// Log request
			logEntry := fmt.Sprintf("[%s] --> %s %s %s",
				start.Format("2006-01-02 15:04:05"),
				r.Method,
				r.URL.Path,
				r.RemoteAddr,
			)
			if _, err := logger.Write([]byte(logEntry + "\n")); err != nil {
				// Ignore write errors for logging middleware to avoid breaking the flow
				return
			}

			// Call next handler
			next.ServeHTTP(rw, r)

			// Log response
			duration := time.Since(start)
			logEntry = fmt.Sprintf("[%s] <-- %s %s %d %d bytes %s",
				time.Now().Format("2006-01-02 15:04:05"),
				r.Method,
				r.URL.Path,
				rw.statusCode,
				rw.bytes,
				duration,
			)
			if _, err := logger.Write([]byte(logEntry + "\n")); err != nil {
				// Ignore write errors for logging middleware to avoid breaking the flow
				return
			}
		})
	}
}

// RecoveryMiddleware creates a panic recovery middleware
func RecoveryMiddleware(logger *Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger, _ = NewLogger(nil)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					logEntry := fmt.Sprintf("[%s] PANIC: %v\n",
						time.Now().Format("2006-01-02 15:04:05"),
						err,
					)
					if _, err := logger.Write([]byte(logEntry)); err != nil {
						// Ignore write errors during panic recovery
						return
					}

					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					if _, err := w.Write([]byte(`{"type":"internal_error","message":"Internal server error"}`)); err != nil {
						// If we can't write the error response, there's not much we can do
						return
					}
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}
