package authentication

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"image/png"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
)

// TFAManager handles two-factor authentication
type TFAManager struct {
	issuer string
	window time.Duration
	// In a real implementation, this would be a repository interface
	// For now, we'll keep it simple without database dependency
}

// TFASetup contains TFA setup information
type TFASetup struct {
	Secret     string                 `json:"secret"`
	QRCode     string                 `json:"qr_code"`
	BackupCodes []string               `json:"backup_codes"`
	Method     string                 `json:"method"`
	Enabled    bool                   `json:"enabled"`
	Config     map[string]interface{} `json:"config,omitempty"`
}

// TFAValidation contains TFA validation result
type TFAValidation struct {
	Valid      bool     `json:"valid"`
	Expired    bool     `json:"expired"`
	Attempts   int      `json:"attempts"`
	Remaining  int      `json:"remaining"`
	Method     string   `json:"method"`
	LastUsed   *time.Time `json:"last_used,omitempty"`
}

// TFAMethod represents a TFA method configuration
type TFAMethod struct {
	Type        string                 `json:"type"`        // "totp", "sms", "email", "push"
	Enabled     bool                   `json:"enabled"`
	Config      map[string]interface{} `json:"config"`
	Verified    bool                   `json:"verified"`
	LastUsed    *time.Time             `json:"last_used,omitempty"`
	FailureCount int                   `json:"failure_count"`
	LockedUntil *time.Time             `json:"locked_until,omitempty"`
}

// NewTFAManager creates a new TFA manager
func NewTFAManager(issuer string, window time.Duration) *TFAManager {
	if issuer == "" {
		issuer = "Cortex"
	}
	if window == 0 {
		window = 2 * time.Minute
	}

	return &TFAManager{
		issuer: issuer,
		window: window,
	}
}

// GenerateSecret generates a new TOTP secret
func (tm *TFAManager) GenerateSecret() (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      tm.issuer,
		SecretSize:  32,
		Period:      30, // 30 seconds
		Digits:      6,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	return key.Secret(), nil
}

// GenerateQRCode generates a QR code for the TOTP secret
func (tm *TFAManager) GenerateQRCode(username, secret string) (string, error) {
	key, err := otp.NewKeyFromURL(fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		tm.issuer, username, secret, tm.issuer))
	if err != nil {
		return "", fmt.Errorf("failed to create OTP key: %w", err)
	}

	// Generate QR code
	qrCode, err := qr.Encode(key.String(), qr.M, qr.Auto)
	if err != nil {
		return "", fmt.Errorf("failed to generate QR code: %w", err)
	}

	// Scale the QR code
	qrCode, err = barcode.Scale(qrCode, 256, 256)
	if err != nil {
		return "", fmt.Errorf("failed to scale QR code: %w", err)
	}

	// Convert to base64 image
	var buf []byte
	if err := png.Encode(bufferWriter{&buf}, qrCode); err != nil {
		return "", fmt.Errorf("failed to encode QR code: %w", err)
	}

	base64QR := base64.StdEncoding.EncodeToString(buf)
	return fmt.Sprintf("data:image/png;base64,%s", base64QR), nil
}

// ValidateCode validates a TOTP code
func (tm *TFAManager) ValidateCode(secret, code string) bool {
	valid := totp.Validate(code, secret)
	return valid
}

// ValidateCodeWithWindow validates a TOTP code with time window
func (tm *TFAManager) ValidateCodeWithWindow(secret, code string) bool {
	// Use standard validation with time window tolerance
	valid := totp.Validate(code, secret)
	return valid
}

// GenerateBackupCodes generates backup codes for TFA
func (tm *TFAManager) GenerateBackupCodes(count int) ([]string, error) {
	codes := make([]string, count)

	for i := 0; i < count; i++ {
		// Generate 8-character backup code
		bytes := make([]byte, 5)
		if _, err := rand.Read(bytes); err != nil {
			return nil, fmt.Errorf("failed to generate backup code: %w", err)
		}

		code := strings.ToUpper(base32.StdEncoding.EncodeToString(bytes)[:8])
		// Format with hyphen for readability: XXXX-XXXX
		if len(code) >= 8 {
			code = code[:4] + "-" + code[4:]
		}
		codes[i] = code
	}

	return codes, nil
}

// GenerateBackupCodeHash creates a hash of backup codes for storage
func (tm *TFAManager) GenerateBackupCodeHash(codes []string) ([]string, error) {
	hashes := make([]string, len(codes))
	passwordManager := NewPasswordManager(nil)

	for i, code := range codes {
		hash, err := passwordManager.HashPassword(code)
		if err != nil {
			return nil, fmt.Errorf("failed to hash backup code: %w", err)
		}
		hashes[i] = hash
	}

	return hashes, nil
}

// ValidateBackupCode validates a backup code against stored hashes
func (tm *TFAManager) ValidateBackupCode(code string, hashedCodes []string) (bool, int, error) {
	passwordManager := NewPasswordManager(nil)

	for i, hash := range hashedCodes {
		if passwordManager.ValidatePassword(hash, code) {
			return true, i, nil
		}
	}

	return false, -1, nil
}

// SetupTFA sets up TFA for a user
func (tm *TFAManager) SetupTFA(username string) (*TFASetup, error) {
	// Generate secret
	secret, err := tm.GenerateSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate secret: %w", err)
	}

	// Generate QR code
	qrCode, err := tm.GenerateQRCode(username, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to generate QR code: %w", err)
	}

	// Generate backup codes
	backupCodes, err := tm.GenerateBackupCodes(10)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	return &TFASetup{
		Secret:     secret,
		QRCode:     qrCode,
		BackupCodes: backupCodes,
		Method:     "totp",
		Enabled:    false,
	}, nil
}

// EnableTFA enables TFA for a user after verification
func (tm *TFAManager) EnableTFA(userID int64, secret string, backupCodes []string) error {
	// In a real implementation, this would store the secret and hashed backup codes
	// in the database for the user

	_, err := tm.GenerateBackupCodeHash(backupCodes)
	if err != nil {
		return fmt.Errorf("failed to hash backup codes: %w", err)
	}

	// Store in database (placeholder)
	// err = tm.tfaRepo.StoreTFASecret(userID, secret, hashedBackupCodes)

	return nil
}

// DisableTFA disables TFA for a user
func (tm *TFAManager) DisableTFA(userID int64) error {
	// Remove TFA secret and backup codes from database
	// return tm.tfaRepo.RemoveTFASecret(userID)
	return nil
}

// ValidateUserTFA validates TFA for a user
func (tm *TFAManager) ValidateUserTFA(userID int64, code string) (*TFAValidation, error) {
	// Get user's TFA secret from database
	secret, backupCodes, err := tm.getUserTFASecret(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get TFA secrets: %w", err)
	}

	if secret == "" {
		return &TFAValidation{
			Valid:     false,
			Expired:   false,
			Attempts:  0,
			Remaining: 0,
			Method:    "totp",
		}, nil
	}

	validation := &TFAValidation{
		Valid:     false,
		Expired:   false,
		Attempts:  0,
		Remaining: 3,
		Method:    "totp",
	}

	// Check if method is locked
	// locked, lockedUntil, err := tm.tfaRepo.IsTFALocked(userID)
	// if err != nil {
	//     return nil, err
	// }
	// if locked && time.Now().Before(lockedUntil) {
	//     validation.LockedUntil = &lockedUntil
	//     return validation, nil
	// }

	// Try TOTP validation first
	if tm.ValidateCodeWithWindow(secret, code) {
		validation.Valid = true
		validation.LastUsed = &[]time.Time{time.Now()}[0]

		// Update last used timestamp
		// tm.tfaRepo.UpdateTFALastUsed(userID)

		// Reset failure count
		// tm.tfaRepo.ResetTFAFailures(userID)

		return validation, nil
	}

	// Try backup code validation
	valid, _, err := tm.ValidateBackupCode(code, backupCodes)
	if err != nil {
		return nil, fmt.Errorf("failed to validate backup code: %w", err)
	}

	if valid {
		validation.Valid = true
		validation.Method = "backup_code"
		validation.LastUsed = &[]time.Time{time.Now()}[0]

		// Remove used backup code
		// newBackupCodes := append(backupCodes[:index], backupCodes[index+1:]...)
		// tm.tfaRepo.UpdateBackupCodes(userID, newBackupCodes)

		return validation, nil
	}

	// Increment failure count
	// failures, locked, lockedUntil, err := tm.tfaRepo.IncrementTFAFailure(userID)
	// if err != nil {
	//     return nil, err
	// }

	// validation.Attempts = failures
	// validation.Remaining = max(0, 3-failures)
	//
	// if locked {
	//     validation.LockedUntil = &lockedUntil
	// }

	return validation, nil
}

// GenerateSMSCode generates an SMS verification code
func (tm *TFAManager) GenerateSMSCode() (string, error) {
	// Generate 6-digit code
	bytes := make([]byte, 3)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate SMS code: %w", err)
	}

	code := fmt.Sprintf("%06d", int(bytes[0])<<16|int(bytes[1])<<8|int(bytes[2]))
	return code, nil
}

// SendSMSCode sends an SMS code (placeholder implementation)
func (tm *TFAManager) SendSMSCode(phoneNumber, code string) error {
	// In a real implementation, this would integrate with an SMS service
	// For now, we'll just log it
	fmt.Printf("SMS Code for %s: %s\n", phoneNumber, code)
	return nil
}

// GenerateEmailCode generates an email verification code
func (tm *TFAManager) GenerateEmailCode() (string, error) {
	return tm.GenerateSMSCode() // Same format as SMS code
}

// SendEmailCode sends an email code (placeholder implementation)
func (tm *TFAManager) SendEmailCode(email, code string) error {
	// In a real implementation, this would integrate with an email service
	fmt.Printf("Email Code for %s: %s\n", email, code)
	return nil
}

// SetupTFAForUser sets up TFA for a specific user with the specified method
func (tm *TFAManager) SetupTFAForUser(userID int64, username, method string, config map[string]interface{}) (*TFASetup, error) {
	switch method {
	case "totp":
		return tm.SetupTFA(username)
	case "sms":
		phone, ok := config["phone"].(string)
		if !ok || phone == "" {
			return nil, fmt.Errorf("phone number is required for SMS TFA")
		}

		code, err := tm.GenerateSMSCode()
		if err != nil {
			return nil, fmt.Errorf("failed to generate SMS code: %w", err)
		}

		if err := tm.SendSMSCode(phone, code); err != nil {
			return nil, fmt.Errorf("failed to send SMS code: %w", err)
		}

		return &TFASetup{
			Method:  "sms",
			Enabled: false,
			Config: map[string]interface{}{
				"phone": phone,
				"code_sent": true,
			},
		}, nil

	case "email":
		email, ok := config["email"].(string)
		if !ok || email == "" {
			return nil, fmt.Errorf("email is required for email TFA")
		}

		code, err := tm.GenerateEmailCode()
		if err != nil {
			return nil, fmt.Errorf("failed to generate email code: %w", err)
		}

		if err := tm.SendEmailCode(email, code); err != nil {
			return nil, fmt.Errorf("failed to send email code: %w", err)
		}

		return &TFASetup{
			Method:  "email",
			Enabled: false,
			Config: map[string]interface{}{
				"email": email,
				"code_sent": true,
			},
		}, nil

	default:
		return nil, fmt.Errorf("unsupported TFA method: %s", method)
	}
}

// EnableTFAForUser enables TFA for a user with verification
func (tm *TFAManager) EnableTFAForUser(userID int64, username, method string, verificationCode string, config map[string]interface{}) error {
	switch method {
	case "totp":
		// Verify TOTP code against generated secret
		secret, ok := config["secret"].(string)
		if !ok || secret == "" {
			return fmt.Errorf("secret is required for TOTP verification")
		}

		if !tm.ValidateCode(secret, verificationCode) {
			return fmt.Errorf("invalid TOTP code")
		}

		// Generate backup codes
		backupCodes, err := tm.GenerateBackupCodes(10)
		if err != nil {
			return fmt.Errorf("failed to generate backup codes: %w", err)
		}

		return tm.EnableTFA(userID, secret, backupCodes)

	case "sms", "email":
		// Verify the verification code that was sent
		// This would involve checking the temporary code stored in Redis or database
		return fmt.Errorf("%s TFA verification not implemented", method)

	default:
		return fmt.Errorf("unsupported TFA method: %s", method)
	}
}

// getUserTFASecret retrieves user's TFA secret from database (placeholder)
func (tm *TFAManager) getUserTFASecret(userID int64) (string, []string, error) {
	// In a real implementation, this would query the database
	// For now, return empty values
	return "", make([]string, 0), nil
}

// bufferWriter is a simple writer that appends to a byte slice
type bufferWriter struct {
	buf *[]byte
}

func (bw bufferWriter) Write(p []byte) (n int, err error) {
	*bw.buf = append(*bw.buf, p...)
	return len(p), nil
}

// TFAStatus represents the TFA status for a user
type TFAStatus struct {
	Enabled      bool        `json:"enabled"`
	Methods      []*TFAMethod `json:"methods"`
	PrimaryMethod string      `json:"primary_method"`
	BackupCodes   int         `json:"backup_codes_remaining"`
	LastUsed      *time.Time  `json:"last_used,omitempty"`
}

// GetUserTFAStatus gets the TFA status for a user
func (tm *TFAManager) GetUserTFAStatus(userID int64) (*TFAStatus, error) {
	// In a real implementation, this would query the database
	return &TFAStatus{
		Enabled:        false,
		Methods:        []*TFAMethod{},
		PrimaryMethod:  "",
		BackupCodes: 0,
	}, nil
}

// RegenerateBackupCodes regenerates backup codes for a user
func (tm *TFAManager) RegenerateBackupCodes(userID int64) ([]string, error) {
	codes, err := tm.GenerateBackupCodes(10)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Hash and store in database
	_, err = tm.GenerateBackupCodeHash(codes)
	if err != nil {
		return nil, fmt.Errorf("failed to hash backup codes: %w", err)
	}

	// Store in database
	// err = tm.tfaRepo.UpdateBackupCodes(userID, hashedCodes)

	return codes, nil
}