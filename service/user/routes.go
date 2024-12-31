package user

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"gopkg.in/gomail.v2"

	"github.com/GetStream/stream-chat-go/v5"
	"github.com/KAsare1/Kodefx-server/cmd/models"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type Handler struct {
	db *gorm.DB
}

func NewHandler(db *gorm.DB) *Handler {
	return &Handler{db: db}
}




// RegisterRoutes sets up all user-related routes
func (h *Handler) RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/login", h.handleLogin).Methods("POST")
	router.HandleFunc("/register", h.HandleRegister).Methods("POST")
	router.HandleFunc("/users", h.GetUsers).Methods("GET")
	router.HandleFunc("/users/{id}", h.GetUser).Methods("GET")
	router.HandleFunc("/users/{id}", h.UpdateUser).Methods("PUT")
	router.HandleFunc("/users/{id}", h.DeleteUser).Methods("DELETE")
	router.HandleFunc("/user/verify", h.verifyUser).Methods("POST")
	router.HandleFunc("/refresh", h.handleRefreshToken).Methods("POST")
    router.HandleFunc("/reset-password", h.handlePasswordResetRequest).Methods("POST")
    router.HandleFunc("/reset-password/{userId}/confirm", h.handlePasswordReset).Methods("POST")
	router.HandleFunc("/verify-reset-token", h.handleVerifyResetToken).Methods("POST")
	router.HandleFunc("/experts", h.GetExperts).Methods("GET")
	router.HandleFunc("/experts/{id}", h.GetExpert).Methods("GET")
	router.HandleFunc("/experts/{id}", h.UpdateExpert).Methods("PUT")
	router.HandleFunc("/experts/verify/{id}", h.VerifyExpert).Methods("POST")
	router.HandleFunc("/experts/search", h.SearchExperts).Methods("GET")
	router.HandleFunc("/experts/expertise/{expertise}", h.GetExpertsByExpertise).Methods("GET")
    router.HandleFunc("/images/{filename}", h.ServeImage).Methods("GET")
    router.HandleFunc("/certifications/{filename}", h.ServeCertification).Methods("GET")

    fileServer := http.FileServer(http.Dir("uploads/images"))
    router.PathPrefix("/images/").Handler(http.StripPrefix("/images/", fileServer))

}


func (h *Handler) ServeImage(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    filename := vars["filename"]

    // Basic security check for directory traversal
    if containsDotDot(filename) {
        http.Error(w, "Invalid path", http.StatusBadRequest)
        return
    }

    // Construct the full path
    imagePath := filepath.Join("uploads/images", filepath.Clean(filename))

    // Check if file exists
    if _, err := os.Stat(imagePath); os.IsNotExist(err) {
        http.Error(w, "Image not found", http.StatusNotFound)
        return
    }

    // Set headers
    w.Header().Set("Cache-Control", "public, max-age=3600")
    w.Header().Set("Content-Type", getContentType(imagePath))

    // Serve the file
    http.ServeFile(w, r, imagePath)
}

func containsDotDot(v string) bool {
    if !filepath.IsAbs(v) {
        v = filepath.Clean(filepath.Join("/", v))
    }
    return filepath.Clean(v) != v
}

func (h *Handler) ServeCertification(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    filename := vars["filename"]

    if containsDotDot(filename) {
        http.Error(w, "Invalid path", http.StatusBadRequest)
        return
    }

    certPath := filepath.Join("uploads/certifications", filepath.Clean(filename))
    serveFile(w, r, certPath, false)
}


func serveFile(w http.ResponseWriter, r *http.Request, filepath string, isImage bool) {
    // Check if file exists
    if _, err := os.Stat(filepath); os.IsNotExist(err) {
        http.Error(w, "File not found", http.StatusNotFound)
        return
    }

    // Set appropriate headers based on file type
    if isImage {
        w.Header().Set("Cache-Control", "public, max-age=3600")
        w.Header().Set("Content-Type", getContentType(filepath))
    } else {
        // For certifications (typically PDFs)
        w.Header().Set("Content-Type", "application/pdf")
        // Optional: force download instead of displaying in browser
        w.Header().Set("Content-Disposition", "attachment")
    }

    http.ServeFile(w, r, filepath)
}




// Helper function to determine content type
func getContentType(filename string) string {
    ext := filepath.Ext(filename)
    switch ext {
    case ".jpg", ".jpeg":
        return "image/jpeg"
    case ".png":
        return "image/png"
    case ".gif":
        return "image/gif"
    case ".webp":
        return "image/webp"
    default:
        return "application/octet-stream"
    }
}


func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
    var loginRequest struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }

    if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    var user models.User
    result := h.db.Where("email = ?", loginRequest.Email).First(&user)
    if result.Error != nil {
        http.Error(w, "User not found", http.StatusUnauthorized)
        return
    }

    // Verify password
    if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(loginRequest.Password)); err != nil {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    // Generate Access Token for your API
    accessToken, err := generateJWT(user.ID, 7500) 
    if err != nil {
        http.Error(w, "Error generating access token", http.StatusInternalServerError)
        return
    }

    // Generate Refresh Token
    refreshToken, err := generateRefreshToken(user.ID)
    if err != nil {
        http.Error(w, "Error generating refresh token", http.StatusInternalServerError)
        return
    }

    // Save Refresh Token to Database (optional for invalidation purposes)
    err = saveRefreshToken(h.db, user.ID, refreshToken)
    if err != nil {
        http.Error(w, "Error saving refresh token", http.StatusInternalServerError)
        return
    }

    // Initialize Stream Chat Client
    API_KEY := os.Getenv("STREAM_API_KEY")
    API_SECRET := os.Getenv("STREAM_API_SECRET")
    streamClient, err := stream_chat.NewClient(API_KEY, API_SECRET)
    if err != nil {
        http.Error(w, "Error initializing Stream client", http.StatusInternalServerError)
        return
    }

    // Convert user.ID to string
    userIDStr := fmt.Sprintf("%d", user.ID)

    // Generate a Stream Chat token
    streamToken, err := streamClient.CreateToken(userIDStr, time.Now().Add(time.Hour * 24 * 365)) 
    if err != nil {
        http.Error(w, "Error generating Stream token", http.StatusInternalServerError)
        return
    }

    // Prepare response
    response := map[string]interface{}{
        "message":        "Login successful",
        "access_token":   accessToken,
        "refresh_token":  refreshToken,
        "user_id":        user.ID,
        "stream_token":   streamToken,
    }

    // If user is an expert, fetch and include expert_id
    if user.Role == "expert" {
        var expert models.Expert
        result := h.db.Where("user_id = ?", user.ID).First(&expert)
        if result.Error == nil {
            response["expert_id"] = expert.ID
        } else if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
            // Only return error if it's not a "not found" error
            http.Error(w, "Error fetching expert profile", http.StatusInternalServerError)
            return
        }
    }

    // Respond with tokens and expert_id if applicable
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}




func (h *Handler) HandleRegister(w http.ResponseWriter, r *http.Request) {
    // Parse json data
    var registerRequest struct {
        FullName           string   `json:"full_name"`
        Email              string   `json:"email"`
        Password           string   `json:"password"`
        Phone              string   `json:"phone"`
        Role               string   `json:"role"`
        Expertise          string   `json:"expertise"`
        Bio                string   `json:"bio"`
        CertificationFiles []string `json:"certification_files"`
    }
    if err := json.NewDecoder(r.Body).Decode(&registerRequest); err != nil {
        http.Error(w, "Invalid JSON input", http.StatusBadRequest)
        return
    }
    // Validate required fields
    if registerRequest.FullName == "" || registerRequest.Email == "" || registerRequest.Password == "" || registerRequest.Phone == "" || registerRequest.Role == "" {
        http.Error(w, "Missing required fields", http.StatusBadRequest)
        return
    }

    // Validate unique constraints
    var existingUser models.User
    if result := h.db.Where("email = ? OR phone = ?", registerRequest.Email, registerRequest.Phone).First(&existingUser); !errors.Is(result.Error, gorm.ErrRecordNotFound) {
        if result.Error != nil {
            http.Error(w, "Database error", http.StatusInternalServerError)
            return
        }
        
        var errorMessage string
        if existingUser.Email == registerRequest.Email && existingUser.Phone == registerRequest.Phone {
            errorMessage = "Email and phone number are already in use"
        } else if existingUser.Email == registerRequest.Email {
            errorMessage = "Email is already in use"
        } else {
            errorMessage = "Phone number is already in use"
        }
        log.Printf("Registration attempt with duplicate %s", errorMessage)
        http.Error(w, errorMessage, http.StatusConflict)
        return
    }

    // Hash password
    passwordHash, err := bcrypt.GenerateFromPassword([]byte(registerRequest.Password), bcrypt.DefaultCost)
    if err != nil {
        http.Error(w, "Error hashing password", http.StatusInternalServerError)
        return
    }

    // Generate verification code
    verificationCode := fmt.Sprintf("%06d", rand.Intn(1000000))
    verificationExpiry := time.Now().Add(15 * time.Minute)

    // Begin transaction
    tx := h.db.Begin()

    // Create user
    user := models.User{
        FullName:             registerRequest.FullName,
        Email:               registerRequest.Email,
        PasswordHash:        string(passwordHash),
        Phone:               registerRequest.Phone,
        Role:                registerRequest.Role,
        PhoneVerified:       false,
        EmailVerificationCode: verificationCode,
        VerificationExpiry:  verificationExpiry,
    }

    if err := tx.Create(&user).Error; err != nil {
        if strings.Contains(err.Error(), "UNIQUE constraint") || strings.Contains(err.Error(), "duplicate key") {
            log.Printf("Unique constraint violation during user creation: %v", err)
            tx.Rollback()
            http.Error(w, "Email or phone number is already in use", http.StatusConflict)
            return
        }
        tx.Rollback()
        http.Error(w, "Error registering user", http.StatusInternalServerError)
        return
    }

    var expertID uint
    if registerRequest.Role == "expert" {
        // Create expert profile
        expert := models.Expert{
            UserID:    user.ID,
            Expertise: registerRequest.Expertise,
            Bio:       registerRequest.Bio,
        }

        if err := tx.Create(&expert).Error; err != nil {
            tx.Rollback()
            http.Error(w, "Error creating expert profile", http.StatusInternalServerError)
            return
        }

        expertID = expert.ID

        // Handle certification files
        for _, fileURL := range registerRequest.CertificationFiles {
            certification := models.CertificationFile{
                ExpertID: expertID,
                FilePath:  fileURL,
            }
            if err := tx.Create(&certification).Error; err != nil {
                tx.Rollback()
                http.Error(w, "Error saving certification URL", http.StatusInternalServerError)
                return
            }
        }
    }

    // Commit transaction
    if err := tx.Commit().Error; err != nil {
        http.Error(w, "Error committing transaction", http.StatusInternalServerError)
        return
    }

    // Send verification email
    go func() {
        if err := sendVerificationEmail(user.Email, verificationCode); err != nil {
            log.Printf("Error sending verification email: %v", err)
        }
    }()

    // Respond with success message
    w.Header().Set("Content-Type", "application/json")
    response := map[string]interface{}{
        "message": "User registered successfully. Please check your email for verification code.",
        "user_id": user.ID,
    }
    if expertID != 0 {
        response["expert_id"] = expertID
    }
    json.NewEncoder(w).Encode(response)
}




// sendVerificationEmail sends a verification email with the 6-digit code
func sendVerificationEmail(email, code string) error {
	// Load SMTP configuration from environment variables
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASS")

	// Create a new email message
	m := gomail.NewMessage()
	m.SetHeader("From", smtpUser)
	m.SetHeader("To", email)
	m.SetHeader("Subject", "Email Verification Code")
	m.SetBody("text/plain", fmt.Sprintf("Your verification code is: %s. Ignore this email if you did not request a verification code.", code))

	// Set up the dialer
	port, err := strconv.Atoi(smtpPort)
	if err != nil {
		return fmt.Errorf("invalid SMTP port: %v", err)
	}
	d := gomail.NewDialer(smtpHost, port, smtpUser, smtpPass)

	// Send the email
	return d.DialAndSend(m)
}




func (h *Handler) verifyUser(w http.ResponseWriter, r *http.Request) {
    var request struct {
        Email string `json:"email"`
        Code  string `json:"code"`
    }

    if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    var user models.User
    if err := h.db.Where("email = ?", request.Email).First(&user).Error; err != nil {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }

    // Check if the code matches and is not expired
    if user.EmailVerificationCode != request.Code || time.Now().After(user.VerificationExpiry) {
        http.Error(w, "Invalid or expired verification code", http.StatusUnauthorized)
        return
    }


    user.EmailVerified = true
    user.EmailVerificationCode = "" // Clear the code
    user.VerificationExpiry = time.Time{}

    if err := h.db.Save(&user).Error; err != nil {
        http.Error(w, "Error updating user", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "message": "Email verified successfully",
    })
}






// GetUsers retrieves all users
func (h *Handler) GetUsers(w http.ResponseWriter, r *http.Request) {
	var users []models.User
	result := h.db.Find(&users)
	if result.Error != nil {
		http.Error(w, "Error retrieving users", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// GetUser retrieves a specific user by ID
func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	// Parse user ID from URL
	vars := mux.Vars(r)
	userID, err := strconv.ParseUint(vars["id"], 10, 64)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var user models.User
	result := h.db.Preload("Expert").First(&user, userID).Preload("ProfilePicturePath")
	if result.Error != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}


// func createDirectoryIfNotExist(path string) error {
// 	if _, err := os.Stat(path); os.IsNotExist(err) {
// 		if err := os.MkdirAll(path, 0755); err != nil {
// 			return fmt.Errorf("could not create directory %s: %w", path, err)
// 		}
// 	}
// 	return nil
// }


// UpdateUser updates user information
func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	// Parse user ID from URL
	vars := mux.Vars(r)
	userID, err := strconv.ParseUint(vars["id"], 10, 64)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Parse multipart form data
	var updateData struct {
		FullName          string `json:"full_name"`
		Phone             string `json:"phone"`
		ProfilePictureURL string `json:"profile_picture_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
		http.Error(w, "Invalid JSON input", http.StatusBadRequest)
		return
	}

	// Find user by ID
	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Update fields
	if updateData.FullName != "" {
		user.FullName = updateData.FullName
	}
	if updateData.Phone != "" {
		user.Phone = updateData.Phone
	}
	if updateData.ProfilePictureURL != "" {
		user.ProfilePicturePath = updateData.ProfilePictureURL
	}

	// Save updated user data
	if err := h.db.Save(&user).Error; err != nil {
		http.Error(w, "Error updating user", http.StatusInternalServerError)
		return
	}

	// Return updated user details
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}



// DeleteUser removes a user
func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	// Parse user ID from URL
	vars := mux.Vars(r)
	userID, err := strconv.ParseUint(vars["id"], 10, 64)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Delete user
	result := h.db.Delete(&models.User{}, userID)
	if result.Error != nil {
		http.Error(w, "Error deleting user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User deleted successfully",
	})
}

func (h *Handler) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
    // Create a logger
    logger := log.New(os.Stdout, "RefreshToken: ", log.Ldate|log.Ltime|log.Lshortfile)

    var refreshRequest struct {
        RefreshToken string `json:"refresh_token"`
    }

    if err := json.NewDecoder(r.Body).Decode(&refreshRequest); err != nil {
        logger.Printf("Decoding error: %v", err)
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    // Start a database transaction
    tx := h.db.Begin()

    // Validate refresh token against stored token in database
    var user models.User
    if err := tx.Where("refresh_token = ?", refreshRequest.RefreshToken).First(&user).Error; err != nil {
        tx.Rollback()
        logger.Printf("Invalid refresh token for request: %v", refreshRequest.RefreshToken)
        http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
        return
    }

    // Check refresh token expiration (assuming you add an expiration field)
    if user.RefreshTokenExpiredAt.Before(time.Now()) {
        tx.Rollback()
        logger.Printf("Expired refresh token for user ID: %d", user.ID)
        http.Error(w, "Refresh token expired", http.StatusUnauthorized)
        return
    }

    // Generate new access token
    newAccessToken, err := generateJWT(user.ID, 15)
    if err != nil {
        tx.Rollback()
        logger.Printf("Failed to generate access token for user ID: %d, error: %v", user.ID, err)
        http.Error(w, "Error generating new token", http.StatusInternalServerError)
        return
    }

    // Generate new refresh token (rotation)
    newRefreshToken, err := generateRefreshToken(user.ID)
    if err != nil {
        tx.Rollback()
        logger.Printf("Failed to generate refresh token for user ID: %d, error: %v", user.ID, err)
        http.Error(w, "Error generating refresh token", http.StatusInternalServerError)
        return
    }

    // Update user with new refresh token and expiration
    updateResult := tx.Model(&user).Updates(models.User{
        Refresh: newRefreshToken,
        RefreshTokenExpiredAt: time.Now().Add(30 * 24 * time.Hour), // 30 days expiration
    })

    if updateResult.Error != nil {
        tx.Rollback()
        logger.Printf("Failed to update refresh token for user ID: %d, error: %v", user.ID, updateResult.Error)
        http.Error(w, "Error updating refresh token", http.StatusInternalServerError)
        return
    }

    // Commit the transaction
    if err := tx.Commit().Error; err != nil {
        logger.Printf("Transaction commit error: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    // Log successful token refresh
    logger.Printf("Successful token refresh for user ID: %d", user.ID)

    // Respond with new tokens
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "access_token":  newAccessToken,
        "refresh_token": newRefreshToken,
    })
}



var jwtSecretKey = []byte(os.Getenv("SECRET_KEY"))

func generateJWT(userID uint, expirationMinutes int) (string, error) {
    claims := &jwt.RegisteredClaims{
        Subject:   fmt.Sprint(userID),
        ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * time.Duration(expirationMinutes))),
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(jwtSecretKey)
}


func generateRefreshToken(userID uint) (string, error) {
    // Generate cryptographically secure random bytes
    b := make([]byte, 32)
    _, err := rand.Read(b)
    if err != nil {
        return "", err
    }

    // Use HMAC to create a token that's tied to the user
    mac := hmac.New(sha256.New, []byte(os.Getenv("SECRET_KEY")))
    mac.Write([]byte(fmt.Sprintf("%d", userID)))
    mac.Write(b)
    
    signature := mac.Sum(nil)
    return fmt.Sprintf("%d_%x_%x", userID, b, signature), nil
}

func saveRefreshToken(db *gorm.DB, userID uint, refreshToken string) error {
    expirationTime := time.Now().Add(30 * 24 * time.Hour) // 30 days
    return db.Model(&models.User{}).Where("id = ?", userID).Updates(map[string]interface{}{
        "refresh_token": refreshToken,
        "refresh_token_expired_at": expirationTime,
    }).Error
}


type PasswordResetToken struct {
	gorm.Model
	UserID    uint
	Token     string
	ExpiresAt time.Time
}

func (h *Handler) handlePasswordResetRequest(w http.ResponseWriter, r *http.Request) {
    // Parse request body
    var resetRequest struct {
        Email string `json:"email"`
    }

    if err := json.NewDecoder(r.Body).Decode(&resetRequest); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Validate email
    if resetRequest.Email == "" {
        http.Error(w, "Email is required", http.StatusBadRequest)
        return
    }

    // Find user by email
    var user models.User
    result := h.db.Where("email = ?", resetRequest.Email).First(&user)
    if result.Error != nil {
        // Keep response vague for security
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]string{
            "message": "If an account exists, a reset code will be sent to your email",
        })
        return
    }

    // Generate a secure 6-digit reset token
    resetToken := fmt.Sprintf("%06d", rand.Intn(1000000))

    // Begin a transaction
    tx := h.db.Begin()

    // Delete any existing reset tokens for this user
    if err := tx.Where("user_id = ?", user.ID).Delete(&models.PasswordResetToken{}).Error; err != nil {
        tx.Rollback()
        http.Error(w, "Error processing reset request", http.StatusInternalServerError)
        return
    }

    // Create new reset token
    passwordResetToken := models.PasswordResetToken{
        UserID:    user.ID,
        Token:     resetToken,
        ExpiresAt: time.Now().Add(5 * time.Minute),
    }

    if err := tx.Create(&passwordResetToken).Error; err != nil {
        tx.Rollback()
        http.Error(w, "Error creating reset token", http.StatusInternalServerError)
        return
    }

    // Commit transaction
    if err := tx.Commit().Error; err != nil {
        http.Error(w, "Error processing reset request", http.StatusInternalServerError)
        return
    }

    // Send the reset code via email
    if err := sendVerificationEmail(user.Email, resetToken); err != nil {
        http.Error(w, "Error sending email", http.StatusInternalServerError)
        return
    }

    // Respond to the user
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "message": "If an account exists, a reset code will be sent to your email",
    })
}


func (h *Handler) handlePasswordReset(w http.ResponseWriter, r *http.Request) {
    // Extract user ID from URL parameters
    vars := mux.Vars(r)
    userID, err := strconv.ParseUint(vars["userId"], 10, 32)
    if err != nil {
        http.Error(w, "Invalid user ID", http.StatusBadRequest)
        return
    }

    var resetRequest struct {
        Password string `json:"password"`
    }

    if err := json.NewDecoder(r.Body).Decode(&resetRequest); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Validate password strength
    if len(resetRequest.Password) < 6 {
        http.Error(w, "Password must be at least 6 characters long", http.StatusBadRequest)
        return
    }

    // Begin a transaction
    tx := h.db.Begin()

    // Find the user by ID
    var user models.User
    if err := tx.First(&user, userID).Error; err != nil {
        tx.Rollback()
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }

    // Hash the new password
    passwordHash, err := bcrypt.GenerateFromPassword([]byte(resetRequest.Password), bcrypt.DefaultCost)
    if err != nil {
        tx.Rollback()
        http.Error(w, "Error hashing password", http.StatusInternalServerError)
        return
    }

    // Update the user's password
    user.PasswordHash = string(passwordHash)
    if err := tx.Save(&user).Error; err != nil {
        tx.Rollback()
        http.Error(w, "Error updating password", http.StatusInternalServerError)
        return
    }

    // Commit the transaction
    if err := tx.Commit().Error; err != nil {
        http.Error(w, "Error processing password reset", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "message": "Password reset successful",
    })
}



type TokenVerificationRequest struct {
    Email string `json:"email"`
    Token string `json:"token"`
}

func (h *Handler) handleVerifyResetToken(w http.ResponseWriter, r *http.Request) {
    var req TokenVerificationRequest

    // Decode the incoming request payload
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Find the user by email
    var user models.User
    if err := h.db.Where("email = ?", req.Email).First(&user).Error; err != nil {
        // Deliberately vague response to avoid revealing user existence
        http.Error(w, "Invalid email or token", http.StatusBadRequest)
        return
    }

    // Find the reset token for the user
    var resetToken models.PasswordResetToken
    if err := h.db.Where("user_id = ? AND token = ?", user.ID, req.Token).First(&resetToken).Error; err != nil {
        http.Error(w, "Invalid email or token", http.StatusBadRequest)
        return
    }

    // Check if the token is expired
    if time.Now().After(resetToken.ExpiresAt) {
        http.Error(w, "Token expired", http.StatusBadRequest)
        return
    }

    // Token is valid; respond with success and include user ID
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "message": "Token is valid",
        "user_id": user.ID,
    })
}



func (h *Handler) GetExperts(w http.ResponseWriter, r *http.Request) {
    if h.db == nil {
        http.Error(w, "Database connection not initialized", http.StatusInternalServerError)
        return
    }

    // Parse query parameters
    verified := r.URL.Query().Get("verified")
    page, err := strconv.Atoi(r.URL.Query().Get("page"))
    if err != nil || page < 1 {
        page = 1
    }
    pageSize := 20

    // Base query with both User and CertificationFiles preloaded
    query := h.db.Model(&models.Expert{}).
        Preload("User").
        Preload("CertificationFiles")

    // Filter by verification status if specified
    if verified != "" {
        isVerified, parseErr := strconv.ParseBool(verified)
        if parseErr != nil {
            http.Error(w, "Invalid value for 'verified'", http.StatusBadRequest)
            return
        }
        query = query.Where("verified = ?", isVerified)
    }

    // Count total records
    var total int64
    if err := query.Count(&total).Error; err != nil {
        http.Error(w, "Error counting experts", http.StatusInternalServerError)
        return
    }

    // Fetch paginated experts
    var experts []models.Expert
    result := query.Offset((page - 1) * pageSize).Limit(pageSize).Find(&experts)
    if result.Error != nil {
        http.Error(w, "Error retrieving experts", http.StatusInternalServerError)
        return
    }

    // Check if there are no experts
    if len(experts) == 0 {
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "experts":     []interface{}{},
            "total":      0,
            "page":       page,
            "page_size":  pageSize,
            "total_pages": 0,
        })
        return
    }

    // Construct response
    response := make([]map[string]interface{}, 0, len(experts))
    for _, expert := range experts {
        if expert.User == nil {
            continue // Skip if User is nil
        }

        expertData := map[string]interface{}{
            "ID":                expert.ID,
            "CreatedAt":         expert.CreatedAt,
            "UpdatedAt":         expert.UpdatedAt,
            "UserID":           expert.UserID,
            "Expertise":        expert.Expertise,
            "Bio":              expert.Bio,
            "Verified":         expert.Verified,
            "CertificationFiles": expert.CertificationFiles,
            "User": map[string]interface{}{
                "FullName":           expert.User.FullName,
                "Email":             expert.User.Email,
                "Phone":             expert.User.Phone,
                "Role":              expert.User.Role,
                "PhoneVerified":     expert.User.PhoneVerified,
                "EmailVerified":     expert.User.EmailVerified,
                "Status":            expert.User.Status,
                "ProfilePicturePath": expert.User.ProfilePicturePath,
            },
        }
        response = append(response, expertData)
    }

    // Return the response
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "experts":     response,
        "total":       total,
        "page":        page,
        "page_size":   pageSize,
        "total_pages": (total + int64(pageSize) - 1) / int64(pageSize),
    })
}

// GetExpert retrieves a specific expert by ID with full details
func (h *Handler) GetExpert(w http.ResponseWriter, r *http.Request) {
    if h.db == nil {
        http.Error(w, "Database connection not initialized", http.StatusInternalServerError)
        return
    }

    // Parse expert ID from URL
    vars := mux.Vars(r)
    if vars == nil {
        http.Error(w, "Missing URL parameters", http.StatusBadRequest)
        return
    }

    expertID, err := strconv.ParseUint(vars["id"], 10, 64)
    if err != nil {
        http.Error(w, "Invalid expert ID", http.StatusBadRequest)
        return
    }

    var expert models.Expert
    result := h.db.Preload("User").
        Preload("CertificationFiles").
        First(&expert, expertID)

    if result.Error != nil {
        if errors.Is(result.Error, gorm.ErrRecordNotFound) {
            http.Error(w, "Expert not found", http.StatusNotFound)
        } else {
            http.Error(w, "Error retrieving expert", http.StatusInternalServerError)
        }
        return
    }

    // Check if User is nil before accessing
    if expert.User == nil {
        http.Error(w, "Expert user data not found", http.StatusInternalServerError)
        return
    }

    // Construct response including both expert and user data
    expertData := map[string]interface{}{
        "ID":                expert.ID,
        "CreatedAt":         expert.CreatedAt,
        "UpdatedAt":         expert.UpdatedAt,
        "UserID":           expert.UserID,
        "Expertise":        expert.Expertise,
        "Bio":              expert.Bio,
        "Verified":         expert.Verified,
        "CertificationFiles": expert.CertificationFiles,
        "User": map[string]interface{}{
            "FullName":           expert.User.FullName,
            "Email":             expert.User.Email,
            "Phone":             expert.User.Phone,
            "Role":              expert.User.Role,
            "PhoneVerified":     expert.User.PhoneVerified,
            "EmailVerified":     expert.User.EmailVerified,
            "Status":            expert.User.Status,
            "ProfilePicturePath": expert.User.ProfilePicturePath,
        },
    }

    // Return the response
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(expertData)
}

// UpdateExpert allows updating expert profile information
func (h *Handler) UpdateExpert(w http.ResponseWriter, r *http.Request) {
    // Parse expert ID from URL
    vars := mux.Vars(r)
    expertID, err := strconv.ParseUint(vars["id"], 10, 64)
    if err != nil {
        http.Error(w, "Invalid expert ID", http.StatusBadRequest)
        return
    }

    // Parse request body
    var updateRequest struct {
        Expertise          string `json:"expertise"`
        Bio                string `json:"bio"`
        CertificationFiles []struct {
            FileName string `json:"file_name"`
            FilePath string `json:"file_path"`
        } `json:"certification_files"`
    }
    if err := json.NewDecoder(r.Body).Decode(&updateRequest); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Find expert
    var expert models.Expert
    if result := h.db.Preload("CertificationFiles").First(&expert, expertID); result.Error != nil {
        http.Error(w, "Expert not found", http.StatusNotFound)
        return
    }

    // Update fields
    expert.Expertise = updateRequest.Expertise
    expert.Bio = updateRequest.Bio

    // Handle certification file updates
    if len(updateRequest.CertificationFiles) > 0 {
        // Clear existing certification files
        if err := h.db.Where("expert_id = ?", expert.ID).Delete(&models.CertificationFile{}).Error; err != nil {
            http.Error(w, "Error clearing certification files", http.StatusInternalServerError)
            return
        }

        // Add new certification files
        for _, file := range updateRequest.CertificationFiles {
            certificationFile := models.CertificationFile{
                ExpertID: expert.ID,
                FileName: file.FileName,
                FilePath: file.FilePath,
            }
            if err := h.db.Create(&certificationFile).Error; err != nil {
                http.Error(w, "Error adding certification files", http.StatusInternalServerError)
                return
            }
        }
    }

    // Save expert updates
    if err := h.db.Save(&expert).Error; err != nil {
        http.Error(w, "Error updating expert", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "message": "Expert updated successfully",
        "expert":  expert,
    })
}

// VerifyExpert handles expert verification by an admin
func (h *Handler) VerifyExpert(w http.ResponseWriter, r *http.Request) {
	// Parse expert ID from URL
	vars := mux.Vars(r)
	expertID, err := strconv.ParseUint(vars["id"], 10, 64)
	if err != nil {
		http.Error(w, "Invalid expert ID", http.StatusBadRequest)
		return
	}

	// Parse verification request
	var verifyRequest struct {
		Verified bool `json:"verified"`
	}
	if err := json.NewDecoder(r.Body).Decode(&verifyRequest); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Find expert
	var expert models.Expert
	result := h.db.First(&expert, expertID)
	if result.Error != nil {
		http.Error(w, "Expert not found", http.StatusNotFound)
		return
	}

	// Update verification status
	expert.Verified = verifyRequest.Verified
	if err := h.db.Save(&expert).Error; err != nil {
		http.Error(w, "Error updating expert verification", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":   "Expert verification updated",
		"verified": expert.Verified,
	})
}

// SearchExperts allows searching experts by various criteria
func (h *Handler) SearchExperts(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	query := r.URL.Query().Get("q")
	expertise := r.URL.Query().Get("expertise")
	verified := r.URL.Query().Get("verified")
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize := 10

	// Base query
	dbQuery := h.db.Model(&models.Expert{}).Preload("User")

	// Apply filters
	if query != "" {
		searchQuery := "%" + query + "%"
		dbQuery = dbQuery.Where(
			"expertise LIKE ? OR certifications LIKE ? OR bio LIKE ?", 
			searchQuery, searchQuery, searchQuery,
		)
	}

	if expertise != "" {
		dbQuery = dbQuery.Where("expertise LIKE ?", "%"+expertise+"%")
	}

	if verified != "" {
		isVerified, _ := strconv.ParseBool(verified)
		dbQuery = dbQuery.Where("verified = ?", isVerified)
	}

	// Count total results
	var total int64
	dbQuery.Count(&total)

	// Retrieve paginated results
	var experts []models.Expert
	result := dbQuery.Offset((page - 1) * pageSize).Limit(pageSize).Find(&experts)
	
	if result.Error != nil {
		http.Error(w, "Error searching experts", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"experts":     experts,
		"total":       total,
		"page":        page,
		"page_size":   pageSize,
		"total_pages": (total + int64(pageSize) - 1) / int64(pageSize),
	})
}

// GetExpertsByExpertise retrieves experts by a specific expertise area
func (h *Handler) GetExpertsByExpertise(w http.ResponseWriter, r *http.Request) {
	// Parse expertise from URL
	vars := mux.Vars(r)
	expertise := vars["expertise"]

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize := 10

	// Query experts by expertise
	var experts []models.Expert
	var total int64

	// Use LIKE for partial matches
	query := h.db.Model(&models.Expert{}).
		Where("expertise LIKE ?", "%"+expertise+"%").
		Preload("User")

	// Count total matching experts
	query.Count(&total)

	// Retrieve paginated results
	result := query.
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&experts)

	if result.Error != nil {
		http.Error(w, "Error retrieving experts", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"experts":     experts,
		"total":       total,
		"page":        page,
		"page_size":   pageSize,
		"total_pages": (total + int64(pageSize) - 1) / int64(pageSize),
	})
}