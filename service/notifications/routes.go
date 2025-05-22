package notification

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/KAsare1/Kodefx-server/cmd/models"
	"github.com/gorilla/mux"
	expo "github.com/oliveroneill/exponent-server-sdk-golang/sdk"
	"gorm.io/gorm"
)

// NotificationHandler handles notification operations
type NotificationHandler struct {
	db         *gorm.DB
	expoClient *expo.PushClient
}

// NewNotificationHandler creates a new notification handler
func NewNotificationHandler(db *gorm.DB) *NotificationHandler {
	return &NotificationHandler{
		db:         db,
		expoClient: expo.NewPushClient(nil),
	}
}

// RegisterRoutes registers all notification routes
func (h *NotificationHandler) RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/devices", h.RegisterDevice).Methods("POST")
	router.HandleFunc("/notifications", h.SendNotification).Methods("POST")
	router.HandleFunc("/notifications/broadcast", h.BroadcastNotification).Methods("POST")
	router.HandleFunc("/users/{userId}/devices", h.GetUserDevices).Methods("GET")
	router.HandleFunc("/users/{userId}/notifications", h.SendUserNotification).Methods("POST")
	router.HandleFunc("/users/{userId}/history", h.GetUserNotificationHistory).Methods("GET")
	router.HandleFunc("/devices/{id}", h.DeleteDevice).Methods("DELETE")
}

// RegisterDevice registers a new device for push notifications
func (h *NotificationHandler) RegisterDevice(w http.ResponseWriter, r *http.Request) {
	var device models.Device
	if err := json.NewDecoder(r.Body).Decode(&device); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if device.UserID == "" || device.Token == "" {
		http.Error(w, "UserID and token are required", http.StatusBadRequest)
		return
	}

	// Validate the Expo push token format
	if _, err := expo.NewExponentPushToken(device.Token); err != nil {
		http.Error(w, "Invalid Expo push token format", http.StatusBadRequest)
		return
	}

	// Check if this device already exists
	var existingDevice models.Device
	result := h.db.Where("token = ? AND user_id = ?", device.Token, device.UserID).First(&existingDevice)
	
	if result.Error == nil {
		// Device already exists, update it
		existingDevice.UpdatedAt = time.Now()
		existingDevice.DeviceType = device.DeviceType
		existingDevice.DeviceName = device.DeviceName
		if err := h.db.Save(&existingDevice).Error; err != nil {
			http.Error(w, "Error updating device", http.StatusInternalServerError)
			return
		}
		device = existingDevice
	} else {
		// Device doesn't exist, create it
		if err := h.db.Create(&device).Error; err != nil {
			http.Error(w, "Error creating device", http.StatusInternalServerError)
			return
		}
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Device registered successfully",
		"device":  device,
	})
}

// GetUserDevices gets all devices for a specific user
func (h *NotificationHandler) GetUserDevices(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["userId"]
	
	if userID == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}
	
	// Query devices for this user
	var devices []models.Device
	if err := h.db.Where("user_id = ?", userID).Find(&devices).Error; err != nil {
		http.Error(w, "Error retrieving devices", http.StatusInternalServerError)
		return
	}
	
	// Send response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(devices)
}

// SendNotification sends a push notification to a specific device
func (h *NotificationHandler) SendNotification(w http.ResponseWriter, r *http.Request) {
	var req models.NotificationRequest
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Token == "" || req.Title == "" || req.Body == "" {
		http.Error(w, "Token, title and body are required", http.StatusBadRequest)
		return
	}

	// Find device to get user ID
	var device models.Device
	if err := h.db.Where("token = ?", req.Token).First(&device).Error; err != nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	// Call the Expo push service using SDK
	success, err := h.sendExpoNotificationSDK([]string{req.Token}, req.Title, req.Body, req.Data)
	
	// Create notification history
	status := "sent"
	if !success || err != nil {
		status = "failed"
	}
	
	// Convert data to JSON string
	dataJSON, _ := json.Marshal(req.Data)
	
	history := models.NotificationHistory{
		UserID: device.UserID,
		Title:  req.Title,
		Body:   req.Body,
		Data:   string(dataJSON),
		Status: status,
		SentAt: time.Now(),
	}
	
	if dbErr := h.db.Create(&history).Error; dbErr != nil {
		// Log this error but don't fail the request
		log.Printf("Error creating notification history: %v", dbErr)
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": success,
		"message": "Notification sent",
	})
}

// SendUserNotification sends a notification to all devices of a user
func (h *NotificationHandler) SendUserNotification(w http.ResponseWriter, r *http.Request) {
	// Get user ID from URL path
	vars := mux.Vars(r)
	userID := vars["userId"]
	
	if userID == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}
	
	// Parse notification details
	var notificationData struct {
		Title string                 `json:"title"`
		Body  string                 `json:"body"`
		Data  map[string]interface{} `json:"data,omitempty"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&notificationData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	
	// Get user's devices
	var devices []models.Device
	result := h.db.Where("user_id = ?", userID).Find(&devices)
	
	if result.Error != nil {
		http.Error(w, "Error retrieving user devices", http.StatusInternalServerError)
		return
	}
	
	if len(devices) == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "No devices registered for this user",
		})
		return
	}
	
	// Collect all tokens for this user
	var tokens []string
	for _, device := range devices {
		tokens = append(tokens, device.Token)
	}
	
	// Send notification to all user devices
	success, err := h.sendExpoNotificationSDK(tokens, notificationData.Title, notificationData.Body, notificationData.Data)
	
	// Create notification history
	status := "sent"
	if !success || err != nil {
		status = "failed"
	}
	
	// Convert data to JSON string
	dataJSON, _ := json.Marshal(notificationData.Data)
	
	history := models.NotificationHistory{
		UserID: userID,
		Title:  notificationData.Title,
		Body:   notificationData.Body,
		Data:   string(dataJSON),
		Status: status,
		SentAt: time.Now(),
	}
	
	if dbErr := h.db.Create(&history).Error; dbErr != nil {
		// Log this error but don't fail the request
		log.Printf("Error creating notification history: %v", dbErr)
	}
	
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	// Send response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": success,
		"message": fmt.Sprintf("Notification sent to %d devices", len(tokens)),
	})
}

// BroadcastNotification sends a notification to multiple users or all users
func (h *NotificationHandler) BroadcastNotification(w http.ResponseWriter, r *http.Request) {
	var req models.BroadcastRequest
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Title == "" || req.Body == "" {
		http.Error(w, "Title and body are required", http.StatusBadRequest)
		return
	}

	var devices []models.Device
	query := h.db

	// If specific user IDs are provided, filter by them
	if len(req.UserIDs) > 0 {
		query = query.Where("user_id IN ?", req.UserIDs)
	}

	// Get all devices (or filtered by user IDs)
	if err := query.Find(&devices).Error; err != nil {
		http.Error(w, "Error retrieving devices", http.StatusInternalServerError)
		return
	}

	if len(devices) == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "No devices found for notification",
		})
		return
	}

	// Collect all tokens and track users for history
	var tokens []string
	userMap := make(map[string]bool)
	for _, device := range devices {
		tokens = append(tokens, device.Token)
		userMap[device.UserID] = true
	}

	// Send notifications using SDK (it handles batching internally)
	success, err := h.sendExpoNotificationSDK(tokens, req.Title, req.Body, req.Data)
	
	// Determine the status based on the success of sending
	status := "sent"
	if !success || err != nil {
		status = "failed"
	}

	// Convert data to JSON string for storage
	dataJSON, _ := json.Marshal(req.Data)
	
	// Create notification history for each user
	for userID := range userMap {
		history := models.NotificationHistory{
			UserID: userID,
			Title:  req.Title,
			Body:   req.Body,
			Data:   string(dataJSON),
			Status: status,
			SentAt: time.Now(),
		}
		
		if err := h.db.Create(&history).Error; err != nil {
			// Log this error but don't fail the request
			log.Printf("Error creating notification history for user %s: %v\n", userID, err)
		}
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": success,
		"message": fmt.Sprintf("Broadcast sent to %d devices", len(tokens)),
	})
}

// GetUserNotificationHistory gets notification history for a specific user
func (h *NotificationHandler) GetUserNotificationHistory(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["userId"]
	
	if userID == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}
	
	// Set default pagination values
	limit := 20
	page := 1
	
	// Parse query parameters
	if limitParam := r.URL.Query().Get("limit"); limitParam != "" {
		if parsedLimit, err := strconv.Atoi(limitParam); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}
	
	if pageParam := r.URL.Query().Get("page"); pageParam != "" {
		if parsedPage, err := strconv.Atoi(pageParam); err == nil && parsedPage > 0 {
			page = parsedPage
		}
	}
	
	// Calculate offset
	offset := (page - 1) * limit
	
	// Query notification history for this user
	var history []models.NotificationHistory
	var count int64
	
	// Get total count
	if err := h.db.Model(&models.NotificationHistory{}).Where("user_id = ?", userID).Count(&count).Error; err != nil {
		http.Error(w, "Error counting notifications", http.StatusInternalServerError)
		return
	}
	
	// Get paginated results
	if err := h.db.Where("user_id = ?", userID).
		Order("sent_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&history).Error; err != nil {
		http.Error(w, "Error retrieving notification history", http.StatusInternalServerError)
		return
	}
	
	// Send response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total":   count,
		"page":    page,
		"limit":   limit,
		"history": history,
	})
}

// DeleteDevice deletes a device token
func (h *NotificationHandler) DeleteDevice(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	deviceID, err := strconv.ParseUint(vars["id"], 10, 64)
	if err != nil {
		http.Error(w, "Invalid device ID", http.StatusBadRequest)
		return
	}

	result := h.db.Delete(&models.Device{}, deviceID)
	if result.Error != nil {
		http.Error(w, "Error deleting device", http.StatusInternalServerError)
		return
	}

	if result.RowsAffected == 0 {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Device deleted successfully",
	})
}

// sendExpoNotificationSDK sends push notifications using the Expo SDK
func (h *NotificationHandler) sendExpoNotificationSDK(tokenStrings []string, title, body string, data map[string]interface{}) (bool, error) {
	var validTokens []expo.ExponentPushToken
	var invalidTokens []string

	// Validate and convert tokens
	for _, tokenString := range tokenStrings {
		pushToken, err := expo.NewExponentPushToken(tokenString)
		if err != nil {
			log.Printf("Invalid push token format %s: %v", tokenString, err)
			invalidTokens = append(invalidTokens, tokenString)
			continue
		}
		validTokens = append(validTokens, pushToken)
	}

	if len(validTokens) == 0 {
		return false, fmt.Errorf("no valid push tokens found")
	}

	// Convert data to map[string]string
	var stringData map[string]string
	if data != nil {
		stringData = make(map[string]string)
		for key, value := range data {
			stringData[key] = fmt.Sprintf("%v", value)
		}
	}

	// Create and send the push message
	pushMessage := &expo.PushMessage{
		To:       validTokens,
		Body:     body,
		Title:    title,
		Sound:    "default",
		Priority: expo.DefaultPriority,
		Data:     stringData,
	}

	response, err := h.expoClient.Publish(pushMessage)
	if err != nil {
		return false, fmt.Errorf("failed to publish notification: %v", err)
	}

	// Check response for errors
	if validationErr := response.ValidateResponse(); validationErr != nil {
		log.Printf("Push notification validation error: %v", validationErr)
		
		// Clean up invalid tokens from database
		h.cleanupInvalidTokens(invalidTokens)
		
		return false, fmt.Errorf("notification validation failed: %v", validationErr)
	}

	// Clean up any invalid tokens we found
	if len(invalidTokens) > 0 {
		h.cleanupInvalidTokens(invalidTokens)
	}

	return true, nil
}

// Helper function to remove invalid tokens from database
func (h *NotificationHandler) cleanupInvalidTokens(tokens []string) {
	for _, token := range tokens {
		if err := h.db.Where("token = ?", token).Delete(&models.Device{}).Error; err != nil {
			log.Printf("Error cleaning up invalid token %s: %v", token, err)
		} else {
			log.Printf("Cleaned up invalid token: %s", token)
		}
	}
}
