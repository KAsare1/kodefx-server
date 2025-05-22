package signals

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/KAsare1/Kodefx-server/cmd/models"
	"github.com/KAsare1/Kodefx-server/cmd/utils"
	"github.com/gorilla/mux"
	expo "github.com/oliveroneill/exponent-server-sdk-golang/sdk"
	"gorm.io/gorm"
)

type NotificationSender interface {
	SendUserNotification(userID string, title, body string, data map[string]interface{}) (bool, error)
	BroadcastNotification(title, body string, data map[string]interface{}, userIDs []string) (bool, error)
}

// DefaultNotificationSender implements the NotificationSender interface
type DefaultNotificationSender struct {
	db         *gorm.DB
	expoClient *expo.PushClient
}

// Add notificationSender field to SignalHandler
type SignalHandler struct {
	db                 *gorm.DB
	notificationSender NotificationSender
}

// Update the NewSignalHandler function to initialize with NotificationSender
func NewSignalHandler(db *gorm.DB) *SignalHandler {
	return &SignalHandler{
		db: db,
		notificationSender: &DefaultNotificationSender{
			db:         db,
			expoClient: expo.NewPushClient(nil),
		},
	}
}

type PaginatedResponse struct {
	Data       interface{}    `json:"data"`
	Pagination PaginationMeta `json:"pagination"`
}

type PaginationMeta struct {
	CurrentPage int   `json:"current_page"`
	PerPage     int   `json:"per_page"`
	TotalItems  int64 `json:"total_items"`
	TotalPages  int   `json:"total_pages"`
	HasPrevious bool  `json:"has_previous"`
	HasNext     bool  `json:"has_next"`
}

func ParsePaginationParams(r *http.Request) (int, int, error) {
	query := r.URL.Query()

	// Parse page number (default to 1)
	page := 1
	if query.Get("page") != "" {
		parsedPage, err := strconv.Atoi(query.Get("page"))
		if err != nil || parsedPage < 1 {
			return 0, 0, fmt.Errorf("invalid page parameter")
		}
		page = parsedPage
	}

	// Parse per_page (default to 10, cap at 100)
	perPage := 10
	if query.Get("per_page") != "" {
		parsedPerPage, err := strconv.Atoi(query.Get("per_page"))
		if err != nil || parsedPerPage < 1 {
			return 0, 0, fmt.Errorf("invalid per_page parameter")
		}
		if parsedPerPage > 100 {
			perPage = 100 // Cap at 100 to prevent excessive queries
		} else {
			perPage = parsedPerPage
		}
	}

	return page, perPage, nil
}

func (s *DefaultNotificationSender) SendUserNotification(userID string, title, body string, data map[string]interface{}) (bool, error) {
	// Get user's devices
	var devices []models.Device
	result := s.db.Where("user_id = ?", userID).Find(&devices)

	if result.Error != nil {
		return false, fmt.Errorf("error retrieving user devices: %v", result.Error)
	}

	if len(devices) == 0 {
		return true, nil // No devices to notify, but not an error
	}

	// Collect all tokens for this user
	var tokens []string
	for _, device := range devices {
		tokens = append(tokens, device.Token)
	}

	// Send notification to all user devices using SDK
	success, err := s.sendExpoNotificationSDK(tokens, title, body, data)

	// Create notification history
	status := "sent"
	if !success || err != nil {
		status = "failed"
	}

	// Convert data to JSON string
	dataJSON, _ := json.Marshal(data)

	history := models.NotificationHistory{
		UserID: userID,
		Title:  title,
		Body:   body,
		Data:   string(dataJSON),
		Status: status,
		SentAt: time.Now(),
	}

	if dbErr := s.db.Create(&history).Error; dbErr != nil {
		// Log this error but don't fail the request
		log.Printf("Error creating notification history: %v", dbErr)
	}

	return success, err
}

// BroadcastNotification sends a notification to multiple users or all users
func (s *DefaultNotificationSender) BroadcastNotification(title, body string, data map[string]interface{}, userIDs []string) (bool, error) {
	var devices []models.Device
	query := s.db

	// If specific user IDs are provided, filter by them
	if len(userIDs) > 0 {
		query = query.Where("user_id IN ?", userIDs)
	}

	// Get all devices (or filtered by user IDs)
	if err := query.Find(&devices).Error; err != nil {
		return false, fmt.Errorf("error retrieving devices: %v", err)
	}

	if len(devices) == 0 {
		return true, nil // No devices to notify, but not an error
	}

	// Collect all tokens and track users for history
	var tokens []string
	userMap := make(map[string]bool)
	for _, device := range devices {
		tokens = append(tokens, device.Token)
		userMap[device.UserID] = true
	}

	// Send notifications using SDK (it handles batching internally)
	success, err := s.sendExpoNotificationSDK(tokens, title, body, data)

	// Determine the status based on the success of sending
	status := "sent"
	if !success || err != nil {
		status = "failed"
	}

	// Convert data to JSON string for storage
	dataJSON, _ := json.Marshal(data)

	// Create notification history for each user
	for userID := range userMap {
		history := models.NotificationHistory{
			UserID: userID,
			Title:  title,
			Body:   body,
			Data:   string(dataJSON),
			Status: status,
			SentAt: time.Now(),
		}

		if err := s.db.Create(&history).Error; err != nil {
			// Log this error but don't fail the request
			log.Printf("Error creating notification history for user %s: %v\n", userID, err)
		}
	}

	return success, err
}

// sendExpoNotificationSDK sends push notifications using the Expo SDK
func (s *DefaultNotificationSender) sendExpoNotificationSDK(tokenStrings []string, title, body string, data map[string]interface{}) (bool, error) {
	// Convert string tokens to ExponentPushToken
	var pushTokens []expo.ExponentPushToken
	var invalidTokens []string
	
	for _, tokenString := range tokenStrings {
		pushToken, err := expo.NewExponentPushToken(tokenString)
		if err != nil {
			log.Printf("Invalid push token format %s: %v", tokenString, err)
			invalidTokens = append(invalidTokens, tokenString)
			continue // Skip invalid tokens instead of failing completely
		}
		pushTokens = append(pushTokens, pushToken)
	}

	if len(pushTokens) == 0 {
		return false, fmt.Errorf("no valid push tokens found")
	}

	// Convert data to map[string]string as required by the SDK
	var stringData map[string]string
	if data != nil {
		stringData = make(map[string]string)
		for key, value := range data {
			// Convert all values to strings
			stringData[key] = fmt.Sprintf("%v", value)
		}
	}

	// Create the push message
	pushMessage := &expo.PushMessage{
		To:       pushTokens,
		Body:     body,
		Title:    title,
		Sound:    "default",
		Priority: expo.DefaultPriority,
		Data:     stringData,
	}

	// Send the notification
	response, err := s.expoClient.Publish(pushMessage)
	if err != nil {
		return false, fmt.Errorf("failed to publish notification: %v", err)
	}

	// Check for any validation errors in the response
	if validationErr := response.ValidateResponse(); validationErr != nil {
		log.Printf("Push notification validation error: %v", validationErr)
		
		// Clean up invalid tokens from database
		s.cleanupInvalidTokens(invalidTokens)
		
		return false, fmt.Errorf("notification validation failed: %v", validationErr)
	}

	// Clean up any invalid tokens we found during token conversion
	if len(invalidTokens) > 0 {
		s.cleanupInvalidTokens(invalidTokens)
	}

	return true, nil
}

// Helper function to remove invalid tokens from database
func (s *DefaultNotificationSender) cleanupInvalidTokens(tokens []string) {
	for _, token := range tokens {
		if err := s.db.Where("token = ?", token).Delete(&models.Device{}).Error; err != nil {
			log.Printf("Error cleaning up invalid token %s: %v", token, err)
		} else {
			log.Printf("Cleaned up invalid token: %s", token)
		}
	}
}

func (h *SignalHandler) RegisterRoutes(router *mux.Router) {
	signalRouter := router.PathPrefix("/signals").Subrouter()

	// Base CRUD operations
	signalRouter.HandleFunc("", utils.AuthMiddleware(h.CreateSignal)).Methods("POST")
	signalRouter.HandleFunc("", utils.AuthMiddleware(h.GetSignals)).Methods("GET")
	signalRouter.HandleFunc("/{id:[0-9]+}", utils.AuthMiddleware(h.GetSignalByID)).Methods("GET")
	signalRouter.HandleFunc("/{id:[0-9]+}", utils.AuthMiddleware(h.UpdateSignal)).Methods("PUT")
	signalRouter.HandleFunc("/{id:[0-9]+}", utils.AuthMiddleware(h.DeleteSignal)).Methods("DELETE")

	// Filtered signal routes
	signalRouter.HandleFunc("/user/{userID:[0-9]+}", utils.AuthMiddleware(h.GetSignalsByUserID)).Methods("GET")
	signalRouter.HandleFunc("/pair/{pair}", utils.AuthMiddleware(h.GetSignalsByPair)).Methods("GET")
	signalRouter.HandleFunc("/action/{action}", utils.AuthMiddleware(h.GetSignalsByAction)).Methods("GET")
	signalRouter.HandleFunc("/action/{outcome}", utils.AuthMiddleware(h.GetSignalsByAction)).Methods("GET")

	// Batch operations
	signalRouter.HandleFunc("/batch", utils.AuthMiddleware(h.CreateBatchSignals)).Methods("POST")
	signalRouter.HandleFunc("/batch", utils.AuthMiddleware(h.DeleteBatchSignals)).Methods("DELETE")

	// Analytics/Statistics
	signalRouter.HandleFunc("/stats", utils.AuthMiddleware(h.GetSignalStats)).Methods("GET")
	signalRouter.HandleFunc("/stats/user/{userID:[0-9]+}", utils.AuthMiddleware(h.GetUserSignalStats)).Methods("GET")

	signalRouter.HandleFunc("/payment/initialize", utils.AuthMiddleware(h.InitializeSignalPayment)).Methods("POST")
}


// CreateSignal creates a new signal
func (h *SignalHandler) CreateSignal(w http.ResponseWriter, r *http.Request) {
	userID, err := utils.GetUserIDFromContext(r.Context())
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var signal models.Signal
	if err := json.NewDecoder(r.Body).Decode(&signal); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Set the user ID from the context
	signal.UserID = userID

	// Create the signal
	if err := h.db.Create(&signal).Error; err != nil {
		http.Error(w, "Error creating signal", http.StatusInternalServerError)
		return
	}

	// Send notification to users about the new signal
	// Get users with active signal subscriptions
	var subscriberIDs []string
	h.db.Model(&models.SignalSubscription{}).
		Where("status = ? AND NOW() BETWEEN start_date AND end_date", "active").
		Pluck("user_id", &subscriberIDs)

	// Convert userIDs from uint to string for the notification system
	var subscriberIDStrings []string
	for _, id := range subscriberIDs {
		subscriberIDStrings = append(subscriberIDStrings, id)
	}

	// Get user information for better notification content
	var user models.User
	h.db.First(&user, userID)

	// Create notification data for deep linking
	notificationData := map[string]interface{}{
		"type":      "new_signal",
		"signalId":  signal.ID,
		"creatorId": userID,
		"pair":      signal.Pair,
		"action":    signal.Action,
	}

	// Prepare notification content
	title := fmt.Sprintf("New %s Signal for %s", signal.Action, signal.Pair)
	body := fmt.Sprintf("%s by %s", signal.Commentary, user.FullName)
	if len(body) > 100 {
		body = body[:97] + "..."
	}

	// Send the notification in the background
	go func() {
		success, err := h.notificationSender.BroadcastNotification(
			title,
			body,
			notificationData,
			subscriberIDStrings,
		)

		if !success || err != nil {
			log.Printf("Failed to send signal notification: %v", err)
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(signal)
}
// Define a custom response structure that only includes the fields you want
type SignalWithUserInfo struct {
	ID           uint      `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Pair         string    `json:"pair"`
	Action       string    `json:"action"`
	StopLoss     float64   `json:"stop_loss"`
	TakeProfits  []float64 `json:"take_profits"`
	Commentary   string    `json:"commentary"`
	Outcome      string    `json:"outcome"`
	UserID       uint      `json:"user_id"`
	UserFullName string    `json:"user_full_name"`
}

// In your GetSignals function
func (h *SignalHandler) GetSignals(w http.ResponseWriter, r *http.Request) {
	var signals []models.Signal

	// Parse pagination parameters
	page, perPage, err := ParsePaginationParams(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Calculate offset
	offset := (page - 1) * perPage

	// Get total count for pagination metadata
	var totalItems int64
	if err := h.db.Model(&models.Signal{}).Count(&totalItems).Error; err != nil {
		http.Error(w, "Error retrieving signals count", http.StatusInternalServerError)
		return
	}

	if err := h.db.Preload("User").Limit(perPage).Offset(offset).Find(&signals).Error; err != nil {
		http.Error(w, "Error retrieving signals", http.StatusInternalServerError)
		return
	}

	customResponse := make([]SignalWithUserInfo, len(signals))
	for i, signal := range signals {
		customResponse[i] = SignalWithUserInfo{
			ID:           signal.ID,
			CreatedAt:    signal.CreatedAt,
			UpdatedAt:    signal.UpdatedAt,
			Pair:         signal.Pair,
			Action:       signal.Action,
			StopLoss:     signal.StopLoss,
			TakeProfits:  signal.TakeProfits,
			Commentary:   signal.Commentary,
			Outcome:      signal.Outcome,
			UserID:       signal.User.ID,
			UserFullName: signal.User.FullName,
		}
	}

	// Calculate pagination metadata
	totalPages := int(math.Ceil(float64(totalItems) / float64(perPage)))
	paginationMeta := PaginationMeta{
		CurrentPage: page,
		PerPage:     perPage,
		TotalItems:  totalItems,
		TotalPages:  totalPages,
		HasPrevious: page > 1,
		HasNext:     page < totalPages,
	}

	// Prepare response
	response := PaginatedResponse{
		Data:       customResponse,
		Pagination: paginationMeta,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetSignalByID retrieves a specific signal by ID
func (h *SignalHandler) GetSignalByID(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid signal ID", http.StatusBadRequest)
		return
	}

	var signal models.Signal
	if err := h.db.Preload("User").First(&signal, id).Error; err != nil {
		http.Error(w, "Signal not found", http.StatusNotFound)
		return
	}

	// Structuring the response
	response := SignalWithUserInfo{
		ID:           signal.ID,
		CreatedAt:    signal.CreatedAt,
		UpdatedAt:    signal.UpdatedAt,
		Pair:         signal.Pair,
		Action:       signal.Action,
		StopLoss:     signal.StopLoss,
		TakeProfits:  signal.TakeProfits,
		Commentary:   signal.Commentary,
		Outcome:      signal.Outcome,
		UserID:       signal.User.ID,
		UserFullName: signal.User.FullName,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// UpdateSignal updates an existing signal
func (h *SignalHandler) UpdateSignal(w http.ResponseWriter, r *http.Request) {
	userID, err := utils.GetUserIDFromContext(r.Context())
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid signal ID", http.StatusBadRequest)
		return
	}

	var updatedSignal models.Signal
	if err := json.NewDecoder(r.Body).Decode(&updatedSignal); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var signal models.Signal
	if err := h.db.First(&signal, id).Error; err != nil {
		http.Error(w, "Signal not found", http.StatusNotFound)
		return
	}

	// Verify the user owns this signal
	if signal.UserID != userID {
		http.Error(w, "Unauthorized: you don't have permission to update this signal", http.StatusForbidden)
		return
	}

	// Check if outcome is being updated
	outcomeChanged := signal.Outcome != updatedSignal.Outcome && updatedSignal.Outcome != ""

	// Update signal fields
	signal.Pair = updatedSignal.Pair
	signal.Action = updatedSignal.Action
	signal.StopLoss = updatedSignal.StopLoss
	signal.TakeProfits = updatedSignal.TakeProfits
	signal.Commentary = updatedSignal.Commentary
	signal.Outcome = updatedSignal.Outcome

	if err := h.db.Save(&signal).Error; err != nil {
		http.Error(w, "Error updating signal", http.StatusInternalServerError)
		return
	}

	// If outcome has been updated, send notification to subscribers
	if outcomeChanged {
		// Get users with active signal subscriptions
		var subscriberIDs []string
		h.db.Model(&models.SignalSubscription{}).
			Where("status = ? AND NOW() BETWEEN start_date AND end_date", "active").
			Pluck("user_id", &subscriberIDs)

		// Convert userIDs from uint to string for the notification system
		var subscriberIDStrings []string
		for _, id := range subscriberIDs {
			subscriberIDStrings = append(subscriberIDStrings, id)
		}

		// Get user information for better notification content
		var user models.User
		h.db.First(&user, userID)

		// Prepare notification content based on outcome
		title := fmt.Sprintf("Signal Outcome Update: %s", signal.Pair)
		var body string

		switch updatedSignal.Outcome {
		case "win":
			body = fmt.Sprintf("✅ %s signal for %s was successful", signal.Action, signal.Pair)
		case "loss":
			body = fmt.Sprintf("❌ %s signal for %s hit stop loss", signal.Action, signal.Pair)
		case "partial":
			body = fmt.Sprintf("⚠️ %s signal for %s had partial profit", signal.Action, signal.Pair)
		default:
			body = fmt.Sprintf("Signal for %s has been updated to %s", signal.Pair, updatedSignal.Outcome)
		}

		// Create notification data for deep linking
		notificationData := map[string]interface{}{
			"type":     "signal_outcome",
			"signalId": signal.ID,
			"outcome":  updatedSignal.Outcome,
			"pair":     signal.Pair,
			"action":   signal.Action,
		}

		// Send the notification in the background
		go func() {
			success, err := h.notificationSender.BroadcastNotification(
				title,
				body,
				notificationData,
				subscriberIDStrings,
			)

			if !success || err != nil {
				log.Printf("Failed to send signal outcome notification: %v", err)
			}
		}()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(signal)
}

// DeleteSignal deletes a signal
func (h *SignalHandler) DeleteSignal(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid signal ID", http.StatusBadRequest)
		return
	}

	result := h.db.Delete(&models.Signal{}, id)
	if result.Error != nil {
		http.Error(w, "Error deleting signal", http.StatusInternalServerError)
		return
	}

	if result.RowsAffected == 0 {
		http.Error(w, "Signal not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Signal deleted successfully",
	})
}

// GetSignalsByUserID retrieves all signals for a specific user
func (h *SignalHandler) GetSignalsByUserID(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["userID"])
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Parse pagination parameters
	page, perPage, err := ParsePaginationParams(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Calculate offset
	offset := (page - 1) * perPage

	// Get total count for pagination metadata
	var totalItems int64
	if err := h.db.Model(&models.Signal{}).Where("user_id = ?", userID).Count(&totalItems).Error; err != nil {
		http.Error(w, "Error retrieving signals count", http.StatusInternalServerError)
		return
	}

	// Get paginated signals with user information
	var signals []models.Signal
	if err := h.db.Preload("User").Where("user_id = ?", userID).Limit(perPage).Offset(offset).Find(&signals).Error; err != nil {
		http.Error(w, "Error retrieving signals", http.StatusInternalServerError)
		return
	}

	// Transform signals to match `SignalWithUserInfo` format
	customResponse := make([]SignalWithUserInfo, len(signals))
	for i, signal := range signals {
		customResponse[i] = SignalWithUserInfo{
			ID:           signal.ID,
			CreatedAt:    signal.CreatedAt,
			UpdatedAt:    signal.UpdatedAt,
			Pair:         signal.Pair,
			Action:       signal.Action,
			StopLoss:     signal.StopLoss,
			TakeProfits:  signal.TakeProfits,
			Commentary:   signal.Commentary,
			Outcome:      signal.Outcome,
			UserID:       signal.User.ID,
			UserFullName: signal.User.FullName,
		}
	}

	// Calculate pagination metadata
	totalPages := int(math.Ceil(float64(totalItems) / float64(perPage)))
	paginationMeta := PaginationMeta{
		CurrentPage: page,
		PerPage:     perPage,
		TotalItems:  totalItems,
		TotalPages:  totalPages,
		HasPrevious: page > 1,
		HasNext:     page < totalPages,
	}

	// Prepare response
	response := PaginatedResponse{
		Data:       customResponse,
		Pagination: paginationMeta,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetSignalsByPair retrieves all signals for a specific pair
func (h *SignalHandler) GetSignalsByPair(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pair := vars["pair"]

	// Parse pagination parameters
	page, perPage, err := ParsePaginationParams(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Calculate offset
	offset := (page - 1) * perPage

	// Get total count for pagination metadata
	var totalItems int64
	if err := h.db.Model(&models.Signal{}).Where("pair = ?", pair).Count(&totalItems).Error; err != nil {
		http.Error(w, "Error retrieving signals count", http.StatusInternalServerError)
		return
	}

	// Get paginated signals with user information
	var signals []models.Signal
	if err := h.db.Preload("User").Where("pair = ?", pair).Limit(perPage).Offset(offset).Find(&signals).Error; err != nil {
		http.Error(w, "Error retrieving signals", http.StatusInternalServerError)
		return
	}

	// Transform signals to match `SignalWithUserInfo` format
	customResponse := make([]SignalWithUserInfo, len(signals))
	for i, signal := range signals {
		customResponse[i] = SignalWithUserInfo{
			ID:           signal.ID,
			CreatedAt:    signal.CreatedAt,
			UpdatedAt:    signal.UpdatedAt,
			Pair:         signal.Pair,
			Action:       signal.Action,
			StopLoss:     signal.StopLoss,
			TakeProfits:  signal.TakeProfits,
			Commentary:   signal.Commentary,
			Outcome:      signal.Outcome,
			UserID:       signal.User.ID,
			UserFullName: signal.User.FullName,
		}
	}

	// Calculate pagination metadata
	totalPages := int(math.Ceil(float64(totalItems) / float64(perPage)))
	paginationMeta := PaginationMeta{
		CurrentPage: page,
		PerPage:     perPage,
		TotalItems:  totalItems,
		TotalPages:  totalPages,
		HasPrevious: page > 1,
		HasNext:     page < totalPages,
	}

	// Prepare response
	response := PaginatedResponse{
		Data:       customResponse,
		Pagination: paginationMeta,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetSignalsByAction retrieves all signals for a specific action (buy/sell)
func (h *SignalHandler) GetSignalsByAction(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	action := vars["action"]

	// Parse pagination parameters
	page, perPage, err := ParsePaginationParams(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Calculate offset
	offset := (page - 1) * perPage

	// Get total count for pagination metadata
	var totalItems int64
	if err := h.db.Model(&models.Signal{}).Where("action = ?", action).Count(&totalItems).Error; err != nil {
		http.Error(w, "Error retrieving signals count", http.StatusInternalServerError)
		return
	}

	// Get paginated signals with user information
	var signals []models.Signal
	if err := h.db.Preload("User").Where("action = ?", action).Limit(perPage).Offset(offset).Find(&signals).Error; err != nil {
		http.Error(w, "Error retrieving signals", http.StatusInternalServerError)
		return
	}

	// Transform signals to match `SignalWithUserInfo` format
	customResponse := make([]SignalWithUserInfo, len(signals))
	for i, signal := range signals {
		customResponse[i] = SignalWithUserInfo{
			ID:           signal.ID,
			CreatedAt:    signal.CreatedAt,
			UpdatedAt:    signal.UpdatedAt,
			Pair:         signal.Pair,
			Action:       signal.Action,
			StopLoss:     signal.StopLoss,
			TakeProfits:  signal.TakeProfits,
			Commentary:   signal.Commentary,
			Outcome:      signal.Outcome,
			UserID:       signal.User.ID,
			UserFullName: signal.User.FullName,
		}
	}

	// Calculate pagination metadata
	totalPages := int(math.Ceil(float64(totalItems) / float64(perPage)))
	paginationMeta := PaginationMeta{
		CurrentPage: page,
		PerPage:     perPage,
		TotalItems:  totalItems,
		TotalPages:  totalPages,
		HasPrevious: page > 1,
		HasNext:     page < totalPages,
	}

	// Prepare response
	response := PaginatedResponse{
		Data:       customResponse,
		Pagination: paginationMeta,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *SignalHandler) GetSignalsByOutcome(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	outcome := vars["outcome"]

	// Parse pagination parameters
	page, perPage, err := ParsePaginationParams(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Calculate offset
	offset := (page - 1) * perPage

	// Get total count for pagination metadata
	var totalItems int64
	if err := h.db.Model(&models.Signal{}).Where("outcome = ?", outcome).Count(&totalItems).Error; err != nil {
		http.Error(w, "Error retrieving signals count", http.StatusInternalServerError)
		return
	}

	// Get paginated signals with user information
	var signals []models.Signal
	if err := h.db.Preload("User").Where("outcome = ?", outcome).Limit(perPage).Offset(offset).Find(&signals).Error; err != nil {
		http.Error(w, "Error retrieving signals", http.StatusInternalServerError)
		return
	}

	// Transform signals to match `SignalWithUserInfo` format
	customResponse := make([]SignalWithUserInfo, len(signals))
	for i, signal := range signals {
		customResponse[i] = SignalWithUserInfo{
			ID:           signal.ID,
			CreatedAt:    signal.CreatedAt,
			UpdatedAt:    signal.UpdatedAt,
			Pair:         signal.Pair,
			Action:       signal.Action,
			StopLoss:     signal.StopLoss,
			TakeProfits:  signal.TakeProfits,
			Commentary:   signal.Commentary,
			Outcome:      signal.Outcome,
			UserID:       signal.User.ID,
			UserFullName: signal.User.FullName,
		}
	}

	// Calculate pagination metadata
	totalPages := int(math.Ceil(float64(totalItems) / float64(perPage)))
	paginationMeta := PaginationMeta{
		CurrentPage: page,
		PerPage:     perPage,
		TotalItems:  totalItems,
		TotalPages:  totalPages,
		HasPrevious: page > 1,
		HasNext:     page < totalPages,
	}

	// Prepare response
	response := PaginatedResponse{
		Data:       customResponse,
		Pagination: paginationMeta,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// CreateBatchSignals creates multiple signals at once
func (h *SignalHandler) CreateBatchSignals(w http.ResponseWriter, r *http.Request) {
	userID, err := utils.GetUserIDFromContext(r.Context())
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var signals []models.Signal
	if err := json.NewDecoder(r.Body).Decode(&signals); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Set the user ID for all signals
	for i := range signals {
		signals[i].UserID = userID
	}

	// Create the signals in a transaction
	err = h.db.Transaction(func(tx *gorm.DB) error {
		for i := range signals {
			if err := tx.Create(&signals[i]).Error; err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		http.Error(w, "Error creating signals: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Get users with active signal subscriptions
	var subscriberIDs []string
	h.db.Model(&models.SignalSubscription{}).
		Where("status = ? AND NOW() BETWEEN start_date AND end_date", "active").
		Pluck("user_id", &subscriberIDs)

	// Convert userIDs from uint to string for the notification system
	var subscriberIDStrings []string
	for _, id := range subscriberIDs {
		subscriberIDStrings = append(subscriberIDStrings, id)
	}

	// Get user information for better notification content
	var user models.User
	h.db.First(&user, userID)

	// Send a single notification about the batch
	title := fmt.Sprintf("New Batch of Trading Signals")
	body := fmt.Sprintf("%d new signals from %s", len(signals), user.FullName)

	// Create notification data
	notificationData := map[string]interface{}{
		"type":      "new_signal_batch",
		"count":     len(signals),
		"creatorId": userID,
	}

	// Send the notification in the background
	go func() {
		success, err := h.notificationSender.BroadcastNotification(
			title,
			body,
			notificationData,
			subscriberIDStrings,
		)

		if !success || err != nil {
			log.Printf("Failed to send batch signal notification: %v", err)
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(signals)
}

// DeleteBatchSignals deletes multiple signals by their IDs
func (h *SignalHandler) DeleteBatchSignals(w http.ResponseWriter, r *http.Request) {
	var request struct {
		IDs []uint `json:"ids"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if len(request.IDs) == 0 {
		http.Error(w, "No signal IDs provided", http.StatusBadRequest)
		return
	}

	result := h.db.Delete(&models.Signal{}, request.IDs)
	if result.Error != nil {
		http.Error(w, "Error deleting signals", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":       "Signals deleted successfully",
		"deleted_count": result.RowsAffected,
	})
}

// GetSignalStats retrieves statistics about signals
func (h *SignalHandler) GetSignalStats(w http.ResponseWriter, r *http.Request) {
	var stats struct {
		TotalCount   int64          `json:"total_count"`
		PairCounts   map[string]int `json:"pair_counts"`
		ActionCounts map[string]int `json:"action_counts"`
		UserCounts   map[string]int `json:"user_counts"`
	}

	// Initialize maps
	stats.PairCounts = make(map[string]int)
	stats.ActionCounts = make(map[string]int)
	stats.UserCounts = make(map[string]int)

	// Get total count
	h.db.Model(&models.Signal{}).Count(&stats.TotalCount)

	// Get pair counts
	var pairResults []struct {
		Pair  string
		Count int
	}
	h.db.Model(&models.Signal{}).Select("pair, count(*) as count").Group("pair").Find(&pairResults)
	for _, result := range pairResults {
		stats.PairCounts[result.Pair] = result.Count
	}

	// Get action counts
	var actionResults []struct {
		Action string
		Count  int
	}
	h.db.Model(&models.Signal{}).Select("action, count(*) as count").Group("action").Find(&actionResults)
	for _, result := range actionResults {
		stats.ActionCounts[result.Action] = result.Count
	}

	// Get user counts
	var userResults []struct {
		UserID string
		Count  int
	}
	h.db.Model(&models.Signal{}).Select("user_id, count(*) as count").Group("user_id").Find(&userResults)
	for _, result := range userResults {
		stats.UserCounts[result.UserID] = result.Count
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// GetUserSignalStats retrieves statistics about a specific user's signals
func (h *SignalHandler) GetUserSignalStats(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["userID"])
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var stats struct {
		TotalCount   int64          `json:"total_count"`
		PairCounts   map[string]int `json:"pair_counts"`
		ActionCounts map[string]int `json:"action_counts"`
	}

	// Initialize maps
	stats.PairCounts = make(map[string]int)
	stats.ActionCounts = make(map[string]int)

	// Get total count for user
	h.db.Model(&models.Signal{}).Where("user_id = ?", userID).Count(&stats.TotalCount)

	// Get pair counts for user
	var pairResults []struct {
		Pair  string
		Count int
	}
	h.db.Model(&models.Signal{}).
		Select("pair, count(*) as count").
		Where("user_id = ?", userID).
		Group("pair").
		Find(&pairResults)

	for _, result := range pairResults {
		stats.PairCounts[result.Pair] = result.Count
	}

	// Get action counts for user
	var actionResults []struct {
		Action string
		Count  int
	}
	h.db.Model(&models.Signal{}).
		Select("action, count(*) as count").
		Where("user_id = ?", userID).
		Group("action").
		Find(&actionResults)

	for _, result := range actionResults {
		stats.ActionCounts[result.Action] = result.Count
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// InitializeSignalPayment initializes payment for signal subscriptions
func (h *SignalHandler) InitializeSignalPayment(w http.ResponseWriter, r *http.Request) {
	userID, err := utils.GetUserIDFromContext(r.Context())
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var paymentRequest struct {
		Amount     float64 `json:"amount"`
		SignalPlan string  `json:"signal_plan"`
	}

	if err := json.NewDecoder(r.Body).Decode(&paymentRequest); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Start transaction
	tx := h.db.Begin()

	// Get user information for payment
	var user models.User
	if err := tx.First(&user, userID).Error; err != nil {
		tx.Rollback()
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Create a reference ID for this payment
	reference := fmt.Sprintf("SIG-%d-%d", userID, time.Now().Unix())

	// Create a pending signal subscription
	signalSubscription := models.SignalSubscription{
		UserID:    userID,
		Plan:      paymentRequest.SignalPlan,
		Amount:    paymentRequest.Amount,
		Status:    "pending",
		PaymentID: reference,
		StartDate: time.Time{},
		EndDate:   time.Time{},
	}

	if err := tx.Create(&signalSubscription).Error; err != nil {
		tx.Rollback()
		http.Error(w, "Error creating signal subscription", http.StatusInternalServerError)
		return
	}

	// Initialize Paystack payment
	paystackURL := "https://api.paystack.co/transaction/initialize"

	paystackReq := map[string]interface{}{
		"email":     user.Email,
		"amount":    int64(paymentRequest.Amount * 100), // Convert to smallest unit
		"reference": reference,
		"metadata": map[string]interface{}{
			"payment_type": "signal_subscription",
			"user_id":      userID,
			"signal_plan":  paymentRequest.SignalPlan,
		},
	}
	log.Printf("Payload to Paystack: %+v\n", paystackReq)

	payloadBytes, _ := json.Marshal(paystackReq)
	req, _ := http.NewRequest("POST", paystackURL, bytes.NewBuffer(payloadBytes))
	req.Header.Set("Authorization", "Bearer "+os.Getenv("PAYSTACK_SECRET_KEY"))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		tx.Rollback()
		http.Error(w, "Error initializing payment", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var paystackResp struct {
		Status bool `json:"status"`
		Data   struct {
			AuthorizationURL string `json:"authorization_url"`
			AccessCode       string `json:"access_code"`
			Reference        string `json:"reference"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&paystackResp); err != nil {
		tx.Rollback()
		http.Error(w, "Error reading payment response", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit().Error; err != nil {
		http.Error(w, "Error completing initialization", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"authorization_url": paystackResp.Data.AuthorizationURL,
		"reference":         reference,
		"subscription_id":   signalSubscription.ID,
	})
}
