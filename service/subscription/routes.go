package subscription

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"gorm.io/gorm"
	"github.com/KAsare1/Kodefx-server/cmd/models"
	"github.com/KAsare1/Kodefx-server/cmd/utils"
)

// Response is a standardized API response structure
type Response struct {
	Data  interface{} `json:"data,omitempty"`
	Meta  interface{} `json:"meta,omitempty"`
	Error string      `json:"error,omitempty"`
}

// SubscriptionFilter represents all possible filters for subscriptions
type SubscriptionFilter struct {
	UserID     uint
	Plan       string
	Status     string
	MinAmount  float64
	MaxAmount  float64
	StartDate  time.Time
	EndDate    time.Time
	IsExpired  *bool // Pointer to handle three states: nil (not filtered), true, false
}

// SubscriptionResponse extends the subscription model with calculated fields
type SubscriptionResponse struct {
	models.SignalSubscription
	IsExpired bool `json:"is_expired"`
}

// SubscriptionHandler handles subscription-related HTTP requests
type SubscriptionHandler struct {
	db *gorm.DB
}

// NewSubscriptionHandler creates a new subscription handler
func NewSubscriptionHandler(db *gorm.DB) *SubscriptionHandler {
	return &SubscriptionHandler{db: db}
}

// RegisterRoutes registers all subscription routes
func (h *SubscriptionHandler) RegisterRoutes(router *mux.Router) {
	subscriptionRouter := router.PathPrefix("/subscriptions").Subrouter()

	// List all subscriptions with filters
	subscriptionRouter.HandleFunc("", utils.AuthMiddleware(h.GetSubscriptions)).Methods("GET")

	// Get a specific subscription by ID
	subscriptionRouter.HandleFunc("/{id:[0-9]+}", utils.AuthMiddleware(h.GetSubscription)).Methods("GET")

	// User subscription routes
	subscriptionRouter.HandleFunc("/user/{userID:[0-9]+}", utils.AuthMiddleware(h.GetUserSubscriptions)).Methods("GET")
	subscriptionRouter.HandleFunc("/user/{userID:[0-9]+}/active", utils.AuthMiddleware(h.GetActiveSubscription)).Methods("GET")
}

// GetSubscriptions handles retrieving subscriptions with various filters
func (h *SubscriptionHandler) GetSubscriptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	var filter SubscriptionFilter
	var err error
	
	// Parse query parameters
	queryParams := r.URL.Query()

	// Parse user_id filter
	if userIDStr := queryParams.Get("user_id"); userIDStr != "" {
		userID, err := strconv.ParseUint(userIDStr, 10, 32)
		if err == nil {
			filter.UserID = uint(userID)
		}
	}

	// Parse plan filter
	filter.Plan = queryParams.Get("plan")

	// Parse status filter
	filter.Status = queryParams.Get("status")

	// Parse amount range filters
	if minAmountStr := queryParams.Get("min_amount"); minAmountStr != "" {
		filter.MinAmount, err = strconv.ParseFloat(minAmountStr, 64)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid min_amount parameter")
			return
		}
	}

	if maxAmountStr := queryParams.Get("max_amount"); maxAmountStr != "" {
		filter.MaxAmount, err = strconv.ParseFloat(maxAmountStr, 64)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid max_amount parameter")
			return
		}
	}

	// Parse date range filters
	layout := "2006-01-02"
	
	if startDateStr := queryParams.Get("start_date"); startDateStr != "" {
		filter.StartDate, err = time.Parse(layout, startDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid start_date format. Use YYYY-MM-DD")
			return
		}
	}

	if endDateStr := queryParams.Get("end_date"); endDateStr != "" {
		filter.EndDate, err = time.Parse(layout, endDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid end_date format. Use YYYY-MM-DD")
			return
		}
	}

	// Parse expired filter
	if expiredStr := queryParams.Get("expired"); expiredStr != "" {
		isExpired, err := strconv.ParseBool(expiredStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid expired parameter. Use 'true' or 'false'")
			return
		}
		filter.IsExpired = &isExpired
	}

	// Build query
	query := h.db.Model(&models.SignalSubscription{}).Preload("User")
	query = h.applySubscriptionFilters(query, filter)

	// Setup pagination
	pageStr := queryParams.Get("page")
	pageSizeStr := queryParams.Get("page_size")
	
	page := 1
	if pageStr != "" {
		pageVal, err := strconv.Atoi(pageStr)
		if err == nil && pageVal > 0 {
			page = pageVal
		}
	}
	
	pageSize := 10
	if pageSizeStr != "" {
		pageSizeVal, err := strconv.Atoi(pageSizeStr)
		if err == nil && pageSizeVal > 0 && pageSizeVal <= 100 {
			pageSize = pageSizeVal
		}
	}
	
	offset := (page - 1) * pageSize

	// Get total count of matching records
	var total int64
	query.Count(&total)

	// Execute the query with pagination
	var subscriptions []models.SignalSubscription
	result := query.Limit(pageSize).Offset(offset).Find(&subscriptions)
	if result.Error != nil {
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve subscriptions")
		return
	}

	// Transform subscriptions to include is_expired field
	var responseSubscriptions []SubscriptionResponse
	now := time.Now()
	for _, sub := range subscriptions {
		responseSubscriptions = append(responseSubscriptions, SubscriptionResponse{
			SignalSubscription: sub,
			IsExpired:          sub.EndDate.Before(now),
		})
	}

	// Create meta information
	meta := map[string]interface{}{
		"total":     total,
		"page":      page,
		"page_size": pageSize,
		"pages":     (total + int64(pageSize) - 1) / int64(pageSize),
	}

	// Send response
	h.respondWithJSON(w, http.StatusOK, Response{
		Data: responseSubscriptions,
		Meta: meta,
	})
}

// GetSubscription retrieves a single subscription by ID
func (h *SubscriptionHandler) GetSubscription(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.ParseUint(vars["id"], 10, 32)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid subscription ID")
		return
	}

	var subscription models.SignalSubscription
	if err := h.db.Preload("User").First(&subscription, id).Error; err != nil {
		h.respondWithError(w, http.StatusNotFound, "Subscription not found")
		return
	}

	// Check if subscription is expired
	now := time.Now()
	isExpired := subscription.EndDate.Before(now)

	response := SubscriptionResponse{
		SignalSubscription: subscription,
		IsExpired:          isExpired,
	}

	h.respondWithJSON(w, http.StatusOK, Response{Data: response})
}

// GetUserSubscriptions gets all subscriptions for a specific user
func (h *SubscriptionHandler) GetUserSubscriptions(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.ParseUint(vars["userID"], 10, 32)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	// Check if user exists
	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		h.respondWithError(w, http.StatusNotFound, "User not found")
		return
	}

	// Parse query parameters for expired filter
	queryParams := r.URL.Query()
	var isExpiredPtr *bool
	if expiredStr := queryParams.Get("expired"); expiredStr != "" {
		isExpired, err := strconv.ParseBool(expiredStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid expired parameter. Use 'true' or 'false'")
			return
		}
		isExpiredPtr = &isExpired
	}

	// Build query
	query := h.db.Model(&models.SignalSubscription{}).Where("user_id = ?", userID)

	// Apply expired filter if provided
	now := time.Now()
	if isExpiredPtr != nil {
		if *isExpiredPtr {
			// Find expired subscriptions
			query = query.Where("end_date < ?", now)
		} else {
			// Find active subscriptions
			query = query.Where("end_date >= ?", now)
		}
	}

	// Get subscriptions
	var subscriptions []models.SignalSubscription
	if err := query.Find(&subscriptions).Error; err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve subscriptions")
		return
	}

	// Transform subscriptions to include is_expired field
	var responseSubscriptions []SubscriptionResponse
	for _, sub := range subscriptions {
		responseSubscriptions = append(responseSubscriptions, SubscriptionResponse{
			SignalSubscription: sub,
			IsExpired:          sub.EndDate.Before(now),
		})
	}

	h.respondWithJSON(w, http.StatusOK, Response{Data: responseSubscriptions})
}

// GetActiveSubscription gets the current active subscription for a user
func (h *SubscriptionHandler) GetActiveSubscription(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.ParseUint(vars["userID"], 10, 32)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	// Find active subscription (not expired and status is active)
	now := time.Now()
	var subscription models.SignalSubscription
	
	err = h.db.Where("user_id = ? AND end_date >= ? AND status = ?", userID, now, "active").
		Order("end_date DESC").  // Get the subscription that expires the latest
		Preload("User").
		First(&subscription).Error
	
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, "No active subscription found for this user")
		return
	}

	response := SubscriptionResponse{
		SignalSubscription: subscription,
		IsExpired:          false, // By definition, this will be false since we queried for non-expired
	}

	h.respondWithJSON(w, http.StatusOK, Response{Data: response})
}

// applySubscriptionFilters applies filters to a subscription query
func (h *SubscriptionHandler) applySubscriptionFilters(query *gorm.DB, filter SubscriptionFilter) *gorm.DB {
	if filter.UserID != 0 {
		query = query.Where("user_id = ?", filter.UserID)
	}

	if filter.Plan != "" {
		query = query.Where("plan = ?", filter.Plan)
	}

	if filter.Status != "" {
		query = query.Where("status = ?", filter.Status)
	}

	if filter.MinAmount != 0 {
		query = query.Where("amount >= ?", filter.MinAmount)
	}

	if filter.MaxAmount != 0 {
		query = query.Where("amount <= ?", filter.MaxAmount)
	}

	if !filter.StartDate.IsZero() {
		query = query.Where("start_date >= ?", filter.StartDate)
	}

	if !filter.EndDate.IsZero() {
		query = query.Where("end_date <= ?", filter.EndDate)
	}

	// Handle expired filter
	now := time.Now()
	if filter.IsExpired != nil {
		if *filter.IsExpired {
			// Find expired subscriptions
			query = query.Where("end_date < ?", now)
		} else {
			// Find active subscriptions
			query = query.Where("end_date >= ?", now)
		}
	}

	return query
}

// Helper function to respond with an error
func (h *SubscriptionHandler) respondWithError(w http.ResponseWriter, code int, message string) {
	h.respondWithJSON(w, code, Response{Error: message})
}

// Helper function to respond with JSON
func (h *SubscriptionHandler) respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}