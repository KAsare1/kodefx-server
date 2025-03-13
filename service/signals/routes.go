package signals

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/KAsare1/Kodefx-server/cmd/models"
	"github.com/KAsare1/Kodefx-server/cmd/utils"
	"github.com/gorilla/mux"
	"gorm.io/gorm"
	
)

type SignalHandler struct {
	db *gorm.DB
}

func NewSignalHandler(db *gorm.DB) *SignalHandler {
	return &SignalHandler{db: db}
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

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(signal)
}



// GetSignals retrieves all signals
func (h *SignalHandler) GetSignals(w http.ResponseWriter, r *http.Request) {
	var signals []models.Signal
	
	// Parse query parameters
	query := r.URL.Query()
	limit := 100 // Default limit
	if query.Get("limit") != "" {
		parsedLimit, err := strconv.Atoi(query.Get("limit"))
		if err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}
	
	offset := 0
	if query.Get("offset") != "" {
		parsedOffset, err := strconv.Atoi(query.Get("offset"))
		if err == nil && parsedOffset >= 0 {
			offset = parsedOffset
		}
	}
	
	// Apply pagination
	if err := h.db.Limit(limit).Offset(offset).Find(&signals).Error; err != nil {
		http.Error(w, "Error retrieving signals", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(signals)
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
	if err := h.db.First(&signal, id).Error; err != nil {
		http.Error(w, "Signal not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(signal)
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

    // Update signal fields
    signal.Pair = updatedSignal.Pair
    signal.Action = updatedSignal.Action
    signal.StopLoss = updatedSignal.StopLoss
    signal.TakeProfits = updatedSignal.TakeProfits
    signal.Commentary = updatedSignal.Commentary

    if err := h.db.Save(&signal).Error; err != nil {
        http.Error(w, "Error updating signal", http.StatusInternalServerError)
        return
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

	var signals []models.Signal
	if err := h.db.Where("user_id = ?", userID).Find(&signals).Error; err != nil {
		http.Error(w, "Error retrieving signals", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(signals)
}

// GetSignalsByPair retrieves all signals for a specific pair
func (h *SignalHandler) GetSignalsByPair(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pair := vars["pair"]

	var signals []models.Signal
	if err := h.db.Where("pair = ?", pair).Find(&signals).Error; err != nil {
		http.Error(w, "Error retrieving signals", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(signals)
}

// GetSignalsByAction retrieves all signals for a specific action (buy/sell)
func (h *SignalHandler) GetSignalsByAction(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	action := vars["action"]

	var signals []models.Signal
	if err := h.db.Where("action = ?", action).Find(&signals).Error; err != nil {
		http.Error(w, "Error retrieving signals", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(signals)
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
        UserID:       userID,
        Plan:         paymentRequest.SignalPlan,
        Amount:       paymentRequest.Amount,
        Status:       "pending",
        PaymentID:    reference,
        StartDate:    time.Time{}, 
        EndDate:      time.Time{},
    }

    if err := tx.Create(&signalSubscription).Error; err != nil {
        tx.Rollback()
        http.Error(w, "Error creating signal subscription", http.StatusInternalServerError)
        return
    }

    // Initialize Paystack payment
    paystackURL := "https://api.paystack.co/transaction/initialize"
    
    paystackReq := map[string]interface{}{
        "email": user.Email,
        "amount": int64(paymentRequest.Amount * 100), // Convert to smallest unit
        "reference": reference,
        "metadata": map[string]interface{}{
            "payment_type": "signal_subscription",
            "user_id": userID,
            "signal_plan": paymentRequest.SignalPlan,
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
        Status  bool `json:"status"`
        Data    struct {
            AuthorizationURL string `json:"authorization_url"`
            AccessCode      string `json:"access_code"`
            Reference      string `json:"reference"`
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
        "reference": reference,
        "subscription_id": signalSubscription.ID,
    })
}