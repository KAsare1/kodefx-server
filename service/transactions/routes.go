package transactions

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/KAsare1/Kodefx-server/cmd/models"
	"github.com/KAsare1/Kodefx-server/cmd/utils"
	"github.com/gorilla/mux"
	"gorm.io/gorm"
)

// TransactionFilter represents all possible filters for transactions
type TransactionFilter struct {
	UserID    uint
	Method    string
	Purpose   string
	MinAmount float64
	MaxAmount float64
	StartDate time.Time
	EndDate   time.Time
}

// Response represents the standard API response structure
type Response struct {
	Data  interface{} `json:"data"`
	Meta  interface{} `json:"meta,omitempty"`
	Error string      `json:"error,omitempty"`
}


type TransactionHandler struct {
	db *gorm.DB
}

func NewTransactionHandler(db *gorm.DB) *TransactionHandler{
	return &TransactionHandler{db: db}
}

// RegisterTransactionRoutes registers transaction-related routes with Gorilla Mux
func (h *TransactionHandler) RegisterRoutes(router *mux.Router) {
	transactionRouter := router.PathPrefix("/transactions").Subrouter()

	transactionRouter.HandleFunc("", utils.AuthMiddleware(h.GetTransactions)).Methods("GET")
}


// GetTransactions handles retrieving transactions with various filters
func (h *TransactionHandler) GetTransactions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	var filter TransactionFilter
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

	// Parse method filter
	filter.Method = queryParams.Get("method")

	// Parse purpose filter
	filter.Purpose = queryParams.Get("purpose")

	// Parse amount range filters
	if minAmountStr := queryParams.Get("min_amount"); minAmountStr != "" {
		filter.MinAmount, err = strconv.ParseFloat(minAmountStr, 64)
		if err != nil {
			respondWithError(w, http.StatusBadRequest, "Invalid min_amount parameter")
			return
		}
	}

	if maxAmountStr := queryParams.Get("max_amount"); maxAmountStr != "" {
		filter.MaxAmount, err = strconv.ParseFloat(maxAmountStr, 64)
		if err != nil {
			respondWithError(w, http.StatusBadRequest, "Invalid max_amount parameter")
			return
		}
	}

	// Parse date range filters
	layout := "2006-01-02"
	
	if startDateStr := queryParams.Get("start_date"); startDateStr != "" {
		filter.StartDate, err = time.Parse(layout, startDateStr)
		if err != nil {
			respondWithError(w, http.StatusBadRequest, "Invalid start_date format. Use YYYY-MM-DD")
			return
		}
	}

	if endDateStr := queryParams.Get("end_date"); endDateStr != "" {
		filter.EndDate, err = time.Parse(layout, endDateStr)
		if err != nil {
			respondWithError(w, http.StatusBadRequest, "Invalid end_date format. Use YYYY-MM-DD")
			return
		}
	}

	// Build query
	query := h.db.Model(&models.Transaction{}).Preload("User")

	// Apply filters
	if filter.UserID != 0 {
		query = query.Where("user_id = ?", filter.UserID)
	}

	if filter.Method != "" {
		query = query.Where("method = ?", filter.Method)
	}

	if filter.Purpose != "" {
		query = query.Where("purpose LIKE ?", "%"+filter.Purpose+"%")
	}

	if filter.MinAmount != 0 {
		query = query.Where("amount >= ?", filter.MinAmount)
	}

	if filter.MaxAmount != 0 {
		query = query.Where("amount <= ?", filter.MaxAmount)
	}

	if !filter.StartDate.IsZero() {
		query = query.Where("created_at >= ?", filter.StartDate)
	}

	if !filter.EndDate.IsZero() {
		// Add one day to include the end date fully
		endDatePlusDay := filter.EndDate.Add(24 * time.Hour)
		query = query.Where("created_at < ?", endDatePlusDay)
	}

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
	var transactions []models.Transaction
	result := query.Limit(pageSize).Offset(offset).Find(&transactions)
	if result.Error != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to retrieve transactions")
		return
	}

	// Create meta information
	meta := map[string]interface{}{
		"total":     total,
		"page":      page,
		"page_size": pageSize,
		"pages":     (total + int64(pageSize) - 1) / int64(pageSize),
	}

	// Send response
	respondWithJSON(w, http.StatusOK, Response{
		Data: transactions,
		Meta: meta,
	})
}

// Helper function to respond with an error
func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, Response{Error: message})
}

// Helper function to respond with JSON
func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(payload)
}