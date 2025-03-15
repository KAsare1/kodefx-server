package transactions

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
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

// PaginatedResponse represents the standard paginated API response structure
type PaginatedResponse struct {
	Data       interface{}   `json:"data"`
	Pagination PaginationMeta `json:"pagination"`
	Error      string        `json:"error,omitempty"`
}

// PaginationMeta contains pagination metadata
type PaginationMeta struct {
	CurrentPage  int   `json:"current_page"`
	PerPage      int   `json:"per_page"`
	TotalItems   int64 `json:"total_items"`
	TotalPages   int   `json:"total_pages"`
	HasPrevious  bool  `json:"has_previous"`
	HasNext      bool  `json:"has_next"`
}


type PaystackTransaction struct {
	ID        int     `json:"id"`
	Domain    string  `json:"domain"`
	Status    string  `json:"status"`
	Reference string  `json:"reference"`
	Amount    float64 `json:"amount"`
	Channel   string  `json:"channel"`
	Currency  string  `json:"currency"`
	PaidAt    string  `json:"paid_at"`
	CreatedAt string  `json:"created_at"`
	Customer  struct {
		Email string `json:"email"`
	} `json:"customer"`
	Metadata map[string]interface{} `json:"metadata"`
}

// PaystackResponse represents Paystack API response structure
type PaystackResponse struct {
	Status  bool                  `json:"status"`
	Message string                `json:"message"`
	Data    []PaystackTransaction `json:"data"`
	Meta    struct {
		Next     string `json:"next"`
		Previous string `json:"previous"`
		PerPage  int    `json:"perPage"`
	} `json:"meta"`
}

// SimplifiedTransaction is your custom transaction format
type SimplifiedTransaction struct {
	Amount  string `json:"amount"`
	Method  string `json:"method"`
	Purpose string `json:"purpose"`
	Date    string `json:"date"`
	Time    string `json:"time"`
}


type TransactionHandler struct {
	db *gorm.DB
}

func NewTransactionHandler(db *gorm.DB) *TransactionHandler {
	return &TransactionHandler{db: db}
}

// RegisterRoutes registers transaction-related routes with Gorilla Mux
func (h *TransactionHandler) RegisterRoutes(router *mux.Router) {
	transactionRouter := router.PathPrefix("/transactions").Subrouter()

	transactionRouter.HandleFunc("", utils.AuthMiddleware(h.GetPaystackTransactions)).Methods("GET")
	transactionRouter.HandleFunc("/batch", utils.AuthMiddleware(h.CreateBatchTransactions)).Methods("POST")
}

// ParsePaginationParams extracts and validates pagination parameters from request
func ParsePaginationParams(r *http.Request) (int, int, error) {
	query := r.URL.Query()
	
	// Parse page number (default to 1)
	page := 1
	if query.Get("page") != "" {
		parsedPage, err := strconv.Atoi(query.Get("page"))
		if err != nil || parsedPage < 1 {
			return 0, 0, err
		}
		page = parsedPage
	}
	
	// Parse per_page (default to 10, cap at 100)
	perPage := 10
	if query.Get("per_page") != "" {
		parsedPerPage, err := strconv.Atoi(query.Get("per_page"))
		if err != nil || parsedPerPage < 1 {
			return 0, 0, err
		}
		if parsedPerPage > 100 {
			perPage = 100 // Cap at 100 to prevent excessive queries
		} else {
			perPage = parsedPerPage
		}
	}
	
	return page, perPage, nil
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

	// Parse pagination parameters (using new consistent helper)
	page, perPage, err := ParsePaginationParams(r)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid pagination parameters")
		return
	}
	
	// Calculate offset
	offset := (page - 1) * perPage

	// Get total count of matching records
	var totalItems int64
	query.Count(&totalItems)

	// Execute the query with pagination
	var transactions []models.Transaction
	result := query.Limit(perPage).Offset(offset).Find(&transactions)
	if result.Error != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to retrieve transactions")
		return
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

	// Send response
	respondWithJSON(w, http.StatusOK, PaginatedResponse{
		Data:       transactions,
		Pagination: paginationMeta,
	})
}




func (h *TransactionHandler) GetPaystackTransactions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Create request to Paystack API
	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://api.paystack.co/transaction", nil)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to create request")
		return
	}

	// Get API key from environment or config (adjust to your setup)
	apiKey := os.Getenv("PAYSTACK_SECRET_KEY") // You would need to implement this function
	req.Header.Set("Authorization", "Bearer "+apiKey)

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to connect to Paystack API")
		return
	}
	defer resp.Body.Close()

	// Parse response
	var paystackResp PaystackResponse
	if err := json.NewDecoder(resp.Body).Decode(&paystackResp); err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to parse Paystack response")
		return
	}

	// Transform data
	var simplifiedTransactions []SimplifiedTransaction
	for _, transaction := range paystackResp.Data {
		// Extract date and time
		paidAt, err := time.Parse(time.RFC3339, transaction.PaidAt)
		if err != nil {
			continue // Skip this transaction if date parsing fails
		}
		
		// Format amount (convert from kobo/pesewas to cedis)
		amount := fmt.Sprintf("GHS %.2f", float64(transaction.Amount)/100)
		
		// Extract reference and determine purpose
		var reference string
		if transaction.Metadata != nil {
			// Try to find reference in metadata, adjust this according to your metadata structure
			if customFields, ok := transaction.Metadata["custom_fields"].([]interface{}); ok {
				for _, field := range customFields {
					if fieldMap, ok := field.(map[string]interface{}); ok {
						if varName, ok := fieldMap["variable_name"].(string); ok && varName == "reference" {
							if value, ok := fieldMap["value"].(string); ok {
								reference = value
							}
						}
					}
				}
			}
		}

		// If no reference in metadata, use the transaction reference
		if reference == "" {
			reference = transaction.Reference
		}
		
		// Determine purpose based on reference prefix
		purpose := "Other"
		if strings.HasPrefix(reference, "APT-") {
			purpose = "Appointment Booking"
		} else if strings.HasPrefix(reference, "SIG-") {
			purpose = "Subscription"
		}
		
		// Create simplified transaction
		simplifiedTransaction := SimplifiedTransaction{
			Amount:  amount,
			Method:  transaction.Channel,
			Purpose: purpose,
			Date:    paidAt.Format("2006-01-02"),
			Time:    paidAt.Format("15:04:05"),
		}
		
		simplifiedTransactions = append(simplifiedTransactions, simplifiedTransaction)
	}

	// Parse pagination parameters (using your existing function)
	page, perPage, err := ParsePaginationParams(r)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid pagination parameters")
		return
	}
	
	// Apply pagination manually since we've transformed the data
	totalItems := int64(len(simplifiedTransactions))
	totalPages := int(math.Ceil(float64(totalItems) / float64(perPage)))
	
	// Calculate start and end indices
	startIndex := (page - 1) * perPage
	endIndex := startIndex + perPage
	
	// Check bounds
	if startIndex >= int(totalItems) {
		startIndex = 0
		endIndex = 0
	} else if endIndex > int(totalItems) {
		endIndex = int(totalItems)
	}
	
	// Get paginated subset
	paginatedTransactions := simplifiedTransactions
	if len(simplifiedTransactions) > 0 {
		paginatedTransactions = simplifiedTransactions[startIndex:endIndex]
	}
	
	// Prepare pagination metadata
	paginationMeta := PaginationMeta{
		CurrentPage: page,
		PerPage:     perPage,
		TotalItems:  totalItems,
		TotalPages:  totalPages,
		HasPrevious: page > 1,
		HasNext:     page < totalPages,
	}

	// Send response
	respondWithJSON(w, http.StatusOK, PaginatedResponse{
		Data:       paginatedTransactions,
		Pagination: paginationMeta,
	})
}




type BatchTransactionRequest struct {
	Transactions []models.Transaction `json:"transactions"`
}

// Add Batch Transactions endpoint
func (h *TransactionHandler) CreateBatchTransactions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Parse request body
	var batchRequest BatchTransactionRequest
	if err := json.NewDecoder(r.Body).Decode(&batchRequest); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Ensure there are transactions to insert
	if len(batchRequest.Transactions) == 0 {
		respondWithError(w, http.StatusBadRequest, "No transactions provided")
		return
	}

	// Insert transactions into the database
	if err := h.db.Create(&batchRequest.Transactions).Error; err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to insert transactions")
		return
	}

	// Respond with success
	respondWithJSON(w, http.StatusCreated, map[string]string{"message": "Batch transactions created successfully"})
}



// Helper function to respond with an error
func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, PaginatedResponse{Error: message})
}

// Helper function to respond with JSON
func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(payload)
}