package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/KAsare1/Kodefx-server/cmd/models"
	"github.com/KAsare1/Kodefx-server/cmd/utils"
	"github.com/gorilla/mux"
	"gorm.io/gorm"
)

type DashboardHandler struct {
	db *gorm.DB
}

func NewDashboardHandler(db *gorm.DB) *DashboardHandler {
	return &DashboardHandler{db: db}
}

type DashboardStats struct {
	TotalTraders int64   `json:"total_traders"`
	TotalExperts int64   `json:"total_experts"`
	TotalIncome  float64 `json:"total_income"`
}

// RegisterRoutes registers dashboard-related routes with Gorilla Mux
func (h *DashboardHandler) RegisterRoutes(router *mux.Router) {
	dashboardRouter := router.PathPrefix("/dashboard").Subrouter()
	dashboardRouter.HandleFunc("/stats", utils.AuthMiddleware(h.GetDashboardStats)).Methods("GET")
}

func (h *DashboardHandler) GetDashboardStats(w http.ResponseWriter, r *http.Request) {
	var stats DashboardStats
	var tradersCount, expertsCount int64

	// Count Traders
	h.db.Model(&models.User{}).Where("role = ?", "trader").Count(&tradersCount)
	stats.TotalTraders = tradersCount

	// Count Experts
	h.db.Model(&models.Expert{}).Count(&expertsCount)
	stats.TotalExperts = expertsCount

	// Fetch Total Income from Paystack
	income, err := h.FetchTotalIncome()
	if err != nil {
		http.Error(w, "Failed to fetch total income", http.StatusInternalServerError)
		return
	}
	stats.TotalIncome = income

	// Return JSON Response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (h *DashboardHandler) FetchTotalIncome() (float64, error) {
	paystackURL := "https://api.paystack.co/transaction/totals"
	apiKey := os.Getenv("PAYSTACK_SECRET_KEY") // Use environment variable

	req, err := http.NewRequest("GET", paystackURL, nil)
	if err != nil {
		return 0, err
	}

	req.Header.Set("Authorization", "Bearer "+apiKey)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var response struct {
		Status bool `json:"status"`
		Data   struct {
			TotalVolume float64 `json:"total_volume"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return 0, err
	}

	if !response.Status {
		return 0, fmt.Errorf("failed to fetch income from Paystack")
	}

	return response.Data.TotalVolume, nil
}
