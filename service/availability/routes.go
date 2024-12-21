package availability

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/KAsare1/Kodefx-server/cmd/models"
	"github.com/gorilla/mux"
	"gorm.io/gorm"
)

type AvailabilityHandler struct {
    db *gorm.DB
}

func NewAvailabilityHandler(db *gorm.DB) *AvailabilityHandler {
    return &AvailabilityHandler{db: db}
}


func (h *AvailabilityHandler) RegisterRoutes(router *mux.Router) {
    router.HandleFunc("/experts/{expertId}/availability", h.CreateAvailability).Methods("POST")
    router.HandleFunc("/experts/{expertId}/availability", h.GetAvailabilities).Methods("GET")
    router.HandleFunc("/experts/{expertId}/availability/{id}", h.GetAvailability).Methods("GET")
    router.HandleFunc("/experts/{expertId}/availability/{id}", h.UpdateAvailability).Methods("PUT")
    router.HandleFunc("/experts/{expertId}/availability/{id}", h.DeleteAvailability).Methods("DELETE")
    router.HandleFunc("/experts/{expertId}/availability/date/{date}", h.GetAvailabilitiesByDate).Methods("GET")
}




func (h *AvailabilityHandler) CreateAvailability(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    expertID, err := strconv.Atoi(vars["expertId"])
    if err != nil {
        http.Error(w, "Invalid expert ID", http.StatusBadRequest)
        return
    }

    var availability models.Availability
    if err := json.NewDecoder(r.Body).Decode(&availability); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Validate time slots
    if availability.EndTime.Before(availability.StartTime) {
        http.Error(w, "End time must be after start time", http.StatusBadRequest)
        return
    }

    // Check for overlapping slots
    var existingAvailability models.Availability
    overlap := h.db.Where("expert_id = ? AND date = ? AND ((start_time < ? AND end_time > ?) OR (start_time < ? AND end_time > ?))",
        expertID,
        availability.Date,
        availability.EndTime,
        availability.StartTime,
        availability.StartTime,
        availability.EndTime,
    ).First(&existingAvailability)

    if overlap.Error != nil && overlap.Error != gorm.ErrRecordNotFound {
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }

    if overlap.Error == nil {
        http.Error(w, "Time slot overlaps with existing availability", http.StatusConflict)
        return
    }

    // Assign the expert ID
    availability.ExpertID = uint(expertID)

    // Create availability
    if err := h.db.Create(&availability).Error; err != nil {
        http.Error(w, "Error creating availability", http.StatusInternalServerError)
        return
    }

    // Send success response
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(availability)
}




func (h *AvailabilityHandler) GetAvailabilities(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    expertID, err := strconv.ParseUint(vars["expertId"], 10, 64)
    if err != nil {
        http.Error(w, "Invalid expert ID", http.StatusBadRequest)
        return
    }

    // Parse query parameters
    startDate := r.URL.Query().Get("start_date")
    endDate := r.URL.Query().Get("end_date")
    category := r.URL.Query().Get("category")
    page, _ := strconv.Atoi(r.URL.Query().Get("page"))
    if page < 1 {
        page = 1
    }
    pageSize := 10

    query := h.db.Model(&models.Availability{}).Where("expert_id = ?", expertID)

    // Apply filters
    if startDate != "" {
        query = query.Where("date >= ?", startDate)
    }
    if endDate != "" {
        query = query.Where("date <= ?", endDate)
    }
    if category != "" {
        query = query.Where("category = ?", category)
    }

    // Get total count
    var total int64
    query.Count(&total)

    // Get paginated results
    var availabilities []models.Availability
    result := query.Offset((page - 1) * pageSize).Limit(pageSize).Find(&availabilities)
    if result.Error != nil {
        http.Error(w, "Error retrieving availabilities", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "availabilities": availabilities,
        "total":         total,
        "page":          page,
        "page_size":     pageSize,
        "total_pages":   (total + int64(pageSize) - 1) / int64(pageSize),
    })
}

func (h *AvailabilityHandler) GetAvailability(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    expertID, err := strconv.ParseUint(vars["expertId"], 10, 64)
    if err != nil {
        http.Error(w, "Invalid expert ID", http.StatusBadRequest)
        return
    }

    availabilityID, err := strconv.ParseUint(vars["id"], 10, 64)
    if err != nil {
        http.Error(w, "Invalid availability ID", http.StatusBadRequest)
        return
    }

    var availability models.Availability
    if err := h.db.Where("id = ? AND expert_id = ?", availabilityID, expertID).First(&availability).Error; err != nil {
        http.Error(w, "Availability not found", http.StatusNotFound)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(availability)
}

func (h *AvailabilityHandler) UpdateAvailability(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    expertID, err := strconv.ParseUint(vars["expertId"], 10, 64)
    if err != nil {
        http.Error(w, "Invalid expert ID", http.StatusBadRequest)
        return
    }

    availabilityID, err := strconv.ParseUint(vars["id"], 10, 64)
    if err != nil {
        http.Error(w, "Invalid availability ID", http.StatusBadRequest)
        return
    }

    var updateData models.Availability
    if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    var availability models.Availability
    if err := h.db.Where("id = ? AND expert_id = ?", availabilityID, expertID).First(&availability).Error; err != nil {
        http.Error(w, "Availability not found", http.StatusNotFound)
        return
    }

    // Check for overlapping slots (excluding current slot)
    var existingAvailability models.Availability
    overlap := h.db.Where("id != ? AND expert_id = ? AND date = ? AND ((start_time <= ? AND end_time >= ?) OR (start_time <= ? AND end_time >= ?))",
        availabilityID,
        expertID,
        updateData.Date,
        updateData.EndTime,
        updateData.StartTime,
        updateData.EndTime,
        updateData.StartTime,
		updateData.Price,
    ).First(&existingAvailability)

    if overlap.Error == nil {
        http.Error(w, "Time slot overlaps with existing availability", http.StatusConflict)
        return
    }

    // Update fields
    availability.EventName = updateData.EventName
    availability.Note = updateData.Note
    availability.Date = updateData.Date
    availability.StartTime = updateData.StartTime
    availability.EndTime = updateData.EndTime
    availability.Reminder = updateData.Reminder
    availability.Category = updateData.Category
	availability.Price = updateData.Price

    if err := h.db.Save(&availability).Error; err != nil {
        http.Error(w, "Error updating availability", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(availability)
}

func (h *AvailabilityHandler) DeleteAvailability(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    expertID, err := strconv.ParseUint(vars["expertId"], 10, 64)
    if err != nil {
        http.Error(w, "Invalid expert ID", http.StatusBadRequest)
        return
    }

    availabilityID, err := strconv.ParseUint(vars["id"], 10, 64)
    if err != nil {
        http.Error(w, "Invalid availability ID", http.StatusBadRequest)
        return
    }

    result := h.db.Where("id = ? AND expert_id = ?", availabilityID, expertID).Delete(&models.Availability{})
    if result.Error != nil {
        http.Error(w, "Error deleting availability", http.StatusInternalServerError)
        return
    }

    if result.RowsAffected == 0 {
        http.Error(w, "Availability not found", http.StatusNotFound)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "message": "Availability deleted successfully",
    })
}

func (h *AvailabilityHandler) GetAvailabilitiesByDate(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    expertID, err := strconv.ParseUint(vars["expertId"], 10, 64)
    if err != nil {
        http.Error(w, "Invalid expert ID", http.StatusBadRequest)
        return
    }

    dateStr := vars["date"]
    date, err := time.Parse("2006-01-02", dateStr)
    if err != nil {
        http.Error(w, "Invalid date format. Use YYYY-MM-DD", http.StatusBadRequest)
        return
    }

    var availabilities []models.Availability
    if err := h.db.Where("expert_id = ? AND date = ?", expertID, date).Find(&availabilities).Error; err != nil {
        http.Error(w, "Error retrieving availabilities", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(availabilities)
}