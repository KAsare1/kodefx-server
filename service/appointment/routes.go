package appointment

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/KAsare1/Kodefx-server/cmd/models"
	"github.com/gorilla/mux"
	"gorm.io/gorm"
)

type AppointmentHandler struct {
    db *gorm.DB
}

func NewAppointmentHandler(db *gorm.DB) *AppointmentHandler {
    return &AppointmentHandler{db: db}
}


func (h *AppointmentHandler) RegisterRoutes(router *mux.Router) {
    router.HandleFunc("/appointments/book", h.BookAppointment).Methods("POST")
    router.HandleFunc("/appointments", h.GetAllAppointments).Methods("GET")
    router.HandleFunc("/appointments/{id}", h.GetAppointment).Methods("GET")
    // router.HandleFunc("/appointments/{id}/cancel", h.CancelAppointment).Methods("PATCH")
    router.HandleFunc("/appointments/trader/{traderId}", h.GetTraderAppointments).Methods("GET")
    router.HandleFunc("/appointments/expert/{expertId}", h.GetExpertAppointments).Methods("GET")
    router.HandleFunc("/appointments/{id}/payment", h.UpdatePaymentStatus).Methods("PATCH")
}


func (h *AppointmentHandler) BookAppointment(w http.ResponseWriter, r *http.Request) {
    var bookingRequest struct {
        TraderID       uint    `json:"trader_id"`
        AvailabilityID uint    `json:"availability_id"`
        PaymentID      string  `json:"payment_id"`
    }

    if err := json.NewDecoder(r.Body).Decode(&bookingRequest); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    tx := h.db.Begin()


    var availability models.Availability
    if err := tx.First(&availability, bookingRequest.AvailabilityID).Error; err != nil {
        tx.Rollback()
        http.Error(w, "Time slot not found", http.StatusNotFound)
        return
    }


    var existingAppointment models.Appointment
    if err := tx.Where("availability_id = ? AND status != ?", 
        bookingRequest.AvailabilityID, "Cancelled").
        First(&existingAppointment).Error; err == nil {
        tx.Rollback()
        http.Error(w, "Time slot already booked", http.StatusConflict)
        return
    }

    appointment := models.Appointment{
        TraderID:        bookingRequest.TraderID,
        ExpertID:        availability.ExpertID,
        AvailabilityID:  bookingRequest.AvailabilityID,
        AppointmentDate: availability.Date,
        StartTime:       availability.StartTime,
        EndTime:         availability.EndTime,
        Status:          "Confirmed",
        PaymentStatus:   "paid",
        Amount:          availability.Price,
        PaymentID:       bookingRequest.PaymentID,
        EventName:       availability.EventName,
        Category:        availability.Category,
    }

    if err := tx.Create(&appointment).Error; err != nil {
        tx.Rollback()
        http.Error(w, "Error creating appointment", http.StatusInternalServerError)
        return
    }

    if err := tx.Commit().Error; err != nil {
        http.Error(w, "Error completing booking", http.StatusInternalServerError)
        return
    }


    h.db.Preload("Trader").Preload("Expert").First(&appointment, appointment.ID)

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(appointment)
}


func (h *AppointmentHandler) GetAllAppointments(w http.ResponseWriter, r *http.Request) {
    page, _ := strconv.Atoi(r.URL.Query().Get("page"))
    if page < 1 {
        page = 1
    }
    pageSize := 10

    query := h.db.Model(&models.Appointment{}).Preload("Trader").Preload("Expert")

    // Apply filters
    if status := r.URL.Query().Get("status"); status != "" {
        query = query.Where("status = ?", status)
    }
    if date := r.URL.Query().Get("date"); date != "" {
        query = query.Where("appointment_date = ?", date)
    }

    var total int64
    query.Count(&total)

    var appointments []models.Appointment
    if err := query.Offset((page - 1) * pageSize).Limit(pageSize).
        Order("appointment_date DESC, start_time DESC").Find(&appointments).Error; err != nil {
        http.Error(w, "Error retrieving appointments", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "appointments": appointments,
        "total":       total,
        "page":        page,
        "page_size":   pageSize,
        "total_pages": (total + int64(pageSize) - 1) / int64(pageSize),
    })
}

// GetAppointment retrieves a specific appointment by ID
func (h *AppointmentHandler) GetAppointment(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    appointmentID, err := strconv.ParseUint(vars["id"], 10, 64)
    if err != nil {
        http.Error(w, "Invalid appointment ID", http.StatusBadRequest)
        return
    }

    var appointment models.Appointment
    if err := h.db.Preload("Trader").Preload("Expert").First(&appointment, appointmentID).Error; err != nil {
        http.Error(w, "Appointment not found", http.StatusNotFound)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(appointment)
}

// CancelAppointment handles appointment cancellation
// func (h *AppointmentHandler) CancelAppointment(w http.ResponseWriter, r *http.Request) {
//     vars := mux.Vars(r)
//     appointmentID, err := strconv.ParseUint(vars["id"], 10, 64)
//     if err != nil {
//         http.Error(w, "Invalid appointment ID", http.StatusBadRequest)
//         return
//     }

//     var appointment models.Appointment
//     if err := h.db.First(&appointment, appointmentID).Error; err != nil {
//         http.Error(w, "Appointment not found", http.StatusNotFound)
//         return
//     }

//     // Check if appointment can be cancelled (e.g., not too close to start time)
//     if appointment.StartTime.Sub(time.Now()) < 10*time.Minute {
//         http.Error(w, "Cannot cancel appointments less than 24 hours before start time", http.StatusBadRequest)
//         return
//     }

//     tx := h.db.Begin()

//     // Update appointment status
//     if err := tx.Model(&appointment).Updates(map[string]interface{}{
//         "status": "Cancelled",
//         "payment_status": "refunded",
//     }).Error; err != nil {
//         tx.Rollback()
//         http.Error(w, "Error cancelling appointment", http.StatusInternalServerError)
//         return
//     }

//     // TODO: Handle refund through payment processor
//     // processRefund(appointment.PaymentID)

//     tx.Commit()

//     w.Header().Set("Content-Type", "application/json")
//     json.NewEncoder(w).Encode(map[string]string{
//         "message": "Appointment cancelled successfully",
//     })
// }

// GetTraderAppointments retrieves all appointments for a specific trader
func (h *AppointmentHandler) GetTraderAppointments(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    traderID, err := strconv.ParseUint(vars["traderId"], 10, 64)
    if err != nil {
        http.Error(w, "Invalid trader ID", http.StatusBadRequest)
        return
    }

    page, _ := strconv.Atoi(r.URL.Query().Get("page"))
    if page < 1 {
        page = 1
    }
    pageSize := 10

    query := h.db.Model(&models.Appointment{}).Where("trader_id = ?", traderID).
        Preload("Expert").Preload("Availability")

    var total int64
    query.Count(&total)

    var appointments []models.Appointment
    if err := query.Offset((page - 1) * pageSize).Limit(pageSize).
        Order("appointment_date DESC, start_time DESC").Find(&appointments).Error; err != nil {
        http.Error(w, "Error retrieving appointments", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "appointments": appointments,
        "total":       total,
        "page":        page,
        "page_size":   pageSize,
        "total_pages": (total + int64(pageSize) - 1) / int64(pageSize),
    })
}

// GetExpertAppointments retrieves all appointments for a specific expert
func (h *AppointmentHandler) GetExpertAppointments(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    expertID, err := strconv.ParseUint(vars["expertId"], 10, 64)
    if err != nil {
        http.Error(w, "Invalid expert ID", http.StatusBadRequest)
        return
    }

    page, _ := strconv.Atoi(r.URL.Query().Get("page"))
    if page < 1 {
        page = 1
    }
    pageSize := 10

    query := h.db.Model(&models.Appointment{}).Where("expert_id = ?", expertID).
        Preload("Trader").Preload("Availability")

    var total int64
    query.Count(&total)

    var appointments []models.Appointment
    if err := query.Offset((page - 1) * pageSize).Limit(pageSize).
        Order("appointment_date DESC, start_time DESC").Find(&appointments).Error; err != nil {
        http.Error(w, "Error retrieving appointments", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "appointments": appointments,
        "total":       total,
        "page":        page,
        "page_size":   pageSize,
        "total_pages": (total + int64(pageSize) - 1) / int64(pageSize),
    })
}

// UpdatePaymentStatus updates the payment status of an appointment
func (h *AppointmentHandler) UpdatePaymentStatus(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    appointmentID, err := strconv.ParseUint(vars["id"], 10, 64)
    if err != nil {
        http.Error(w, "Invalid appointment ID", http.StatusBadRequest)
        return
    }

    var paymentUpdate struct {
        PaymentStatus string `json:"payment_status"`
        PaymentID     string `json:"payment_id"`
    }
    if err := json.NewDecoder(r.Body).Decode(&paymentUpdate); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    result := h.db.Model(&models.Appointment{}).Where("id = ?", appointmentID).
        Updates(map[string]interface{}{
            "payment_status": paymentUpdate.PaymentStatus,
            "payment_id":    paymentUpdate.PaymentID,
        })

    if result.Error != nil {
        http.Error(w, "Error updating payment status", http.StatusInternalServerError)
        return
    }

    if result.RowsAffected == 0 {
        http.Error(w, "Appointment not found", http.StatusNotFound)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "message": "Payment status updated successfully",
    })
}