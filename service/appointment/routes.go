package appointment

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

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

    router.HandleFunc("/appointments/initialize-payment", h.InitializeAppointmentPayment).Methods("POST")
    router.HandleFunc("/appointments/webhook", h.HandlePaystackWebhook).Methods("POST")
    
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
    pageSize := 100

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
    pageSize := 100

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
    pageSize := 100

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








type PaystackInitializeResponse struct {
    Status  bool `json:"status"`
    Data    struct {
        AuthorizationURL string `json:"authorization_url"`
        AccessCode      string `json:"access_code"`
        Reference      string `json:"reference"`
    } `json:"data"`
}

type PaystackWebhookPayload struct {
    Event string `json:"event"`
    Data  struct {
        Reference  string `json:"reference"`
        Status    string `json:"status"`
        Amount    float64 `json:"amount"`
    } `json:"data"`
}

func (h *AppointmentHandler) InitializeAppointmentPayment(w http.ResponseWriter, r *http.Request) {
    var initRequest struct {
        TraderID       uint    `json:"trader_id"`
        AvailabilityID uint    `json:"availability_id"`
    }

    if err := json.NewDecoder(r.Body).Decode(&initRequest); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Start transaction
    tx := h.db.Begin()

    // Check availability
    var availability models.Availability
    if err := tx.First(&availability, initRequest.AvailabilityID).Error; err != nil {
        tx.Rollback()
        http.Error(w, "Time slot not found", http.StatusNotFound)
        return
    }

    // Check for existing appointments
    var existingAppointment models.Appointment
    if err := tx.Where("availability_id = ? AND status != ?", initRequest.AvailabilityID, "Cancelled").
        First(&existingAppointment).Error; err == nil {
        tx.Rollback()
        http.Error(w, "Time slot already booked", http.StatusConflict)
        return
    }

    // Create pending appointment
    appointment := models.Appointment{
        TraderID:        initRequest.TraderID,
        ExpertID:        availability.ExpertID,
        AvailabilityID:  initRequest.AvailabilityID,
        AppointmentDate: availability.Date,
        StartTime:       availability.StartTime,
        EndTime:         availability.EndTime,
        Status:          "Pending",
        PaymentStatus:   "pending",
        Amount:          availability.Price,
        EventName:       availability.EventName,
        Category:        availability.Category,
    }

    if err := tx.Create(&appointment).Error; err != nil {
        tx.Rollback()
        http.Error(w, "Error creating appointment", http.StatusInternalServerError)
        return
    }

    // Initialize Paystack payment
    paystackURL := "https://api.paystack.co/transaction/initialize"
    var trader models.User
    if err := tx.First(&trader, initRequest.TraderID).Error; err != nil {
        tx.Rollback()
        http.Error(w, "Trader not found", http.StatusNotFound)
        return
    }

    reference := fmt.Sprintf("APT-%d-%d", appointment.ID, time.Now().Unix())

    paystackReq := map[string]interface{}{
        "email": trader.Email,
        "amount": int64(availability.Price * 100), // Convert price to smallest unit
        "reference": reference,
        "metadata": map[string]interface{}{
            "appointment_id": appointment.ID,
            "trader_id": initRequest.TraderID,
            "expert_id": availability.ExpertID,
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

    // Update appointment with payment reference
    appointment.PaymentID = reference
    if err := tx.Save(&appointment).Error; err != nil {
        tx.Rollback()
        http.Error(w, "Error updating appointment", http.StatusInternalServerError)
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
        "appointment_id": appointment.ID,
    })
}


//TODO: SEPERATE THE TWO ENDPOINTS FOR RECEIVEING WEBHOOKS OR JUST MOVE THIS TO A SEPERATE FOLDER/PACKAGE
// HandlePaystackWebhook processes the payment webhook from Paystack
func (h *AppointmentHandler) HandlePaystackWebhook(w http.ResponseWriter, r *http.Request) {
    // Verify Paystack webhook signature
    paystackSignature := r.Header.Get("X-Paystack-Signature")
    body, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "Error reading request body", http.StatusBadRequest)
        return
    }

    // Verify signature
    mac := hmac.New(sha512.New, []byte(os.Getenv("PAYSTACK_SECRET_KEY")))
    mac.Write(body)
    expectedMAC := hex.EncodeToString(mac.Sum(nil))
    if !hmac.Equal([]byte(paystackSignature), []byte(expectedMAC)) {
        http.Error(w, "Invalid signature", http.StatusBadRequest)
        return
    }

    var webhookPayload struct {
        Event string `json:"event"`
        Data  struct {
            Reference string  `json:"reference"`
            Status    string  `json:"status"`
            Amount    float64 `json:"amount"`
            Metadata  struct {
                PaymentType    string `json:"payment_type"`
                AppointmentID  uint   `json:"appointment_id,omitempty"`
                UserID         uint   `json:"user_id,omitempty"`
                TraderID       uint   `json:"trader_id,omitempty"`
                ExpertID       uint   `json:"expert_id,omitempty"`
                SignalPlan     string `json:"signal_plan,omitempty"`
            } `json:"metadata"`
        } `json:"data"`
    }

    if err := json.Unmarshal(body, &webhookPayload); err != nil {
        http.Error(w, "Error parsing webhook payload", http.StatusBadRequest)
        return
    }

    // Only process successful charge events
    if webhookPayload.Event != "charge.success" {
        w.WriteHeader(http.StatusOK)
        return
    }

    tx := h.db.Begin()

    // Determine payment type from the reference or metadata
    paymentType := ""
    if strings.HasPrefix(webhookPayload.Data.Reference, "APT-") {
        paymentType = "appointment"
    } else if strings.HasPrefix(webhookPayload.Data.Reference, "SIG-") {
        paymentType = "signal_subscription"
    } else if webhookPayload.Data.Metadata.PaymentType != "" {
        paymentType = webhookPayload.Data.Metadata.PaymentType
    }

    // Process different payment types
    switch paymentType {
    case "appointment":
        // Find and update appointment
        var appointment models.Appointment
        if err := tx.Where("payment_id = ?", webhookPayload.Data.Reference).First(&appointment).Error; err != nil {
            tx.Rollback()
            http.Error(w, "Appointment not found", http.StatusNotFound)
            return
        }

        // Update appointment status
        appointment.PaymentStatus = "paid"
        appointment.Status = "Confirmed"
        if err := tx.Save(&appointment).Error; err != nil {
            tx.Rollback()
            http.Error(w, "Error updating appointment", http.StatusInternalServerError)
            return
        }

        // Create a new transaction record
        transaction := models.Transaction{
            UserID:  appointment.TraderID,
            Amount:  webhookPayload.Data.Amount / 100, 
            Method:  "Paystack", 
            Purpose: "Appointment", 
        }

        if err := tx.Create(&transaction).Error; err != nil {
            tx.Rollback()
            http.Error(w, "Error creating transaction", http.StatusInternalServerError)
            return
        }

    case "signal_subscription":
        // Get user ID from metadata or parse from reference if needed
        userID := webhookPayload.Data.Metadata.UserID
        
        // If userID is 0, try to extract from reference (SIG-123-timestamp)
        if userID == 0 && strings.HasPrefix(webhookPayload.Data.Reference, "SIG-") {
            parts := strings.Split(webhookPayload.Data.Reference, "-")
            if len(parts) > 1 {
                extractedID, err := strconv.ParseUint(parts[1], 10, 32)
                if err == nil {
                    userID = uint(extractedID)
                }
            }
        }
        
        // Find and update subscription
        var subscription models.SignalSubscription
        if err := tx.Where("payment_id = ?", webhookPayload.Data.Reference).First(&subscription).Error; err != nil {
            tx.Rollback()
            http.Error(w, "Subscription not found", http.StatusNotFound)
            return
        }

        // Calculate subscription duration based on plan
        now := time.Now()
        var endDate time.Time
        
        switch subscription.Plan {
        case "monthly":
            endDate = now.AddDate(0, 1, 0)
        case "quarterly":
            endDate = now.AddDate(0, 3, 0)
        case "annual":
            endDate = now.AddDate(1, 0, 0)
        default:
            endDate = now.AddDate(0, 1, 0) // Default to monthly
        }

        // Update subscription status
        subscription.Status = "active"
        subscription.StartDate = now
        subscription.EndDate = endDate
        
        if err := tx.Save(&subscription).Error; err != nil {
            tx.Rollback()
            http.Error(w, "Error updating subscription", http.StatusInternalServerError)
            return
        }

        // Create a new transaction record
        transaction := models.Transaction{
            UserID:  userID,
            Amount:  webhookPayload.Data.Amount / 100, // Convert from smallest unit
            Method:  "Paystack", 
            Purpose: "Signal Subscription - " + subscription.Plan, 
        }

        if err := tx.Create(&transaction).Error; err != nil {
            tx.Rollback()
            http.Error(w, "Error creating transaction", http.StatusInternalServerError)
            return
        }
        
    default:
        // Unknown payment type
        tx.Rollback()
        log.Printf("Unknown payment type for reference: %s", webhookPayload.Data.Reference)
        w.WriteHeader(http.StatusOK) // Still return 200 to avoid repeated webhooks
        return
    }

    if err := tx.Commit().Error; err != nil {
        http.Error(w, "Error completing webhook processing", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
}