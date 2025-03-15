package api

import (
	"log"
	"net/http"

	"github.com/KAsare1/Kodefx-server/service/appointment"
	"github.com/KAsare1/Kodefx-server/service/availability"
	"github.com/KAsare1/Kodefx-server/service/dashboard"
	"github.com/KAsare1/Kodefx-server/service/forum"
	"github.com/KAsare1/Kodefx-server/service/signals"
	"github.com/KAsare1/Kodefx-server/service/subscription"
	"github.com/KAsare1/Kodefx-server/service/transactions"
	"github.com/KAsare1/Kodefx-server/service/user"
	service "github.com/KAsare1/Kodefx-server/service/ws"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"gorm.io/gorm"
)

type APIServer struct {
	address string
	db      *gorm.DB
}

func NewApiServer(address string, db *gorm.DB) *APIServer {
	return &APIServer{
		address: address,
		db:      db,
	}
}

func (s *APIServer) Run() error {
	router := mux.NewRouter()
	subrouter := router.PathPrefix("/api/v1").Subrouter()

	userHandler := user.NewHandler(s.db)
	userHandler.RegisterRoutes(subrouter)

	appointmentHandler := appointment.NewAppointmentHandler(s.db)
	appointmentHandler.RegisterRoutes(subrouter)

	availabilityHandler := availability.NewAvailabilityHandler(s.db)
	availabilityHandler.RegisterRoutes(subrouter)

	forumHandler := forum.NewPostHandler(s.db)
	forumHandler.RegisterRoutes(subrouter)

	chatHandler := service.NewChatHandler(s.db)
	chatHandler.RegisterRoutes(subrouter)

	signalHandler := signals.NewSignalHandler(s.db)
	signalHandler.RegisterRoutes(subrouter)

	subsHandler := subscription.NewSubscriptionHandler(s.db)
	subsHandler.RegisterRoutes(subrouter)

	transHandler := transactions.NewTransactionHandler(s.db)
	transHandler.RegisterRoutes(subrouter)

	dashboardHandler := dashboard.NewDashboardHandler(s.db)
	dashboardHandler.RegisterRoutes(subrouter)

	// CORS configuration to allow all origins
	corsMiddleware := handlers.CORS(
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"}),
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization", "X-Requested-With", "Accept"}),
		handlers.AllowCredentials(),
	)

	// Apply CORS middleware to the router
	corsRouter := corsMiddleware(router)

	log.Println("Server running at", s.address)
	return http.ListenAndServe(s.address, corsRouter)
}