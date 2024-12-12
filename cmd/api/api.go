package api

import (
	"log"
	"net/http"

	"github.com/KAsare1/Kodefx-server/service"
	"github.com/KAsare1/Kodefx-server/service/appointment"
	"github.com/KAsare1/Kodefx-server/service/availability"
	"github.com/KAsare1/Kodefx-server/service/forum"
	"github.com/KAsare1/Kodefx-server/service/user"
	"github.com/gorilla/mux"
	"gorm.io/gorm"

	"github.com/swaggo/http-swagger"
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

// @title           Kodefx API
// @version         1.0
// @description     API server for Kodefx application
// @host            localhost:8080
// @BasePath        /api/v1
func (s *APIServer) Run() error {
	router := mux.NewRouter()
	subrouter := router.PathPrefix("/api/v1").Subrouter()

	router.PathPrefix("/swagger").Handler(httpSwagger.WrapHandler)

	userHandler := user.NewHandler(s.db) 
	userHandler.RegisterRoutes(subrouter)

	appointmentHandler := appointment.NewAppointmentHandler(s.db)
	appointmentHandler.RegisterRoutes(subrouter)

	availabilityHandler := availability.NewAvailabilityHandler(s.db)
    availabilityHandler.RegisterRoutes(subrouter)

	forumHandler := forum.NewPostHandler(s.db)
    forumHandler.RegisterRoutes(subrouter)

	wsHandler := service.NewWebSocketHandler(s.db)
	wsHandler.RegisterRoutes(subrouter)


	log.Println("Server running at", s.address)
	return http.ListenAndServe(s.address, router)
}