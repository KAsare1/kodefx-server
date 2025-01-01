package api

import (
	"log"
	"net/http"

	// "github.com/KAsare1/Kodefx-server/service"
	"github.com/KAsare1/Kodefx-server/service/appointment"
	"github.com/KAsare1/Kodefx-server/service/availability"
	"github.com/KAsare1/Kodefx-server/service/forum"
	"github.com/KAsare1/Kodefx-server/service/user"
	service "github.com/KAsare1/Kodefx-server/service/ws"
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




	log.Println("Server running at", s.address)
	return http.ListenAndServe(s.address, router)
}




