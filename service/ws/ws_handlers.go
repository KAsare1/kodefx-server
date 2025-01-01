package service

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	// Update this import path

	"github.com/KAsare1/Kodefx-server/cmd/models"
	"github.com/KAsare1/Kodefx-server/cmd/utils"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"gorm.io/gorm"
)

type ChatHandler struct {
	db  *gorm.DB
	hub *models.Hub
}

// NewChatHandler initializes a new chat handler
func NewChatHandler(db *gorm.DB) *ChatHandler {
	hub := models.NewHub()
	go hub.Run()
	
	return &ChatHandler{
		db:  db,
		hub: hub,
	}
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // You might want to implement proper origin checking
	},
}

func (h *ChatHandler) RegisterRoutes(router *mux.Router, ) {
	// WebSocket connection
	router.HandleFunc("/ws", utils.AuthMiddleware(h.HandleWebSocket))

	// Channel routes
	router.HandleFunc("/channels", utils.AuthMiddleware(h.CreateChannel)).Methods("POST")
	router.HandleFunc("/channels", h.GetChannels).Methods("GET")
	router.HandleFunc("/channels/{id}", h.GetChannel).Methods("GET")
	// router.HandleFunc("/channels/{id}", utils.AuthMiddleware(h.UpdateChannel)).Methods("PUT")
	// router.HandleFunc("/channels/{id}", utils.AuthMiddleware(h.DeleteChannel)).Methods("DELETE")
	router.HandleFunc("/channels/{id}/join", utils.AuthMiddleware(h.JoinChannel)).Methods("POST")
	// router.HandleFunc("/channels/{id}/leave", utils.AuthMiddleware(h.LeaveChannel)).Methods("POST")
	router.HandleFunc("/channels/{id}/members", utils.AuthMiddleware(h.GetChannelMembers)).Methods("GET")


	// Message routes
	router.HandleFunc("/messages/peer/{userId}", utils.AuthMiddleware(h.GetPeerMessages)).Methods("GET")
	router.HandleFunc("/channels/{id}/messages", utils.AuthMiddleware(h.GetChannelMessages)).Methods("GET")
}

// HandleWebSocket handles WebSocket connections
func (h *ChatHandler) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
    log.Println("WebSocket connection request received")

    userID, err := utils.GetUserIDFromContext(r.Context())
    if err != nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Printf("WebSocket upgrade failed: %v\n", err)
        return
    }

    log.Printf("WebSocket connection established for user %d\n", userID)

    client := &models.ClientConnection{
        Hub:    h.hub,
        Conn:   conn,
        Send:   make(chan []byte, 256),
        UserID: userID,
    }

    // Subscribe to all channels the user is a member of
    var channels []models.Channel
    if err := h.db.Joins("JOIN channel_clients ON channels.id = channel_clients.channel_id").
        Joins("JOIN clients ON channel_clients.client_id = clients.id").
        Where("clients.user_id = ?", userID).
        Find(&channels).Error; err == nil {
        for _, channel := range channels {
            h.hub.SubscribeToChannel(channel.ID, client)
        }
    }

    h.hub.Register <- client

    go client.WritePump()
    go h.handleClientMessages(client)
}


func (h *ChatHandler) handleClientMessages(client *models.ClientConnection) {
    defer func() {
        h.hub.Unregister <- client
        client.Conn.Close()
    }()

    for {
        _, message, err := client.Conn.ReadMessage()
        if err != nil {
            if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
                log.Printf("error: %v", err)
            }
            break
        }

        var wsMsg models.WebSocketMessage
        if err := json.Unmarshal(message, &wsMsg); err != nil {
            log.Printf("error unmarshaling message: %v", err)
            continue
        }

        switch wsMsg.Type {
        case models.PeerMessageType:
            if wsMsg.PeerMsg == nil {
                continue
            }
            wsMsg.PeerMsg.SenderID = client.UserID
            wsMsg.PeerMsg.CreatedAt = time.Now()

            // Save to database
            if err := h.db.Create(wsMsg.PeerMsg).Error; err != nil {
                log.Printf("error saving peer message: %v", err)
                continue
            }

            // Broadcast to recipient
            msgBytes, _ := json.Marshal(wsMsg)
            h.hub.BroadcastToUser(wsMsg.PeerMsg.ReceiverID, msgBytes)

        case models.ChannelMessageType:
            if wsMsg.ChannelMsg == nil {
                continue
            }
            wsMsg.ChannelMsg.SenderID = client.UserID
            wsMsg.ChannelMsg.CreatedAt = time.Now()

            // Save to database
            if err := h.db.Create(wsMsg.ChannelMsg).Error; err != nil {
                log.Printf("error saving channel message: %v", err)
                continue
            }

            // Broadcast to channel
            msgBytes, _ := json.Marshal(wsMsg)
            h.hub.BroadcastToChannel(wsMsg.ChannelMsg.ChannelID, msgBytes)
        }
    }
}

// CreateChannel handles channel creation
func (h *ChatHandler) CreateChannel(w http.ResponseWriter, r *http.Request) {
	var channel models.Channel
	if err := json.NewDecoder(r.Body).Decode(&channel); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.db.Create(&channel).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(channel)
}

// GetChannels returns all available channels
func (h *ChatHandler) GetChannels(w http.ResponseWriter, r *http.Request) {
	var channels []models.Channel
	if err := h.db.Find(&channels).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(channels)
}


// GetChannel returns a specific channel
func (h *ChatHandler) GetChannel(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	channelID, err := strconv.ParseUint(vars["id"], 10, 32)
	if err != nil {
		http.Error(w, "Invalid channel ID", http.StatusBadRequest)
		return
	}

	var channel models.Channel
	if err := h.db.First(&channel, channelID).Error; err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(channel)
}

// JoinChannel handles joining a channel
func (h *ChatHandler) JoinChannel(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	channelID, err := strconv.ParseUint(vars["id"], 10, 32)
	if err != nil {
		http.Error(w, "Invalid channel ID", http.StatusBadRequest)
		return
	}

	userID, err := utils.GetUserIDFromContext(r.Context())
    if err != nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

	// Get or create client
	var client models.Client
	result := h.db.FirstOrCreate(&client, models.Client{UserID: userID})
	if result.Error != nil {
		http.Error(w, result.Error.Error(), http.StatusInternalServerError)
		return
	}

	// Add client to channel
	var channel models.Channel
	if err := h.db.First(&channel, channelID).Error; err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	

	if err := h.db.Model(&channel).Association("Clients").Append(&client); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// GetPeerMessages retrieves peer-to-peer messages
func (h *ChatHandler) GetPeerMessages(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	peerID, err := strconv.ParseUint(vars["userId"], 10, 32)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	userID, err := utils.GetUserIDFromContext(r.Context())
    if err != nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

	var messages []models.PeerMessage
	if err := h.db.Where(
		"(sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)",
		userID, peerID, peerID, userID,
	).Order("created_at asc").Find(&messages).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(messages)
}

// GetChannelMessages retrieves messages from a channel
func (h *ChatHandler) GetChannelMessages(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	channelID, err := strconv.ParseUint(vars["id"], 10, 32)
	if err != nil {
		http.Error(w, "Invalid channel ID", http.StatusBadRequest)
		return
	}

	var messages []models.ChannelMessage
	if err := h.db.Where("channel_id = ?", channelID).
		Order("created_at asc").
		Find(&messages).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(messages)
}



func (h *ChatHandler) GetChannelMembers(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    channelID, err := strconv.ParseUint(vars["id"], 10, 32)
    if err != nil {
        http.Error(w, "Invalid channel ID", http.StatusBadRequest)
        return
    }

    // Retrieve the channel from the database
    var channel models.Channel
    if err := h.db.First(&channel, channelID).Error; err != nil {
        http.Error(w, "Channel not found", http.StatusNotFound)
        return
    }

    // Retrieve the members of the channel
    var members []models.Client
    if err := h.db.Model(&channel).Association("Clients").Find(&members); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Return the members as a JSON response
    json.NewEncoder(w).Encode(members)
}