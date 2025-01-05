package models

import (
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"gorm.io/gorm"
)


// PeerMessage model for direct messages between users
type MessageContentType string

const (
    TextContent  MessageContentType = "text"
    ImageContent MessageContentType = "image"
)

// PeerMessage struct for direct messages between users
type PeerMessage struct {
    gorm.Model
    SenderID     uint              `gorm:"column:sender_id;not null" json:"sender_id"`
    ReceiverID   uint              `gorm:"column:receiver_id;not null" json:"receiver_id"`
    ContentType  MessageContentType `gorm:"column:content_type;not null;default:'text'" json:"content_type"`
    Content      string            `gorm:"column:content;type:text;not null" json:"content"`
    ImageURL     string            `gorm:"column:image_url;type:text" json:"image_url,omitempty"`
    ReadAt       time.Time         `gorm:"column:read_at" json:"read_at,omitempty"`

    // Relations
    Sender   *User `gorm:"foreignKey:SenderID" json:"sender,omitempty"`
    Receiver *User `gorm:"foreignKey:ReceiverID" json:"receiver,omitempty"`
}

func (PeerMessage) TableName() string {
    return "peer_messages"
}

// ChannelMessage model for messages in channels
type ChannelMessage struct {
    gorm.Model
    ChannelID   uint              `gorm:"column:channel_id;not null" json:"channel_id"`
    SenderID    uint              `gorm:"column:sender_id;not null" json:"sender_id"`
    ContentType MessageContentType `gorm:"column:content_type;not null;default:'text'" json:"content_type"`
    Content     string            `gorm:"column:content;type:text;not null" json:"content"`
    ImageURL    string            `gorm:"column:image_url;type:text" json:"image_url,omitempty"`

    // Relations
    Sender  *User    `gorm:"foreignKey:SenderID" json:"sender,omitempty"`
    Channel *Channel `gorm:"foreignKey:ChannelID" json:"channel,omitempty"`
}

func (ChannelMessage) TableName() string {
    return "channel_messages"
}

// Channel model for group chats
type Channel struct {
	gorm.Model
	Name        string    `gorm:"column:name;not null" json:"name"`
	Description string    `gorm:"column:description;type:text;not null" json:"description"`
	Clients     []*Client `gorm:"many2many:channel_clients" json:"clients,omitempty"`
	Admins	  []*Client   `gorm:"many2many:channel_admins" json:"admins,omitempty"`
	ChannelImage string `gorm:"column:channel_image;size:255" json:"channel_image"`
}

func (Channel) TableName() string {
	return "channels"
}

// Client model for managing active connections
type Client struct {
	gorm.Model
	UserID    uint      `gorm:"column:user_id;not null" json:"user_id"`
	Connected bool      `gorm:"column:connected;default:false" json:"connected"`
	LastSeen  time.Time `gorm:"column:last_seen" json:"last_seen,omitempty"`

	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

func (Client) TableName() string {
	return "clients"
}

// MessageType represents the type of message being sent
type MessageType string

const (
	PeerMessageType    MessageType = "peer"
	ChannelMessageType MessageType = "channel"
)

// WebSocketMessage represents the structure of messages sent over websocket
type WebSocketMessage struct {
	Type       MessageType     `json:"type"`
	PeerMsg    *PeerMessage   `json:"peer_message,omitempty"`
	ChannelMsg *ChannelMessage `json:"channel_message,omitempty"`
}

// ClientConnection represents an active websocket connection
type ClientConnection struct {
	Hub     *Hub
	Conn    *websocket.Conn
	Send    chan []byte
	UserID  uint
	mu      sync.Mutex
}

// Hub maintains the set of active clients and broadcasts messages
type Hub struct {
	// Registered clients
	Clients map[*ClientConnection]bool

	// Channel subscribers
	ChannelSubscriptions map[uint][]*ClientConnection // channelID -> []clients

	// Peer connections
	PeerConnections map[uint][]*ClientConnection // userID -> []clients

	// Channels for client operations
	Register   chan *ClientConnection
	Unregister chan *ClientConnection
	Broadcast  chan []byte

	mu sync.RWMutex
}

func NewHub() *Hub {
	return &Hub{
		Clients:              make(map[*ClientConnection]bool),
		ChannelSubscriptions: make(map[uint][]*ClientConnection),
		PeerConnections:      make(map[uint][]*ClientConnection),
		Register:             make(chan *ClientConnection),
		Unregister:          make(chan *ClientConnection),
		Broadcast:           make(chan []byte),
	}
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.Register:
			h.mu.Lock()
			h.Clients[client] = true
			h.PeerConnections[client.UserID] = append(h.PeerConnections[client.UserID], client)
			h.mu.Unlock()

		case client := <-h.Unregister:
			h.mu.Lock()
			if _, ok := h.Clients[client]; ok {
				delete(h.Clients, client)
				close(client.Send)

				// Remove from peer connections
				connections := h.PeerConnections[client.UserID]
				for i, conn := range connections {
					if conn == client {
						h.PeerConnections[client.UserID] = append(connections[:i], connections[i+1:]...)
						break
					}
				}

				// Remove from channel subscriptions
				for channelID, subscribers := range h.ChannelSubscriptions {
					for i, subscriber := range subscribers {
						if subscriber == client {
							h.ChannelSubscriptions[channelID] = append(subscribers[:i], subscribers[i+1:]...)
							break
						}
					}
				}
			}
			h.mu.Unlock()
		}
	}
}

// HandlePeerMessage handles peer-to-peer messages
func (h *Hub) HandlePeerMessage(msg *PeerMessage) error {
	h.mu.RLock()
	receiverConnections := h.PeerConnections[msg.ReceiverID]
	h.mu.RUnlock()

	wsMsg := WebSocketMessage{
		Type:    PeerMessageType,
		PeerMsg: msg,
	}

	jsonMsg, err := json.Marshal(wsMsg)
	if err != nil {
		return err
	}

	for _, client := range receiverConnections {
		client.mu.Lock()
		select {
		case client.Send <- jsonMsg:
		default:
			close(client.Send)
			delete(h.Clients, client)
		}
		client.mu.Unlock()
	}

	return nil
}

// HandleChannelMessage handles channel broadcast messages
func (h *Hub) HandleChannelMessage(msg *ChannelMessage) error {
	h.mu.RLock()
	subscribers := h.ChannelSubscriptions[msg.ChannelID]
	h.mu.RUnlock()

	wsMsg := WebSocketMessage{
		Type:       ChannelMessageType,
		ChannelMsg: msg,
	}

	jsonMsg, err := json.Marshal(wsMsg)
	if err != nil {
		return err
	}

	for _, client := range subscribers {
		client.mu.Lock()
		select {
		case client.Send <- jsonMsg:
		default:
			close(client.Send)
			delete(h.Clients, client)
		}
		client.mu.Unlock()
	}

	return nil
}

// SubscribeToChannel adds a client to a channel's subscription list
func (h *Hub) SubscribeToChannel(channelID uint, client *ClientConnection) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ChannelSubscriptions[channelID] = append(h.ChannelSubscriptions[channelID], client)
}

// UnsubscribeFromChannel removes a client from a channel's subscription list
func (h *Hub) UnsubscribeFromChannel(channelID uint, client *ClientConnection) {
	h.mu.Lock()
	defer h.mu.Unlock()

	subscribers := h.ChannelSubscriptions[channelID]
	for i, subscriber := range subscribers {
		if subscriber == client {
			h.ChannelSubscriptions[channelID] = append(subscribers[:i], subscribers[i+1:]...)
			break
		}
	}
}

// ReadPump pumps messages from the websocket connection to the hub
func (c *ClientConnection) ReadPump() {
	defer func() {
		c.Hub.Unregister <- c
		c.Conn.Close()
	}()

	c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.Conn.SetPongHandler(func(string) error {
		c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := c.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("error: %v", err)
			}
			break
		}

		var wsMsg WebSocketMessage
		if err := json.Unmarshal(message, &wsMsg); err != nil {
			log.Printf("error unmarshaling message: %v", err)
			continue
		}

		switch wsMsg.Type {
		case PeerMessageType:
			if err := c.Hub.HandlePeerMessage(wsMsg.PeerMsg); err != nil {
				log.Printf("error handling peer message: %v", err)
			}
		case ChannelMessageType:
			if err := c.Hub.HandleChannelMessage(wsMsg.ChannelMsg); err != nil {
				log.Printf("error handling channel message: %v", err)
			}
		}
	}
}

// WritePump pumps messages from the hub to the websocket connection
func (c *ClientConnection) WritePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		c.Conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.Send:
			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.Conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			if err := w.Close(); err != nil {
				return
			}
		case <-ticker.C:
			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}



func (h *Hub) BroadcastToUser(userID uint, message []byte) {
    h.mu.RLock()
    receiverConnections := h.PeerConnections[userID]
    h.mu.RUnlock()

    for _, client := range receiverConnections {
        client.mu.Lock()
        select {
        case client.Send <- message:
        default:
            close(client.Send)
            h.mu.Lock()
            delete(h.Clients, client)
            h.mu.Unlock()
        }
        client.mu.Unlock()
    }
}

func (h *Hub) BroadcastToChannel(channelID uint, message []byte) {
    h.mu.RLock()
    subscribers := h.ChannelSubscriptions[channelID]
    h.mu.RUnlock()

    for _, client := range subscribers {
        client.mu.Lock()
        select {
        case client.Send <- message:
        default:
            close(client.Send)
            h.mu.Lock()
            delete(h.Clients, client)
            h.mu.Unlock()
        }
        client.mu.Unlock()
    }
}