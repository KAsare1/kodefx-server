package service

// import (
// 	"encoding/json"
// 	"log"
// 	"net/http"
// 	"sync"

// 	"github.com/KAsare1/Kodefx-server/cmd/models"
// 	"github.com/KAsare1/Kodefx-server/cmd/utils"
// 	"github.com/gorilla/mux"
// 	"github.com/gorilla/websocket"
// 	"gorm.io/gorm"
// )

// var upgrader = websocket.Upgrader{
//     ReadBufferSize:  1024,
//     WriteBufferSize: 1024,
//     CheckOrigin: func(r *http.Request) bool {
//         return true 
//     },
// }

// type Client struct {
//     UserID uint
//     Conn   *websocket.Conn
//     Hub    *Hub
// }

// type Hub struct {
//     clients    map[uint]*Client // map userID to client
//     mu         sync.RWMutex
//     db         *gorm.DB
// }

// type WebSocketMessage struct {
//     Type       string          `json:"type"`
//     ReceiverID uint           `json:"receiver_id,omitempty"`
//     Content    string         `json:"content,omitempty"`
//     MessageID  uint           `json:"message_id,omitempty"`
// }

// func NewHub(db *gorm.DB) *Hub {
//     return &Hub{
//         clients: make(map[uint]*Client),
//         db:      db,
//     }
// }

// func (h *Hub) registerClient(userID uint, conn *websocket.Conn) *Client {
//     h.mu.Lock()
//     defer h.mu.Unlock()

//     client := &Client{
//         UserID: userID,
//         Conn:   conn,
//         Hub:    h,
//     }
//     h.clients[userID] = client
//     return client
// }

// func (h *Hub) unregisterClient(userID uint) {
//     h.mu.Lock()
//     defer h.mu.Unlock()
//     delete(h.clients, userID)
// }

// func (h *Hub) GetClient(userID uint) (*Client, bool) {
//     h.mu.RLock()
//     defer h.mu.RUnlock()
//     client, exists := h.clients[userID]
//     return client, exists
// }

// func (c *Client) handleMessages() {
//     defer func() {
//         c.Hub.unregisterClient(c.UserID)
//         c.Conn.Close()
//     }()

//     for {
//         _, message, err := c.Conn.ReadMessage()
//         if err != nil {
//             if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
//                 log.Printf("WebSocket error: %v", err)
//             }
//             break
//         }

//         var wsMessage WebSocketMessage
//         if err := json.Unmarshal(message, &wsMessage); err != nil {
//             log.Printf("Error unmarshaling message: %v", err)
//             continue
//         }

//         switch wsMessage.Type {
//         case "message":
//             c.handleNewMessage(wsMessage)
//         case "typing":
//             c.handleTypingNotification(wsMessage)
//         }
//     }
// }

// func (c *Client) handleNewMessage(wsMessage WebSocketMessage) {
//     // Create and save message to database
//     message := models.Message{
//         SenderID:   c.UserID,
//         ReceiverID: wsMessage.ReceiverID,
//         Content:    wsMessage.Content,
//     }

//     if err := c.Hub.db.Create(&message).Error; err != nil {
//         log.Printf("Error saving message: %v", err)
//         return
//     }

//     // Load relationships
//     c.Hub.db.Preload("Sender").Preload("Receiver").First(&message, message.ID)

//     // Send to receiver if online
//     if receiver, exists := c.Hub.GetClient(wsMessage.ReceiverID); exists {
//         response, _ := json.Marshal(map[string]interface{}{
//             "type":    "message",
//             "message": message,
//         })
//         receiver.Conn.WriteMessage(websocket.TextMessage, response)
//     }
// }

// func (c *Client) handleTypingNotification(wsMessage WebSocketMessage) {
//     if receiver, exists := c.Hub.GetClient(wsMessage.ReceiverID); exists {
//         response, _ := json.Marshal(map[string]interface{}{
//             "type":      "typing",
//             "sender_id": c.UserID,
//         })
//         receiver.Conn.WriteMessage(websocket.TextMessage, response)
//     }
// }

// type WebSocketHandler struct {
//     hub *Hub
// }

// func NewWebSocketHandler(db *gorm.DB) *WebSocketHandler {
//     return &WebSocketHandler{
//         hub: NewHub(db),
//     }
// }

// func (h *WebSocketHandler) RegisterRoutes(router *mux.Router) {
//     router.HandleFunc("/ws", h.HandleWebSocket)
// }

// func (h *WebSocketHandler) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
//     userID, err := utils.GetUserIDFromContext(r)
//     if err != nil {
//         http.Error(w, "Unauthorized", http.StatusUnauthorized)
//         return
//     }

//     conn, err := upgrader.Upgrade(w, r, nil)
//     if err != nil {
//         log.Printf("Error upgrading to WebSocket: %v", err)
//         return
//     }

//     client := h.hub.registerClient(userID, conn)
//     go client.handleMessages()
// }