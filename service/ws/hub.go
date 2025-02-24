package service

// import (
// 	"time"

// 	"github.com/KAsare1/Kodefx-server/cmd/models"
// 	"github.com/gorilla/websocket"
// )



// type ClientConnection struct {
// 	Hub     *Hub
// 	Conn    *websocket.Conn
// 	Send    chan []byte
// 	UserID  uint
// 	mu      sync.Mutex
// }


// func (h *Hub) Run() {
// 	for {
// 		select {
// 		case client := <-h.Register:
// 			h.mu.Lock()
// 			h.Clients[client] = true
// 			h.PeerConnections[client.UserID] = append(h.PeerConnections[client.UserID], client)
// 			h.mu.Unlock()

// 		case client := <-h.Unregister:
// 			h.mu.Lock()
// 			if _, ok := h.Clients[client]; ok {
// 				delete(h.Clients, client)
// 				close(client.Send)
				
// 				// Remove from peer connections
// 				connections := h.PeerConnections[client.UserID]
// 				for i, conn := range connections {
// 					if conn == client {
// 						h.PeerConnections[client.UserID] = append(connections[:i], connections[i+1:]...)
// 						break
// 					}
// 				}

// 				// Remove from channel subscriptions
// 				for channelID, subscribers := range h.ChannelSubscriptions {
// 					for i, subscriber := range subscribers {
// 						if subscriber == client {
// 							h.ChannelSubscriptions[channelID] = append(subscribers[:i], subscribers[i+1:]...)
// 							break
// 						}
// 					}
// 				}
// 			}
// 			h.mu.Unlock()
// 		}
// 	}
// }

// // HandlePeerMessage handles peer-to-peer messages
// func (h *Hub) HandlePeerMessage(msg *PeerMessage) error {
// 	h.mu.RLock()
// 	receiverConnections := h.PeerConnections[msg.ReceiverID]
// 	h.mu.RUnlock()

// 	wsMsg := WebSocketMessage{
// 		Type:    PeerMessageType,
// 		PeerMsg: msg,
// 	}

// 	jsonMsg, err := json.Marshal(wsMsg)
// 	if err != nil {
// 		return err
// 	}

// 	for _, client := range receiverConnections {
// 		client.mu.Lock()
// 		select {
// 		case client.Send <- jsonMsg:
// 		default:
// 			close(client.Send)
// 			delete(h.Clients, client)
// 		}
// 		client.mu.Unlock()
// 	}

// 	return nil
// }

// // HandleChannelMessage handles channel broadcast messages
// func (h *Hub) HandleChannelMessage(msg *ChannelMessage) error {
// 	h.mu.RLock()
// 	subscribers := h.ChannelSubscriptions[msg.ChannelID]
// 	h.mu.RUnlock()

// 	wsMsg := WebSocketMessage{
// 		Type:       ChannelMessageType,
// 		ChannelMsg: msg,
// 	}

// 	jsonMsg, err := json.Marshal(wsMsg)
// 	if err != nil {
// 		return err
// 	}

// 	for _, client := range subscribers {
// 		client.mu.Lock()
// 		select {
// 		case client.Send <- jsonMsg:
// 		default:
// 			close(client.Send)
// 			delete(h.Clients, client)
// 		}
// 		client.mu.Unlock()
// 	}

// 	return nil
// }

// // SubscribeToChannel adds a client to a channel's subscription list
// func (h *Hub) SubscribeToChannel(channelID uint, client *ClientConnection) {
// 	h.mu.Lock()
// 	defer h.mu.Unlock()
// 	h.ChannelSubscriptions[channelID] = append(h.ChannelSubscriptions[channelID], client)
// }

// // UnsubscribeFromChannel removes a client from a channel's subscription list
// func (h *Hub) UnsubscribeFromChannel(channelID uint, client *ClientConnection) {
// 	h.mu.Lock()
// 	defer h.mu.Unlock()
	
// 	subscribers := h.ChannelSubscriptions[channelID]
// 	for i, subscriber := range subscribers {
// 		if subscriber == client {
// 			h.ChannelSubscriptions[channelID] = append(subscribers[:i], subscribers[i+1:]...)
// 			break
// 		}
// 	}
// }

// // ReadPump pumps messages from the websocket connection to the hub
// func (c *ClientConnection) ReadPump() {
// 	defer func() {
// 		c.Hub.Unregister <- c
// 		c.Conn.Close()
// 	}()

// 	c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
// 	c.Conn.SetPongHandler(func(string) error {
// 		c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
// 		return nil
// 	})

// 	for {
// 		_, message, err := c.Conn.ReadMessage()
// 		if err != nil {
// 			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
// 				log.Printf("error: %v", err)
// 			}
// 			break
// 		}

// 		var wsMsg WebSocketMessage
// 		if err := json.Unmarshal(message, &wsMsg); err != nil {
// 			log.Printf("error unmarshaling message: %v", err)
// 			continue
// 		}

// 		switch wsMsg.Type {
// 		case PeerMessageType:
// 			if err := c.Hub.HandlePeerMessage(wsMsg.PeerMsg); err != nil {
// 				log.Printf("error handling peer message: %v", err)
// 			}
// 		case ChannelMessageType:
// 			if err := c.Hub.HandleChannelMessage(wsMsg.ChannelMsg); err != nil {
// 				log.Printf("error handling channel message: %v", err)
// 			}
// 		}
// 	}
// }

// // WritePump pumps messages from the hub to the websocket connection
// func (c *ClientConnection) WritePump() {
// 	ticker := time.NewTicker(54 * time.Second)
// 	defer func() {
// 		ticker.Stop()
// 		c.Conn.Close()
// 	}()

// 	for {
// 		select {
// 		case message, ok := <-c.Send:
// 			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
// 			if !ok {
// 				c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
// 				return
// 			}

// 			w, err := c.Conn.NextWriter(websocket.TextMessage)
// 			if err != nil {
// 				return
// 			}
// 			w.Write(message)

// 			if err := w.Close(); err != nil {
// 				return
// 			}
// 		case <-ticker.C:
// 			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
// 			if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
// 				return
// 			}
// 		}
// 	}
// }