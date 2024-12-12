// package chats

// import (
// 	"encoding/json"
// 	"fmt"
// 	"log"
// 	"net/http"

// 	"github.com/GetStream/stream-chat-go/v5"
// )

// // Initialize the Stream Chat client (this should ideally be a global client or passed to functions)
// var client *stream_chat.Client

// func init() {
// 	// Initialize the Stream Chat client with your API key and secret (replace with actual values)
// 	client = stream_chat.NewClient("your_api_key", "your_api_secret")
// }

// // Function to create a new channel
// func createChannel(client *stream_chat.Client, channelID string, members []string) (*stream_chat.Channel, error) {
// 	// Define the request to create the channel
// 	channel, err := client.CreateChannel("messaging", channelID, &stream_chat.ChannelRequest{
// 		Members: members, // Add members to the channel
// 	})
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create channel: %w", err)
// 	}
// 	return channel, nil
// }

// // Function to add a user to a channel
// func addUserToChannel(client *stream_chat.Client, channelID, userID string) error {
// 	// Get the channel by its ID
// 	channel, err := client.Channel("messaging", channelID)
// 	if err != nil {
// 		return fmt.Errorf("failed to get channel: %w", err)
// 	}

// 	// Add the user to the channel
// 	err = channel.AddMembers([]string{userID})
// 	if err != nil {
// 		return fmt.Errorf("failed to add user to channel: %w", err)
// 	}
// 	return nil
// }

// // Function to send a message to a channel
// func sendMessageToChannel(client *stream_chat.Client, channelID, userID, messageText string) error {
// 	// Get the channel by its ID
// 	channel, err := client.Channel("messaging", channelID)
// 	if err != nil {
// 		return fmt.Errorf("failed to get channel: %w", err)
// 	}

// 	// Create a new message
// 	_, err = channel.SendMessage(&stream_chat.Message{
// 		User: &stream_chat.User{ID: userID}, // Specify the sender user
// 		Text: messageText,                    // The message content
// 	}, userID)
// 	if err != nil {
// 		return fmt.Errorf("failed to send message: %w", err)
// 	}
// 	return nil
// }

// // Function to get messages from a channel
// func getMessagesFromChannel(client *stream_chat.Client, channelID string) ([]*stream_chat.Message, error) {
// 	// Get the channel by its ID
// 	channel, err := client.Channel("messaging", channelID)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get channel: %w", err)
// 	}

// 	// Retrieve messages (limit to 10 messages for example)
// 	messages, err := channel.GetMessages(&stream_chat.MessageListRequest{
// 		Limit: 10,
// 	})
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get messages: %w", err)
// 	}
// 	return messages, nil
// }

// // HTTP handler for creating a channel
// func createChannelHandler(w http.ResponseWriter, r *http.Request) {
// 	var requestBody struct {
// 		Members []string `json:"members"`
// 	}

// 	// Parse the incoming JSON request body
// 	err := json.NewDecoder(r.Body).Decode(&requestBody)
// 	if err != nil {
// 		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
// 		return
// 	}

// 	channelID := "general" // Example channel ID, this could come from the request as well

// 	// Create the channel
// 	channel, err := createChannel(client, channelID, requestBody.Members)
// 	if err != nil {
// 		http.Error(w, fmt.Sprintf("Error creating channel: %v", err), http.StatusInternalServerError)
// 		return
// 	}

// 	w.WriteHeader(http.StatusCreated)
// 	fmt.Fprintf(w, "Channel created with ID: %s", channel.ID)
// }

// // HTTP handler for sending a message
// func sendMessageHandler(w http.ResponseWriter, r *http.Request) {
// 	var requestBody struct {
// 		MessageText string `json:"message_text"`
// 		UserID      string `json:"user_id"`
// 		ChannelID   string `json:"channel_id"`
// 	}

// 	// Parse the incoming JSON request body
// 	err := json.NewDecoder(r.Body).Decode(&requestBody)
// 	if err != nil {
// 		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
// 		return
// 	}

// 	// Send the message
// 	err = sendMessageToChannel(client, requestBody.ChannelID, requestBody.UserID, requestBody.MessageText)
// 	if err != nil {
// 		http.Error(w, fmt.Sprintf("Error sending message: %v", err), http.StatusInternalServerError)
// 		return
// 	}

// 	w.WriteHeader(http.StatusOK)
// 	fmt.Fprintf(w, "Message sent successfully!")
// }