package admin

import (
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocketMessage represents a WebSocket message
type WebSocketMessage struct {
	Type      string                 `json:"type"`
	ID        string                 `json:"id,omitempty"`
	Data      interface{}            `json:"data"`
	Timestamp time.Time              `json:"timestamp"`
	Channel   string                 `json:"channel,omitempty"`
	User      string                 `json:"user,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// WebSocketClient represents a connected WebSocket client
type WebSocketClient struct {
	Conn       *websocket.Conn
	ID         string
	User       string
	Channels   map[string]bool
	LastPing   time.Time
	Send       chan WebSocketMessage
	mu         sync.Mutex
}

// WebSocketSubscription represents a subscription request
type WebSocketSubscription struct {
	Channels []string `json:"channels"`
	Filters  map[string]interface{} `json:"filters,omitempty"`
}

// WebSocketEventType represents different types of WebSocket events
type WebSocketEventType string

const (
	// System events
	EventTypeSystemStatus    WebSocketEventType = "system.status"
	EventTypeSystemAlert     WebSocketEventType = "system.alert"
	EventTypeSystemMetrics   WebSocketEventType = "system.metrics"

	// Client events
	EventTypeSubscribe       WebSocketEventType = "client.subscribe"
	EventTypeUnsubscribe     WebSocketEventType = "client.unsubscribe"

	// Provider events
	EventTypeProviderStatus    WebSocketEventType = "provider.status"
	EventTypeProviderAdded     WebSocketEventType = "provider.added"
	EventTypeProviderRemoved   WebSocketEventType = "provider.removed"
	EventTypeProviderConfig    WebSocketEventType = "provider.config"

	// User events
	EventTypeAPIKeyCreated   WebSocketEventType = "user.apikey.created"
	EventTypeAPIKeyUpdated   WebSocketEventType = "user.apikey.updated"
	EventTypeAPIKeyDeleted   WebSocketEventType = "user.apikey.deleted"
	EventTypeUserActivity    WebSocketEventType = "user.activity"

	// Configuration events
	EventTypeConfigChanged    WebSocketEventType = "config.changed"
	EventTypeConfigReload    WebSocketEventType = "config.reloaded"
	EventTypeConfigBackup    WebSocketEventType = "config.backup"

	// Model events
	EventTypeModelDiscovered WebSocketEventType = "model.discovered"
	EventTypeModelGroupAdded WebSocketEventType = "model.group.added"
	EventTypeModelGroupUpdated WebSocketEventType = "model.group.updated"
	EventTypeModelGroupRemoved WebSocketEventType = "model.group.removed"

	// Request events
	EventTypeRequestMetric   WebSocketEventType = "request.metric"
	EventTypeRequestError    WebSocketEventType = "request.error"
	EventTypeRequestLarge    WebSocketEventType = "request.large"

	// Internal events
	EventTypePing           WebSocketEventType = "internal.ping"
	EventTypePong           WebSocketEventType = "internal.pong"
	EventTypeWelcome        WebSocketEventType = "internal.welcome"
	EventTypeGoodbye        WebSocketEventType = "internal.goodbye"
	EventTypeError          WebSocketEventType = "internal.error"
)

// WebSocketHub manages WebSocket connections and message broadcasting
type WebSocketHub struct {
	clients      map[*WebSocketClient]bool
	register     chan *WebSocketClient
	unregister   chan *WebSocketClient
	broadcast    chan WebSocketMessage
	subscribe    chan *WebSocketSubscription
	unsubscribe  chan *WebSocketSubscription
	mu           sync.RWMutex
	eventStreams map[WebSocketEventType]chan interface{}
}

// NewWebSocketHub creates a new WebSocket hub
func NewWebSocketHub() *WebSocketHub {
	return &WebSocketHub{
		clients:      make(map[*WebSocketClient]bool),
		register:     make(chan *WebSocketClient),
		unregister:   make(chan *WebSocketClient),
		broadcast:    make(chan WebSocketMessage, 256),
		subscribe:    make(chan *WebSocketSubscription),
		unsubscribe:  make(chan *WebSocketSubscription),
		eventStreams: make(map[WebSocketEventType]chan interface{}),
	}
}

// Start starts the WebSocket hub
func (h *WebSocketHub) Start() {
	// create unique event channel streams for different event types
	for eventType := range map[WebSocketEventType]bool{
		EventTypeSystemStatus:    true,
		EventTypeSystemAlert:     true,
		EventTypeSystemMetrics:   true,
		EventTypeProviderStatus:  true,
		EventTypeProviderAdded:   true,
		EventTypeProviderRemoved: true,
		EventTypeProviderConfig:  true,
		EventTypeAPIKeyCreated:   true,
		EventTypeAPIKeyUpdated:   true,
		EventTypeAPIKeyDeleted:   true,
		EventTypeUserActivity:    true,
		EventTypeConfigChanged:   true,
		EventTypeConfigReload:    true,
		EventTypeConfigBackup:    true,
		EventTypeModelDiscovered: true,
		EventTypeModelGroupAdded: true,
		EventTypeModelGroupUpdated: true,
		EventTypeModelGroupRemoved: true,
		EventTypeRequestMetric:   true,
		EventTypeRequestError:    true,
		EventTypeRequestLarge:    true,
	} {
		h.eventStreams[eventType] = make(chan interface{}, 100)
	}

	go h.run()
}

// run runs the WebSocket hub main loop
func (h *WebSocketHub) run() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case client := <-h.register:
			h.clients[client] = true
			h.sendWelcome(client)

		case client := <-h.unregister:
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.Send)
			}

		case message := <-h.broadcast:
			h.broadcastMessage(message)

		case subscription := <-h.subscribe:
			h.handleSubscription(subscription, true)

		case subscription := <-h.unsubscribe:
			h.handleSubscription(subscription, false)

		case <-ticker.C:
			h.checkClientsHealth()
		}
	}
}

// sendWelcome sends a welcome message to a new client
func (h *WebSocketHub) sendWelcome(client *WebSocketClient) {
	message := WebSocketMessage{
		Type:      string(EventTypeWelcome),
		ID:        generateMessageID(),
		Data: map[string]interface{}{
			"server_version": "v1.0.0",
			"client_id":     client.ID,
			"connected_at":  time.Now().Format(time.RFC3339),
			"available_channels": []string{
				"system",
				"providers",
				"users",
				"config",
				"models",
				"requests",
			},
		},
		Timestamp: time.Now(),
	}

	select {
	case client.Send <- message:
	default:
		close(client.Send)
		delete(h.clients, client)
	}
}

// broadcastMessage broadcasts a message to all subscribed clients
func (h *WebSocketHub) broadcastMessage(message WebSocketMessage) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for client := range h.clients {
		// Check if client is subscribed to this message's channel
		if message.Channel != "" && !client.Channels[message.Channel] {
			continue
		}

		select {
		case client.Send <- message:
		default:
			close(client.Send)
			delete(h.clients, client)
		}
	}
}

// handleSubscription handles subscription/unsubscription requests
func (h *WebSocketHub) handleSubscription(subscription *WebSocketSubscription, subscribe bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for client := range h.clients {
		for _, channel := range subscription.Channels {
			if subscribe {
				client.mu.Lock()
				if client.Channels == nil {
					client.Channels = make(map[string]bool)
				}
				client.Channels[channel] = true
				client.mu.Unlock()
			} else {
				client.mu.Lock()
				if client.Channels != nil {
					delete(client.Channels, channel)
				}
				client.mu.Unlock()
			}
		}
	}
}

// checkClientsHealth checks the health of connected clients
func (h *WebSocketHub) checkClientsHealth() {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for client := range h.clients {
		// Send ping
		ping := WebSocketMessage{
			Type:      string(EventTypePing),
			ID:        generateMessageID(),
			Timestamp: time.Now(),
		}

		select {
		case client.Send <- ping:
		default:
			close(client.Send)
			delete(h.clients, client)
		}
	}
}

// BroadcastSystemStatus broadcasts system status updates
func (h *WebSocketHub) BroadcastSystemStatus(status map[string]interface{}) {
	message := WebSocketMessage{
		Type:      string(EventTypeSystemStatus),
		ID:        generateMessageID(),
		Data:      status,
		Channel:   "system",
		Timestamp: time.Now(),
	}

	select {
	case h.broadcast <- message:
	default:
		// Channel full, drop the message
	}
}

// BroadcastProviderStatus broadcasts provider status updates
func (h *WebSocketHub) BroadcastProviderStatus(provider string, status map[string]interface{}) {
	message := WebSocketMessage{
		Type:      string(EventTypeProviderStatus),
		ID:        generateMessageID(),
		Data: map[string]interface{}{
			"provider": provider,
			"status":   status,
		},
		Channel:   "providers",
		Timestamp: time.Now(),
	}

	select {
	case h.broadcast <- message:
	default:
	}
}

// BroadcastConfigChange broadcasts configuration changes
func (h *WebSocketHub) BroadcastConfigChange(changeType string, data map[string]interface{}) {
	message := WebSocketMessage{
		Type:      string(EventTypeConfigChanged),
		ID:        generateMessageID(),
		Data: map[string]interface{}{
			"change_type": changeType,
			"data":       data,
		},
		Channel:   "config",
		Timestamp: time.Now(),
	}

	select {
	case h.broadcast <- message:
	default:
	}
}

// BroadcastRequestMetric broadcasts request metrics
func (h *WebSocketHub) BroadcastRequestMetric(metric map[string]interface{}) {
	message := WebSocketMessage{
		Type:      string(EventTypeRequestMetric),
		ID:        generateMessageID(),
		Data:      metric,
		Channel:   "requests",
		Timestamp: time.Now(),
	}

	select {
	case h.broadcast <- message:
	default:
	}
}

// GetConnectedClients returns the number of connected clients
func (h *WebSocketHub) GetConnectedClients() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// handleWebSocket handles WebSocket connections
func (a *AdminServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Upgrade HTTP connection to WebSocket
	conn, err := a.wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		a.logAccess(r, "WEBSOCKET_CONNECT_FAILED", "websocket", "", false)
		return
	}

	// Create client
	client := &WebSocketClient{
		Conn:     conn,
		ID:       generateClientID(),
		User:     extractUserFromRequest(r),
		Channels: make(map[string]bool),
		LastPing: time.Now(),
		Send:     make(chan WebSocketMessage, 256),
	}

	// Register client
	a.wsHub.register <- client

	// Start sender goroutine
	go a.writePump(client)
	go a.readPump(client)

	a.logAccess(r, "WEBSOCKET_CONNECT", "websocket", client.ID, true)
}

// writePump handles sending messages to WebSocket client
func (a *AdminServer) writePump(client *WebSocketClient) {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		client.Conn.Close()
		a.wsHub.unregister <- client
	}()

	for {
		select {
		case message, ok := <-client.Send:
			if !ok {
				client.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := client.Conn.WriteJSON(message); err != nil {
				a.logAccess(nil, "WEBSOCKET_SEND_ERROR", "websocket", client.ID, false)
				return
			}

		case <-ticker.C:
			if err := client.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}

		case <-time.After(time.Minute):
			// Close connection if no activity
			client.Conn.Close()
			return
		}
	}
}

// readPump handles reading messages from WebSocket client
func (a *AdminServer) readPump(client *WebSocketClient) {
	defer func() {
		client.Conn.Close()
		a.wsHub.unregister <- client
	}()

	client.Conn.SetReadLimit(512 * 1024) // 512KB
	client.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	client.Conn.SetPongHandler(func(string) error {
		client.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		client.LastPing = time.Now()
		return nil
	})

	for {
		var message WebSocketMessage
		err := client.Conn.ReadJSON(&message)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				a.logAccess(nil, "WEBSOCKET_READ_ERROR", "websocket", client.ID, false)
			}
			break
		}

		client.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		a.handleWebSocketMessage(client, message)
	}
}

// handleWebSocketMessage handles incoming WebSocket messages from clients
func (a *AdminServer) handleWebSocketMessage(client *WebSocketClient, message WebSocketMessage) {
	switch WebSocketEventType(message.Type) {
	case EventTypePong:
		client.LastPing = time.Now()

	case EventTypeSubscribe:
		if data, ok := message.Data.(map[string]interface{}); ok {
			if channels, ok := data["channels"].([]interface{}); ok {
				var channelNames []string
				for _, channel := range channels {
					if channelName, ok := channel.(string); ok {
						channelNames = append(channelNames, channelName)
					}
				}
				subscription := &WebSocketSubscription{
					Channels: channelNames,
				}
				a.wsHub.subscribe <- subscription
			}
		}

	case EventTypeUnsubscribe:
		if data, ok := message.Data.(map[string]interface{}); ok {
			if channels, ok := data["channels"].([]interface{}); ok {
				var channelNames []string
				for _, channel := range channels {
					if channelName, ok := channel.(string); ok {
						channelNames = append(channelNames, channelName)
					}
				}
				subscription := &WebSocketSubscription{
					Channels: channelNames,
				}
				a.wsHub.unsubscribe <- subscription
			}
		}

	default:
		// Handle other message types or send error
		errorMessage := WebSocketMessage{
			Type:      string(EventTypeError),
			ID:        generateMessageID(),
			Data: map[string]interface{}{
				"error": "Unknown message type: " + message.Type,
			},
			Timestamp: time.Now(),
		}

		select {
		case client.Send <- errorMessage:
		default:
		}
	}
}

// Integration methods for broadcasting events

// initializeWebSocketHub initializes the WebSocket hub
func (a *AdminServer) initializeWebSocketHub() {
	a.wsHub = NewWebSocketHub()
	a.wsHub.Start()

	// Start event monitoring goroutine
	go a.monitorAndBroadcastEvents()
}

// monitorAndBroadcastEvents monitors system events and broadcasts them
func (a *AdminServer) monitorAndBroadcastEvents() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Broadcast system status periodically
			a.broadcastSystemStatusUpdate()

			// Broadcast metrics periodically
			a.broadcastMetricsUpdate()
		}
	}
}

// broadcastSystemStatusUpdate broadcasts current system status
func (a *AdminServer) broadcastSystemStatusUpdate() {
	status := map[string]interface{}{
		"healthy":        true,
		"uptime_seconds": 0, // Would calculate actual uptime
		"clients_connected": a.wsHub.GetConnectedClients(),
		"timestamp":       time.Now().Format(time.RFC3339),
	}

	a.wsHub.BroadcastSystemStatus(status)
}

// broadcastMetricsUpdate broadcasts current metrics
func (a *AdminServer) broadcastMetricsUpdate() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	metrics := map[string]interface{}{
		"memory_alloc_mb": float64(m.Alloc) / 1024 / 1024,
		"goroutines":      runtime.NumGoroutine(),
		"num_gc":          m.NumGC,
		"timestamp":       time.Now().Format(time.RFC3339),
	}

	a.wsHub.BroadcastRequestMetric(metrics)
}

// Event notification methods for integration with other parts of the system

// NotifyProviderCreated notifies about provider creation
func (a *AdminServer) NotifyProviderCreated(providerName string, config map[string]interface{}) {
	if a.wsHub == nil {
		return
	}

	message := WebSocketMessage{
		Type:      string(EventTypeProviderAdded),
		ID:        generateMessageID(),
		Data: map[string]interface{}{
			"provider":  providerName,
			"config":    config,
			"action":    "created",
		},
		Channel:   "providers",
		Timestamp: time.Now(),
	}

	select {
	case a.wsHub.broadcast <- message:
	default:
	}
}

// NotifyProviderDeleted notifies about provider deletion
func (a *AdminServer) NotifyProviderDeleted(providerName string) {
	if a.wsHub == nil {
		return
	}

	message := WebSocketMessage{
		Type:      string(EventTypeProviderRemoved),
		ID:        generateMessageID(),
		Data: map[string]interface{}{
			"provider": providerName,
			"action":   "deleted",
		},
		Channel:   "providers",
		Timestamp: time.Now(),
	}

	select {
	case a.wsHub.broadcast <- message:
	default:
	}
}

// NotifyAPIKeyCreated notifies about API key creation
func (a *AdminServer) NotifyAPIKeyCreated(keyID string, keyData map[string]interface{}) {
	if a.wsHub == nil {
		return
	}

	message := WebSocketMessage{
		Type:      string(EventTypeAPIKeyCreated),
		ID:        generateMessageID(),
		Data: map[string]interface{}{
			"key_id": keyID,
			"action": "created",
		},
		Channel:   "users",
		Timestamp: time.Now(),
	}

	select {
	case a.wsHub.broadcast <- message:
	default:
	}
}

// NotifyConfigReloaded notifies about configuration reload
func (a *AdminServer) NotifyConfigReloaded(success bool, message string) {
	if a.wsHub == nil {
		return
	}

	reloadData := map[string]interface{}{
		"success": success,
		"message": message,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	a.wsHub.BroadcastConfigChange("reload", reloadData)
}

// Helper functions

// generateMessageID generates a unique message ID
func generateMessageID() string {
	return fmt.Sprintf("msg_%d_%d", time.Now().UnixNano(), time.Now().Nanosecond()%10000)
}

// generateClientID generates a unique client ID
func generateClientID() string {
	return fmt.Sprintf("client_%d_%d", time.Now().UnixNano(), time.Now().Nanosecond()%10000)
}