package messaging

import (
	"context"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/nats-io/nats.go"

	"github.com/Neurvinch/SIEPMU/server/internal/identity"
)

// handleWS streams the caller's delivery notifications. Payloads are only
// pointers ("channel X has new seq N"); clients fetch ciphertext over the
// authenticated REST API.
func (s *Service) handleWS(w http.ResponseWriter, r *http.Request) {
	p := identity.FromContext(r.Context())
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan []byte, 64)
	sub, err := s.bus.NC.Subscribe("siepmu.deliver."+p.User.ID.String(), func(m *nats.Msg) {
		select {
		case out <- m.Data:
		default: // slow consumer: client will resync on reconnect
		}
	})
	if err != nil {
		conn.Close(websocket.StatusInternalError, "subscribe failed")
		return
	}
	defer sub.Unsubscribe()
	go func() {
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				cancel()
				return
			}
		}
	}()
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	// Re-check the session periodically: revoked sessions lose the stream.
	check := time.NewTicker(30 * time.Second)
	defer check.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case b := <-out:
			wctx, c := context.WithTimeout(ctx, 10*time.Second)
			err := conn.Write(wctx, websocket.MessageText, b)
			c()
			if err != nil {
				return
			}
		case <-ping.C:
			pctx, c := context.WithTimeout(ctx, 10*time.Second)
			err := conn.Ping(pctx)
			c()
			if err != nil {
				return
			}
		case <-check.C:
			var revoked bool
			s.db.QueryRow(ctx, `SELECT revoked_at IS NOT NULL OR expires_at < now() FROM sessions WHERE id=$1`, p.Session.ID).Scan(&revoked)
			if revoked {
				conn.Close(websocket.StatusPolicyViolation, "session revoked")
				return
			}
		}
	}
}

func (s *Service) RealtimeRoutes(mux *http.ServeMux, auth func(http.HandlerFunc) http.Handler) {
	mux.Handle("GET /api/ws", auth(s.handleWS))
}
