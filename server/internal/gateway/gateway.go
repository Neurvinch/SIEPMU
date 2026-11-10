// Package gateway is Ring 1 (BLACK zone): every external request passes
// through IP block-listing, distributed rate limiting (Redis GCRA), strict
// security headers and request-size limits before it reaches any service.
// There is no route from here to the data ring that bypasses identity.
package gateway

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis_rate/v10"
	"github.com/redis/go-redis/v9"

	"github.com/Neurvinch/SIEPMU/server/internal/events"
	"github.com/Neurvinch/SIEPMU/server/internal/httpx"
	"github.com/Neurvinch/SIEPMU/server/internal/store"
)

type Gateway struct {
	db      *store.Store
	limiter *redis_rate.Limiter
	bus     *events.Bus
	perIP   redis_rate.Limit
	authIP  redis_rate.Limit

	mu      sync.RWMutex
	blocked map[string]time.Time
}

func New(db *store.Store, rdb *redis.Client, bus *events.Bus, perIPPerMin, authPerIPPerMin int) *Gateway {
	return &Gateway{
		db: db, limiter: redis_rate.NewLimiter(rdb), bus: bus,
		perIP:   redis_rate.PerMinute(perIPPerMin),
		authIP:  redis_rate.PerMinute(authPerIPPerMin),
		blocked: map[string]time.Time{},
	}
}

// RefreshBlocklist reloads SOAR IP blocks; called on a timer and on demand.
func (g *Gateway) RefreshBlocklist(ctx context.Context) error {
	rows, err := g.db.Query(ctx, `SELECT ip, expires_at FROM blocked_ips WHERE expires_at > now()`)
	if err != nil {
		return err
	}
	defer rows.Close()
	m := map[string]time.Time{}
	for rows.Next() {
		var ip string
		var exp time.Time
		if err := rows.Scan(&ip, &exp); err != nil {
			return err
		}
		m[ip] = exp
	}
	g.mu.Lock()
	g.blocked = m
	g.mu.Unlock()
	return rows.Err()
}

func (g *Gateway) RunBlocklist(ctx context.Context) {
	sub, _ := g.bus.NC.Subscribe("siepmu.ctl.blocklist", func(_ *natsMsg) { g.RefreshBlocklist(ctx) })
	defer func() {
		if sub != nil {
			sub.Unsubscribe()
		}
	}()
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	g.RefreshBlocklist(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.RefreshBlocklist(ctx)
		}
	}
}

func (g *Gateway) isBlocked(ip string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	exp, ok := g.blocked[ip]
	return ok && time.Now().Before(exp)
}

func securityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(self)")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' wss:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
}

// Wrap applies Ring 1 controls to the whole public handler.
func (g *Gateway) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		securityHeaders(w)
		ip := httpx.ClientIP(r)
		if g.isBlocked(ip) {
			httpx.JSON(w, http.StatusForbidden, httpx.E(403, "blocked", "source address blocked by SOC containment"))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			limit, key := g.perIP, "rl:ip:"+ip
			if strings.HasPrefix(r.URL.Path, "/api/auth/") {
				limit, key = g.authIP, "rl:auth:"+ip
			}
			res, err := g.limiter.Allow(r.Context(), key, limit)
			if err != nil {
				httpx.Fail(w, err)
				return
			}
			w.Header().Set("RateLimit-Remaining", strconv.Itoa(res.Remaining))
			if res.Allowed == 0 {
				w.Header().Set("Retry-After", strconv.Itoa(int(res.RetryAfter.Seconds())+1))
				g.bus.PublishSec(r.Context(), events.SecEvent{Source: "gateway", Kind: "gateway.rate_limited", Severity: 2, IP: ip,
					AttackIDs: []string{"T1499"}, Summary: "rate limit exceeded on " + r.URL.Path, Data: map[string]any{"path": r.URL.Path}})
				httpx.JSON(w, http.StatusTooManyRequests, httpx.E(429, "rate_limited", "too many requests"))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
