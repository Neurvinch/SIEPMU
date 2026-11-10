// siepmu-core runs the SIEPMU-SX mesh services: Ring 1 gateway, Ring 2
// identity, messaging, files, monitoring/SOAR, the cross-domain guard and
// the mesh side of the legacy bridge.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Neurvinch/SIEPMU/server/internal/audit"
	"github.com/Neurvinch/SIEPMU/server/internal/boot"
	"github.com/Neurvinch/SIEPMU/server/internal/events"
	"github.com/Neurvinch/SIEPMU/server/internal/files"
	"github.com/Neurvinch/SIEPMU/server/internal/gateway"
	"github.com/Neurvinch/SIEPMU/server/internal/guard"
	"github.com/Neurvinch/SIEPMU/server/internal/httpx"
	"github.com/Neurvinch/SIEPMU/server/internal/identity"
	"github.com/Neurvinch/SIEPMU/server/internal/legacy"
	"github.com/Neurvinch/SIEPMU/server/internal/messaging"
	"github.com/Neurvinch/SIEPMU/server/internal/monitor"
	"github.com/Neurvinch/SIEPMU/server/internal/pki"
	"github.com/Neurvinch/SIEPMU/server/internal/policy"
	"github.com/Neurvinch/SIEPMU/server/internal/servicekeys"
)

// rotatingCert re-issues the workload certificate before it expires.
type rotatingCert struct {
	mu    sync.Mutex
	cert  *tls.Certificate
	until time.Time
	issue func() (tls.Certificate, error)
}

func (r *rotatingCert) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cert == nil || time.Now().After(r.until) {
		c, err := r.issue()
		if err != nil {
			return nil, err
		}
		r.cert, r.until = &c, time.Now().Add(12*time.Hour)
	}
	return r.cert, nil
}

func main() {
	cfgPath := flag.String("config", "config.yaml", "configuration file")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	env, err := boot.Open(ctx, *cfgPath, false)
	if err != nil {
		log.Fatal(err)
	}
	defer env.Close()
	cfg, db, p := env.Cfg, env.DB, env.Provider

	rdb := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr})
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("redis: %v", err)
	}
	auditSigner, err := servicekeys.HybridSigner(ctx, db, env.KMS, p, "audit-log")
	must(err)
	busSigner, err := servicekeys.HybridSigner(ctx, db, env.KMS, p, "event-bus")
	must(err)
	guardSigner, err := servicekeys.HybridSigner(ctx, db, env.KMS, p, "guard-release")
	must(err)
	tokenSeed, err := servicekeys.Seed(ctx, db, env.KMS, "access-token", "Ed25519", ed25519.SeedSize, func(s []byte) []byte {
		return ed25519.NewKeyFromSeed(s).Public().(ed25519.PublicKey)
	})
	must(err)

	bus, err := events.Start(ctx, cfg.Events, busSigner, p.Verifier())
	must(err)
	defer bus.Close()
	al, err := audit.New(ctx, db, auditSigner)
	must(err)
	go al.RunSigner(ctx, 5*time.Second)
	pol, err := policy.New(ctx)
	must(err)

	var scPool *x509.CertPool
	if cfg.SmartcardCAFile != "" {
		b, err := os.ReadFile(cfg.SmartcardCAFile)
		must(err)
		scPool = x509.NewCertPool()
		if !scPool.AppendCertsFromPEM(b) {
			log.Fatal("smartcard_ca_file contains no certificates")
		}
	}

	ids, err := identity.New(cfg, db, rdb, tokenSeed, env.CA, al, bus, pol, scPool)
	must(err)
	msg := messaging.New(db, ids, al, bus)
	fs := files.New(db, rdb, ids, msg, env.KMS, p, files.FSStore{Root: filepath.Join(cfg.DataDir, "objects")}, al, bus, cfg.Files.MaxSize, cfg.Files.ChunkSize)
	mon := monitor.New(cfg, db, rdb, bus, ids, al, [][]byte{bus.PublicKey()})
	gd := guard.New(cfg, db, ids, env.KMS, p, guardSigner, al, bus)
	lg := legacy.New(db, ids, msg, env.KMS, p.Verifier(), al, bus)
	gw := gateway.New(db, rdb, bus, cfg.RateLimit.PerIPPerMinute, cfg.RateLimit.AuthPerIPPerMin)
	go gw.RunBlocklist(ctx)
	go func() {
		if err := mon.Run(ctx); err != nil && ctx.Err() == nil {
			log.Fatalf("monitor: %v", err)
		}
	}()

	// ---- public API (Ring 1 -> Ring 2 -> services)
	mux := http.NewServeMux()
	auth := func(h http.HandlerFunc) http.Handler { return ids.Authenticate(h) }
	ids.Routes(mux, auth)
	msg.Routes(mux, auth)
	msg.RealtimeRoutes(mux, auth)
	fs.Routes(mux, auth)
	mon.Routes(mux, auth)
	gd.Routes(mux, auth)
	lg.Routes(mux, auth)
	mux.HandleFunc("GET /api/platform", func(w http.ResponseWriter, r *http.Request) {
		httpx.JSON(w, 200, map[string]any{
			"provider": p.Name(), "kem": p.KEM().Name(), "aead": p.AEAD().Name(), "signature": p.Verifier().Algorithm(),
			"mls_cipher_suite": messaging.MLSCipherSuite, "ca_fingerprint": pki.Fingerprint(env.CA.Cert), "trust_domain": pki.TrustDomain,
			"file_chunk_size": cfg.Files.ChunkSize, "levels": identity.Levels,
		})
	})
	mux.HandleFunc("GET /api/platform/ca.pem", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(env.CA.CertPEM())
	})
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		httpx.JSON(w, 404, httpx.E(404, "not_found", "no such endpoint"))
	})
	if cfg.WebDir != "" {
		static := http.FileServer(http.Dir(cfg.WebDir))
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if _, err := os.Stat(filepath.Join(cfg.WebDir, filepath.Clean("/"+r.URL.Path))); err != nil || r.URL.Path == "/" {
				w.Header().Set("Cache-Control", "no-cache")
				http.ServeFile(w, r, filepath.Join(cfg.WebDir, "index.html")) // SPA fallback
				return
			}
			if strings.HasPrefix(r.URL.Path, "/assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			static.ServeHTTP(w, r)
		})
	}
	origin, err := url.Parse(cfg.PublicOrigin)
	must(err)
	pub := &http.Server{Addr: cfg.Listen, Handler: gw.Wrap(mux), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10}
	if cfg.TLS == "internal-ca" {
		rc := &rotatingCert{issue: func() (tls.Certificate, error) {
			return env.WorkloadCert("core", []string{origin.Hostname(), "localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)}, 24*time.Hour)
		}}
		pub.TLSConfig = pki.ServerTLS(tls.Certificate{}, scPool, false)
		pub.TLSConfig.Certificates = nil
		pub.TLSConfig.GetCertificate = rc.get
	}

	// ---- mesh listener (Ring 3): mTLS with SPIFFE workload identities only
	mesh := http.NewServeMux()
	mesh.HandleFunc("POST /ingest/{sensor}", mon.IngestHandler)
	mesh.HandleFunc("POST /mesh/bridge/inbound", lg.HandleInbound)
	mesh.HandleFunc("GET /mesh/bridge/outbound", lg.HandleOutbound)
	mesh.HandleFunc("POST /mesh/bridge/outbound/ack", lg.HandleOutboundAck)
	meshRC := &rotatingCert{issue: func() (tls.Certificate, error) {
		return env.WorkloadCert("core", []string{"siepmu-core", "localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)}, 24*time.Hour)
	}}
	meshTLS := pki.ServerTLS(tls.Certificate{}, env.CA.Pool(), true)
	meshTLS.Certificates = nil
	meshTLS.GetCertificate = meshRC.get
	meshSrv := &http.Server{Addr: cfg.MeshListen, Handler: mesh, TLSConfig: meshTLS, ReadHeaderTimeout: 10 * time.Second}

	errc := make(chan error, 2)
	go func() {
		log.Printf("public listener on %s (tls=%s, origin %s)", cfg.Listen, cfg.TLS, cfg.PublicOrigin)
		if cfg.TLS == "internal-ca" {
			errc <- pub.ListenAndServeTLS("", "")
		} else {
			errc <- pub.ListenAndServe()
		}
	}()
	go func() {
		log.Printf("mesh mTLS listener on %s (trust domain %s)", cfg.MeshListen, pki.TrustDomain)
		errc <- meshSrv.ListenAndServeTLS("", "")
	}()
	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Printf("listener failed: %v", err)
		}
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pub.Shutdown(sctx)
	meshSrv.Shutdown(sctx)
	al.SignHead(sctx)
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
