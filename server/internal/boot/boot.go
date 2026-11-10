// Package boot opens the shared infrastructure (HSM, database, CA) used by
// the core service and the administration CLI.
package boot

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/Neurvinch/SIEPMU/server/internal/config"
	"github.com/Neurvinch/SIEPMU/server/internal/cryptoprov"
	"github.com/Neurvinch/SIEPMU/server/internal/guard"
	"github.com/Neurvinch/SIEPMU/server/internal/legacy"
	"github.com/Neurvinch/SIEPMU/server/internal/pki"
	"github.com/Neurvinch/SIEPMU/server/internal/servicekeys"
	"github.com/Neurvinch/SIEPMU/server/internal/store"
)

const caLabel = "siepmu-root-ca"

type Env struct {
	Cfg      *config.Config
	Provider cryptoprov.Provider
	KMS      *cryptoprov.PKCS11KMS
	DB       *store.Store
	CA       *pki.CA
}

// Open connects to the HSM and database. With create=true (siepmuctl init)
// missing HSM keys and the root CA are generated; otherwise their absence
// is an error so a service can never silently mint a new trust root.
func Open(ctx context.Context, cfgPath string, create bool) (*Env, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	kms, err := cryptoprov.NewPKCS11KMS(cfg.HSM)
	if err != nil {
		return nil, err
	}
	db, err := store.Open(ctx, cfg.PostgresDSN)
	if err != nil {
		return nil, err
	}
	if err := db.Migrate(ctx); err != nil {
		return nil, err
	}
	env := &Env{Cfg: cfg, Provider: cryptoprov.NewNIST(), KMS: kms, DB: db}
	caPath := filepath.Join(cfg.DataDir, "ca.pem")
	signer, err := kms.Signer(caLabel)
	pemBytes, perr := os.ReadFile(caPath)
	switch {
	case err == nil && perr == nil:
		env.CA, err = pki.LoadCA(pemBytes, signer)
		if err != nil {
			return nil, err
		}
	case !create:
		return nil, errors.New("root CA not initialised: run `siepmuctl init`")
	default:
		if err != nil {
			if signer, err = kms.CreateSigner(caLabel); err != nil {
				return nil, fmt.Errorf("create CA key in HSM: %w", err)
			}
		}
		if env.CA, err = pki.NewRootCA(signer, "SIEPMU-SX Internal Root CA", 10*365*24*time.Hour); err != nil {
			return nil, err
		}
		if err := os.WriteFile(caPath, env.CA.CertPEM(), 0o644); err != nil {
			return nil, err
		}
	}
	for _, kek := range []string{servicekeys.MasterKEK, guard.KEK, legacy.KEK} {
		if create {
			err = kms.EnsureKEK(kek)
		} else {
			_, err = kms.Wrap(kek, []byte("probe"), nil)
		}
		if err != nil {
			return nil, fmt.Errorf("HSM key %s: %w (run `siepmuctl init`)", kek, err)
		}
	}
	return env, nil
}

func (e *Env) Close() {
	e.DB.Close()
	e.KMS.Close()
}

// WorkloadCert issues a fresh in-memory workload certificate.
func (e *Env) WorkloadCert(spiffePath string, dns []string, ips []net.IP, ttl time.Duration) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	der, err := e.CA.IssueWorkload(key.Public(), spiffePath, dns, ips, ttl)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der, e.CA.Cert.Raw}, PrivateKey: key}, nil
}
