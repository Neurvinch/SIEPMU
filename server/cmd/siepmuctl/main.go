// siepmuctl administers a SIEPMU-SX deployment: first-time initialisation
// of the HSM-backed trust root, workload certificates, bridges and users.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Neurvinch/SIEPMU/server/internal/audit"
	"github.com/Neurvinch/SIEPMU/server/internal/boot"
	"github.com/Neurvinch/SIEPMU/server/internal/cryptoprov"
	"github.com/Neurvinch/SIEPMU/server/internal/identity"
	"github.com/Neurvinch/SIEPMU/server/internal/pki"
	"github.com/Neurvinch/SIEPMU/server/internal/servicekeys"
)

const usage = `siepmuctl <command> [flags]

  init            create HSM keys, the root CA and the database schema
  create-unit     add an organisational unit
  create-user     provision a user and print the one-time enrolment code
  issue-cert      issue an mTLS workload certificate (X.509-SVID)
  register-bridge register a legacy bridge's signing key
  keygen          generate a composite signing key or an X-Wing KEM key
  guard-pubkey    print the BLACK guard's release-signing public key
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfg := fs.String("config", "config.yaml", "configuration file")
	ctx := context.Background()
	switch cmd {
	case "init":
		fs.Parse(args)
		env, err := boot.Open(ctx, *cfg, true)
		check(err)
		defer env.Close()
		fmt.Printf("HSM token %q ready; root CA fingerprint %s\nCA certificate: %s\n", env.Cfg.HSM.TokenLabel, pki.Fingerprint(env.CA.Cert), filepath.Join(env.Cfg.DataDir, "ca.pem"))

	case "create-unit":
		code := fs.String("code", "", "unit code")
		name := fs.String("name", "", "unit name")
		parent := fs.String("parent", "", "parent unit code")
		fs.Parse(args)
		env, ids := open(ctx, *cfg)
		defer env.Close()
		check(ids.EnsureUnit(ctx, *code, *name, *parent))
		fmt.Println("unit", *code, "ready")

	case "create-user":
		var n identity.NewUser
		fs.StringVar(&n.ServiceNumber, "service-number", "", "service number")
		fs.StringVar(&n.FullName, "name", "", "full name")
		fs.StringVar(&n.Rank, "rank", "", "rank")
		fs.StringVar(&n.Unit, "unit", "", "unit code")
		fs.IntVar(&n.Clearance, "clearance", 0, "0 UNCLASSIFIED .. 4 TOP SECRET")
		comp := fs.String("compartments", "", "comma-separated compartments")
		roles := fs.String("roles", "member", "comma-separated roles: member,commander,soc,auditor,admin,release_officer")
		fs.Parse(args)
		n.Roles = split(*roles)
		n.Compartments = split(*comp)
		env, ids := open(ctx, *cfg)
		defer env.Close()
		u, code, err := ids.CreateUser(ctx, "siepmuctl", n)
		check(err)
		fmt.Printf("user %s (%s) created\nenrolment code (valid 72 h, single use): %s\n", u.ServiceNumber, u.ID, code)

	case "issue-cert":
		id := fs.String("id", "", "SPIFFE path, e.g. bridge/alpha or sensor/suricata")
		out := fs.String("out", ".", "output directory")
		dns := fs.String("dns", "", "comma-separated DNS SANs")
		ttl := fs.Duration("ttl", 30*24*time.Hour, "validity")
		fs.Parse(args)
		if *id == "" {
			check(fmt.Errorf("--id is required"))
		}
		env, err := boot.Open(ctx, *cfg, false)
		check(err)
		defer env.Close()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		check(err)
		der, err := env.CA.IssueWorkload(key.Public(), *id, split(*dns), []net.IP{net.IPv4(127, 0, 0, 1)}, *ttl)
		check(err)
		base := filepath.Join(*out, strings.ReplaceAll(*id, "/", "-"))
		check(os.MkdirAll(*out, 0o700))
		check(pki.WriteKeyPairPEM(base+".crt", base+".key", der, key))
		check(os.WriteFile(filepath.Join(*out, "ca.pem"), env.CA.CertPEM(), 0o644))
		fmt.Printf("issued spiffe://%s/%s -> %s.crt, %s.key (valid %s)\n", pki.TrustDomain, *id, base, base, *ttl)

	case "register-bridge":
		name := fs.String("name", "", "bridge name (SPIFFE path bridge/<name>)")
		pub := fs.String("pubkey", "", "base64 composite signing public key")
		fs.Parse(args)
		pk, err := base64.StdEncoding.DecodeString(*pub)
		check(err)
		env, err := boot.Open(ctx, *cfg, false)
		check(err)
		defer env.Close()
		_, err = env.DB.Exec(ctx, `INSERT INTO bridges(name, public_key) VALUES ($1,$2) ON CONFLICT (name) DO UPDATE SET public_key=EXCLUDED.public_key`, *name, pk)
		check(err)
		fmt.Println("bridge", *name, "registered")

	case "keygen":
		kind := fs.String("type", "signing", "signing | kem")
		out := fs.String("out", "", "private key output file")
		fs.Parse(args)
		p := cryptoprov.NewNIST()
		var priv, pub []byte
		if *kind == "kem" {
			var err error
			pub, priv, err = p.KEM().GenerateKeyPair()
			check(err)
		} else {
			s, seed, err := p.NewSigner(nil)
			check(err)
			priv, pub = seed, s.PublicKey()
		}
		check(os.WriteFile(*out, []byte(base64.StdEncoding.EncodeToString(priv)+"\n"), 0o600))
		fmt.Printf("private key written to %s\npublic key: %s\n", *out, base64.StdEncoding.EncodeToString(pub))

	case "guard-pubkey":
		fs.Parse(args)
		env, err := boot.Open(ctx, *cfg, false)
		check(err)
		defer env.Close()
		s, err := servicekeys.HybridSigner(ctx, env.DB, env.KMS, env.Provider, "guard-release")
		check(err)
		fmt.Println(base64.StdEncoding.EncodeToString(s.PublicKey()))

	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

// open builds an identity service for CLI provisioning (no event bus).
func open(ctx context.Context, cfgPath string) (*boot.Env, *identity.Service) {
	env, err := boot.Open(ctx, cfgPath, false)
	check(err)
	signer, err := servicekeys.HybridSigner(ctx, env.DB, env.KMS, env.Provider, "audit-log")
	check(err)
	al, err := audit.New(ctx, env.DB, signer)
	check(err)
	ids, err := identity.New(env.Cfg, env.DB, redis.NewClient(&redis.Options{Addr: env.Cfg.RedisAddr}), make([]byte, 32), env.CA, al, nil, nil, nil)
	check(err)
	return env, ids
}

func split(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
