// siepmu-bridge connects legacy links (KISS/AX.25 radio, ACP-127 message
// switches, Iridium SBD) to the SIEPMU-SX mesh.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Neurvinch/SIEPMU/server/internal/bridge"
	"github.com/Neurvinch/SIEPMU/server/internal/cryptoprov"
	"github.com/Neurvinch/SIEPMU/server/internal/pki"
)

type config struct {
	Name       string `yaml:"name"`
	CoreURL    string `yaml:"core_url"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	CAFile     string `yaml:"ca_file"`
	SigningKey string `yaml:"signing_key_file"`
	SpoolDir   string `yaml:"spool_dir"`
	AX25       *struct {
		KISSAddr       string `yaml:"kiss_addr"`
		Callsign       string `yaml:"callsign"`
		Classification int    `yaml:"classification"`
	} `yaml:"ax25"`
	ACP127 *struct {
		Listen   string `yaml:"listen"`
		SendAddr string `yaml:"send_addr"`
		Station  string `yaml:"station"`
	} `yaml:"acp127"`
	SBD *struct {
		Listen         string `yaml:"listen"`
		Classification int    `yaml:"classification"`
	} `yaml:"sbd"`
}

func main() {
	cfgPath := flag.String("config", "bridge.yaml", "bridge configuration")
	flag.Parse()
	raw, err := os.ReadFile(*cfgPath)
	must(err)
	var cfg config
	must(yaml.Unmarshal(raw, &cfg))
	seedB64, err := os.ReadFile(cfg.SigningKey)
	must(err)
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(seedB64)))
	must(err)
	signer, _, err := cryptoprov.NewNIST().NewSigner(seed)
	must(err)
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	must(err)
	caPEM, err := os.ReadFile(cfg.CAFile)
	must(err)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		log.Fatal("ca_file contains no certificates")
	}
	r := &bridge.Runner{
		Name: cfg.Name, CoreURL: strings.TrimRight(cfg.CoreURL, "/"), Signer: signer, Spool: bridge.Spool{Dir: cfg.SpoolDir}, Interval: 2 * time.Second,
		Client: &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: pki.ClientTLS(cert, roots, "core")}},
	}
	if c := cfg.AX25; c != nil {
		r.Adapters = append(r.Adapters, &bridge.AX25{Addr: c.KISSAddr, Callsign: c.Callsign, Class: c.Classification})
	}
	if c := cfg.ACP127; c != nil {
		r.Adapters = append(r.Adapters, &bridge.ACP127{Listen: c.Listen, SendAddr: c.SendAddr, Station: c.Station})
	}
	if c := cfg.SBD; c != nil {
		r.Adapters = append(r.Adapters, &bridge.SBD{Listen: c.Listen, Class: c.Classification})
	}
	if len(r.Adapters) == 0 {
		log.Fatal("no adapters configured")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Printf("bridge %s: %d adapter(s), mesh %s", cfg.Name, len(r.Adapters), cfg.CoreURL)
	must(r.Run(ctx))
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
