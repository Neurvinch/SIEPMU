package identity

import "crypto/x509"

func x509Pool(certs []*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

func x509VerifyOpts(roots, inter *x509.CertPool) x509.VerifyOptions {
	return x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
}
