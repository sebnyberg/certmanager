package certmanager

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"time"
)

type signedCertificate struct {
	caCert   *x509.Certificate
	certPool *x509.CertPool
	tlsCert  tls.Certificate
}

func GetMTLSClientConfig(
	ctx context.Context,
	caURL string,
	caPassword string,
	clientName string,
	serverName string,
	expiresAt time.Time,
) (*tls.Config, error) {
	caCert, caCerts, caKey, err := GetCert(ctx, caURL, caPassword)
	if err != nil {
		return nil, err
	}

	cert, key, err := GenSignedCert(caCert, caKey, clientName, nil, expiresAt)
	if err != nil {
		return nil, err
	}

	certs := []*x509.Certificate{cert}
	if len(caCerts) > 0 {
		certs = append(certs, caCert)
		certs = append(certs, caCerts[:len(caCerts)-1]...)
	}

	tlsCert, err := TLSCertificate(certs, key)
	if err != nil {
		return nil, err
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	tlsConf := tls.Config{
		ServerName:   serverName,
		RootCAs:      caPool,
		Certificates: []tls.Certificate{tlsCert},
	}

	return &tlsConf, nil
}

func GetMTLSServerConfig(
	ctx context.Context,
	caURL string,
	caPassword string,
	hostname string,
	altNames []string,
	expiresAt time.Time,
) (*tls.Config, error) {
	caCert, caCerts, caKey, err := GetCert(ctx, caURL, caPassword)
	if err != nil {
		return nil, err
	}

	cert, key, err := GenSignedCert(caCert, caKey, hostname, altNames, expiresAt)
	if err != nil {
		return nil, err
	}

	certs := []*x509.Certificate{cert}
	if len(caCerts) > 0 {
		certs = append(certs, caCert)
		certs = append(certs, caCerts[:len(caCerts)-1]...)
	}

	tlsCert, err := TLSCertificate(certs, key)
	if err != nil {
		return nil, err
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	tlsConf := tls.Config{
		ClientCAs:    caPool,
		Certificates: []tls.Certificate{tlsCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	return &tlsConf, nil
}

// TLSCertificate returns a tls.Certificate from the provided certs and key
func TLSCertificate(certs []*x509.Certificate, key *rsa.PrivateKey) (tls.Certificate, error) {
	certBytes := make([]byte, 0)
	for _, cert := range certs {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		certBytes = append(certBytes, block.Bytes...)
	}
	keyBytes := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	return tls.X509KeyPair(certBytes, keyBytes.Bytes)
}
