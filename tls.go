package certmanager

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"time"

	"github.com/square/certstrap/pkix"
)

type signedCertificate struct {
	caCert   *x509.Certificate
	certPool *x509.CertPool
	tlsCert  tls.Certificate
}

// TLSCertificate returns a tls.Certificate from the provided cert and key
func TLSCertificate(cert *x509.Certificate, key *rsa.PrivateKey) (tls.Certificate, error) {
	pkixCert := pkix.NewCertificateFromDER(cert.Raw)
	certPEM, err := pkixCert.Export()
	if err != nil {
		return tls.Certificate{}, err
	}
	pkixKey := pkix.NewKey(key.Public, key)
	keyPEM, err := pkixKey.ExportPrivate()
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(certPEM, keyPEM)
}

func GetMTLSClientConfig(
	ctx context.Context,
	caURL string,
	caPassword string,
	clientName string,
	serverName string,
	expiresAt time.Time,
) (*tls.Config, error) {
	caCert, caKey, err := GetCert(ctx, caURL, caPassword)
	if err != nil {
		return nil, err
	}

	cert, key, err := GenSignedCert(caCert, caKey, clientName, nil, expiresAt)
	if err != nil {
		return nil, err
	}

	tlsCert, err := TLSCertificate(cert, key)
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
	caCert, caKey, err := GetCert(ctx, caURL, caPassword)
	if err != nil {
		return nil, err
	}

	cert, key, err := GenSignedCert(caCert, caKey, hostname, altNames, expiresAt)
	if err != nil {
		return nil, err
	}

	tlsCert, err := TLSCertificate(cert, key)
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
