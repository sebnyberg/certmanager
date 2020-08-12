package certmanager

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"

	"github.com/square/certstrap/pkix"
)

func GetTLSConfig(
	ctx context.Context,
	caURL string,
	caPassword string,
	hostname string,
	sans []string,
) (*tls.Config, error) {
	ca509Cert, caRSAKey, err := GetCert(ctx, caURL, caPassword)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	caCert := pkix.NewCertificateFromDER(ca509Cert.Raw)
	caCertBytes, err := caCert.Export()
	if err != nil {
		return nil, err
	}
	if ok := certPool.AppendCertsFromPEM(caCertBytes); !ok {
		return nil, errors.New("failed to create certificate pool")
	}

	x509Cert, rsaKey, err := GenSignedCert(ca509Cert, caRSAKey, hostname, sans)
	if err != nil {
		return nil, err
	}

	cert := pkix.NewCertificateFromDER(x509Cert.Raw)
	certBytes, err := cert.Export()
	if err != nil {
		return nil, err
	}

	key := pkix.NewKey(rsaKey.Public, rsaKey)
	keyBytes, err := key.ExportPrivate()
	if err != nil {
		return nil, err
	}

	tlsCert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return nil, err
	}

	tlsConf := tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      certPool,
	}

	return &tlsConf, nil
}
