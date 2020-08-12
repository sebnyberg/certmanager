package certmanager

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"

	"github.com/square/certstrap/pkix"
)

type signedCertificate struct {
	caCert      *pkix.Certificate
	caCertBytes []byte
	cert        *pkix.Certificate
	certBytes   []byte
	certPool    *x509.CertPool
	tlsCert     tls.Certificate
	key         *pkix.Key
	keyBytes    []byte
}

func getTLSConfig(
	ctx context.Context,
	caURL string,
	caPassword string,
	commonName string,
	sans []string,
) (*signedCertificate, error) {
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

	x509Cert, rsaKey, err := GenSignedCert(ca509Cert, caRSAKey, commonName, sans)
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

	signedCert := signedCertificate{
		caCert:      caCert,
		caCertBytes: caCertBytes,
		cert:        cert,
		certBytes:   certBytes,
		certPool:    certPool,
		tlsCert:     tlsCert,
		key:         key,
		keyBytes:    keyBytes,
	}

	return &signedCert, nil
}

func MTLSClientConfig(
	ctx context.Context,
	caURL string,
	caPassword string,
	clientName string,
	serverName string,
) (*tls.Config, error) {
	signedCert, err := getTLSConfig(ctx, caURL, caPassword, clientName, nil)
	if err != nil {
		return nil, err
	}

	tlsConf := tls.Config{
		Certificates: []tls.Certificate{signedCert.tlsCert},
		RootCAs:      signedCert.certPool,
		ServerName:   serverName,
	}

	return &tlsConf, nil
}

func MTLSServerConfig(
	ctx context.Context,
	caURL string,
	caPassword string,
	hostname string,
	altNames []string,
) (*tls.Config, error) {
	signedCert, err := getTLSConfig(ctx, caURL, caPassword, hostname, altNames)
	if err != nil {
		return nil, err
	}

	tlsConf := tls.Config{
		Certificates: []tls.Certificate{signedCert.tlsCert},
		ClientCAs:    signedCert.certPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	return &tlsConf, nil
}
