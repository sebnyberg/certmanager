package certmanager

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/square/certstrap/pkix"
)

func GetCert(ctx context.Context, url string, certPassword string) (*x509.Certificate, *rsa.PrivateKey, error) {
	if !strings.Contains(url, "vault.azure.net") {
		return nil, nil, errors.New("only azure key vault URLs are supported")
	}

	return getAzureKVCert(ctx, url, certPassword)
}

func UploadCert(ctx context.Context, url string, cert *x509.Certificate, key *rsa.PrivateKey, certPassword string) error {
	if !strings.Contains(url, "vault.azure.net") {
		return errors.New("only azure key vault URLs are supported")
	}

	return uploadAzureKVCert(ctx, url, cert, key, certPassword)
}

// GenSignedCert generates a new certificate that has been signed by the provided
// certificate authority (CA). The provided hostname will be used as the CommonName (CN),
// and the list of sans, Subject Alternative Names (SAN), are added to the certificate as well.
//
// For mTLS, it is important that the server's hostname matches that of the certificate.
// For alternative addresses, simply add them to the sans list.
func GenSignedCert(
	caCert *x509.Certificate,
	caKey *rsa.PrivateKey,
	commonName string,
	sans []string,
) (*x509.Certificate, *rsa.PrivateKey, error) {
	var errOnce sync.Once
	var firstErr error
	check := func(err error) {
		if err != nil {
			errOnce.Do(func() {
				firstErr = err
			})
		}
	}

	// Parse CA key and cert
	pkixCAKey := pkix.NewKey(caKey.Public, caKey)
	pkixCACert := pkix.NewCertificateFromDER(caCert.Raw)

	// Generate key
	pkixKey, err := pkix.CreateRSAKey(2048)
	check(err)

	// Create CSR
	names := append([]string{commonName}, sans...)
	csr, err := pkix.CreateCertificateSigningRequest(pkixKey, "", nil, names, nil, "", "", "", "", commonName)
	check(err)

	// Sign
	pkixCert, err := pkix.CreateCertificateHost(pkixCACert, pkixCAKey, csr, time.Now().AddDate(10, 0, 0))
	check(err)

	// Parse cert as x509
	cert, err := pkixCert.GetRawCertificate()
	check(err)

	// Parse key as *rsa.Key
	key, ok := pkixKey.Private.(*rsa.PrivateKey)
	if !ok {
		errOnce.Do(func() {
			firstErr = errors.New("failed to parse crypto.key as rsa.PrivateKey")
		})
	}

	if firstErr == nil {
		return cert, key, firstErr
	}
	return nil, nil, firstErr
}

// GenCACert generates a self-signed Certificate Authority certificate and key.
func GenCACert(name string) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := pkix.CreateRSAKey(2048)
	if err != nil {
		return nil, nil, err
	}

	cert, err := pkix.CreateCertificateAuthority(key, "", time.Now().AddDate(0, 18, 0), "", "", "", "", name)
	if err != nil {
		return nil, nil, err
	}

	x509cert, err := cert.GetRawCertificate()
	if err != nil {
		return nil, nil, err
	}

	rsaKey, ok := key.Private.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("failed to parse private CA key as RSA key")
	}

	return x509cert, rsaKey, nil
}

func check(err error, msg string) {
	if err != nil {
		log.Fatal(msg)
	}
}

func wrapErr(s string, err error) error {
	return fmt.Errorf("%w: %v", err, s)
}

func appendErr(s string, err error) error {
	return fmt.Errorf("%v, err: %v", s, err)
}
