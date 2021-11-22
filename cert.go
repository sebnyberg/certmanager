package certmanager

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/square/certstrap/pkix"
)

func GetCert(
	ctx context.Context,
	url string,
	certPassword string,
) (cert *x509.Certificate, caCerts []*x509.Certificate, key *rsa.PrivateKey, err error) {
	if !strings.Contains(url, "vault.azure.net") {
		return nil, nil, nil, errors.New("only azure key vault URLs are supported")
	}

	return getAzureKVCert(ctx, url, certPassword)
}

func UploadCert(
	ctx context.Context,
	url string,
	cert *x509.Certificate,
	caCerts []*x509.Certificate,
	key *rsa.PrivateKey,
	certPassword string,
) error {
	if !strings.Contains(url, "vault.azure.net") {
		return errors.New("only azure key vault URLs are supported")
	}

	return uploadAzureKVCert(ctx, url, cert, caCerts, key, certPassword)
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
	expiry time.Time,
) (cert *x509.Certificate, key *rsa.PrivateKey, firstErr error) {
	var errOnce sync.Once
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
	pkixCert, err := pkix.CreateCertificateHost(pkixCACert, pkixCAKey, csr, expiry)
	check(err)

	// Parse cert as x509
	cert, err = pkixCert.GetRawCertificate()
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

// GenSelfSignedCA generates a self-signed Certificate Authority certificate and key.
func GenSelfSignedCA(
	name string,
	expiry time.Time,
) (cert *x509.Certificate, key *rsa.PrivateKey, err error) {
	pkixKey, err := pkix.CreateRSAKey(2048)
	if err != nil {
		return nil, nil, err
	}

	pkixCert, err := pkix.CreateCertificateAuthority(pkixKey, "", expiry, "", "", "", "", name)
	if err != nil {
		return nil, nil, err
	}

	x509cert, err := pkixCert.GetRawCertificate()
	if err != nil {
		return nil, nil, err
	}

	rsaKey, ok := pkixKey.Private.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("failed to parse private CA key as RSA key")
	}

	return x509cert, rsaKey, nil
}

func appendErr(s string, err error) error {
	return fmt.Errorf("%v, err: %v", s, err)
}
