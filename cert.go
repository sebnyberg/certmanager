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

func GenSignedClientCert(caCert *x509.Certificate, caKey *rsa.PrivateKey, clientName string) (*x509.Certificate, *rsa.PrivateKey, error) {
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
	pkixClientKey, err := pkix.CreateRSAKey(2048)
	check(err)

	// Create CSR
	csr, err := pkix.CreateCertificateSigningRequest(pkixClientKey, "", nil, []string{clientName}, nil, "", "", "", "", clientName)
	check(err)

	// Sign
	pkixClientCert, err := pkix.CreateCertificateHost(pkixCACert, pkixCAKey, csr, time.Now().AddDate(0, 18, 0))
	check(err)

	// Parse cert as x509
	clientCert, err := pkixClientCert.GetRawCertificate()
	check(err)

	// Parse key as *rsa.Key
	clientKey, ok := pkixClientKey.Private.(*rsa.PrivateKey)
	if !ok {
		errOnce.Do(func() {
			firstErr = errors.New("failed to parse crypto.key as rsa.PrivateKey")
		})
	}

	if firstErr == nil {
		return clientCert, clientKey, firstErr
	}
	return nil, nil, firstErr
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
