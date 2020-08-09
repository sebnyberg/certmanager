package certmanager

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"strings"
)

func GetCert(ctx context.Context, url string, certPassword string) (*rsa.PrivateKey, *x509.Certificate, error) {
	if !strings.Contains(url, "vault.azure.net") {
		return nil, nil, errors.New("only azure key vault URLs are supported")
	}

	return getAzureKVCert(ctx, url, certPassword)
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
