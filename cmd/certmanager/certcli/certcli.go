package certcli

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/square/certstrap/pkix"
)

func validateDir(dir string) error {
	if len(dir) > 0 {
		fi, err := os.Stat(dir)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("failed to validate output directory, err: %v", err)
			}
		} else {
			if !fi.IsDir() {
				return errors.New("output directory must not be a file")
			}
		}
	}
	return nil
}

func writeKey(path string, rsaKey *rsa.PrivateKey) error {
	key := pkix.NewKey(rsaKey.Public, rsaKey)
	keyBytes, err := key.ExportPrivate()
	if err != nil {
		return err
	}
	log.Println("saving certificate key to", path, "...")
	keyFile, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer keyFile.Close()
	_, err = keyFile.Write(keyBytes)

	return err
}

func writeCert(path string, x509Cert *x509.Certificate) error {
	cert := pkix.NewCertificateFromDER(x509Cert.Raw)
	certBytes, err := cert.Export()
	if err != nil {
		return err
	}
	log.Println("saving certificate to", path, "...")
	certFile, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer certFile.Close()
	_, err = certFile.Write(certBytes)
	return err
}
