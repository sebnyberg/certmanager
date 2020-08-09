package certcli

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/sebnyberg/certmanager"
	"github.com/sebnyberg/flagtags"
	"github.com/square/certstrap/pkix"
	"github.com/urfave/cli/v2"
)

type DownloadConfig struct {
	URL              string `env:"URL" usage:"Secret URL, e.g. https://myvault.azure.net/secrets/mycert"`
	CertPassword     string `usage:"Certificate password - leave blank if none"`
	OutDir           string `usage:"Output directory, defaults to current directory"`
	FileNameOverride string `usage:"Override default file name (common name)"`
	TimeoutSeconds   int    `name:"timeout" usage:"Timeout in seconds before giving up" value:"10"`
}

func (c DownloadConfig) validate() error {
	if len(c.URL) == 0 {
		return errors.New("URL is required")
	}

	if len(c.OutDir) > 0 {
		fi, err := os.Stat(c.OutDir)
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

func NewCmdDownload() *cli.Command {
	var conf DownloadConfig

	return &cli.Command{
		Name:        "download",
		Description: "Download a certificate and its key",
		Flags:       flagtags.MustParseFlags(&conf),
		Action: func(c *cli.Context) error {
			if err := conf.validate(); err != nil {
				return err
			}
			return Download(conf)
		},
	}
}

func Download(conf DownloadConfig) error {
	timeoutSeconds := 10
	if conf.TimeoutSeconds > 0 {
		timeoutSeconds = conf.TimeoutSeconds
	}
	timeout := time.Second * time.Duration(timeoutSeconds)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	rsaKey, x509Cert, err := certmanager.GetCert(ctx, conf.URL, conf.CertPassword)
	if err != nil {
		select {
		case <-ctx.Done():
			return errors.New("request timed out - please verify that the URL is correct")
		default:
		}
		return err
	}

	fileName := x509Cert.Subject.CommonName
	if len(conf.FileNameOverride) > 0 {
		fileName = conf.FileNameOverride
	}

	outDir := "."
	if len(conf.OutDir) > 0 {
		outDir = conf.OutDir
	}
	os.MkdirAll(outDir, 0644)

	// Write key to file
	key := pkix.NewKey(rsaKey.Public, rsaKey)
	keyBytes, err := key.ExportPrivate()
	if err != nil {
		return err
	}
	keyPath := outDir + "/" + fileName + ".key"
	log.Println("saving certificate key to", keyPath, "...")
	keyFile, err := os.OpenFile(keyPath, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer keyFile.Close()
	_, err = keyFile.Write(keyBytes)
	if err != nil {
		return err
	}

	// Write cert to file
	cert := pkix.NewCertificateFromDER(x509Cert.Raw)
	certBytes, err := cert.Export()
	if err != nil {
		return err
	}
	certPath := outDir + "/" + fileName + ".crt"
	log.Println("saving certificate to", certPath, "...")
	certFile, err := os.OpenFile(certPath, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer certFile.Close()
	_, err = certFile.Write(certBytes)
	if err != nil {
		return err
	}

	return nil
}
