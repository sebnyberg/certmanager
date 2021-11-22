package certcli

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"time"

	"github.com/sebnyberg/certmanager"
	"github.com/sebnyberg/flagtags"
	"github.com/urfave/cli/v2"
)

type DownloadConfig struct {
	URL            string `env:"URL" usage:"Secret URL, e.g. https://myvault.azure.net/secrets/mycert"`
	CertPassword   string `usage:"Certificate password - leave blank if none"`
	OutDir         string `value:"." usage:"Output directory, defaults to current directory"`
	TimeoutSeconds int    `name:"timeout" usage:"Timeout in seconds before giving up" value:"10"`
}

func (c DownloadConfig) validate() error {
	if len(c.URL) == 0 {
		return errors.New("URL is required")
	}
	return validateDir(c.OutDir)
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
			return download(conf)
		},
	}
}

func download(conf DownloadConfig) error {
	timeoutSeconds := 10
	if conf.TimeoutSeconds > 0 {
		timeoutSeconds = conf.TimeoutSeconds
	}
	timeout := time.Second * time.Duration(timeoutSeconds)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cert, caCerts, key, err := certmanager.GetCert(ctx, conf.URL, conf.CertPassword)
	if err != nil {
		select {
		case <-ctx.Done():
			return errors.New("request timed out - please verify that the URL is correct")
		default:
		}
		return err
	}

	certs := []*x509.Certificate{cert}
	certs = append(certs, caCerts...)

	fileName := cert.Subject.CommonName
	if err = os.MkdirAll(conf.OutDir, 0644); err != nil {
		return err
	}

	// Write key to file
	keyPath := conf.OutDir + "/" + fileName + ".key"
	if err = writeKey(keyPath, key); err != nil {
		return err
	}

	// Write cert to file
	certPath := conf.OutDir + "/" + fileName + ".crt"
	if err := writeCert(certPath, certs...); err != nil {
		return err
	}

	return nil
}
