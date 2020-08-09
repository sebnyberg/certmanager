package certcli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sebnyberg/certmanager"
	"github.com/sebnyberg/flagtags"
	"github.com/urfave/cli/v2"
)

func NewCmdGen() *cli.Command {
	return &cli.Command{
		Name:        "gen",
		Description: "generate certificates and keys",
		Subcommands: []*cli.Command{
			newCmdSignedCert(),
			newCmdGenCACert(),
		},
	}
}

type genSignedConfig struct {
	CAURL          string `env:"CA_URL" name:"ca-url" usage:"URL to CA certificate secret e.g. https://myvault.azure.net/secrets/myca"`
	CACertPassword string `usage:"CA Certificate password - leave blank if none"`
	OutDir         string `value:"." usage:"Output directory, defaults to current directory"`
	TimeoutSeconds int    `name:"timeout" usage:"Timeout in seconds before giving up" value:"10"`
	CommonName     string `usage:"Hostname for a server, e.g. '*.dev.my.domain.com' and any id for a client, e.g. 'my-client'"`
	Domains        string `usage:"Comma-separated list of alternative domain names"`
}

func (c genSignedConfig) validate() error {
	if len(c.CAURL) == 0 {
		return errors.New("CA URL is required")
	}

	if len(c.CommonName) == 0 {
		return errors.New("common name is required")
	}

	return validateDir(c.OutDir)
}

type genCAConfig struct {
	URL            string `usage:"Certificate URL to upload result to, e.g. https://myvault.azure.net/certificates/myca"`
	Name           string `usage:"Certificate Authority (CA) name" name:"name"`
	CertPassword   string `usage:"Certificate Authority (CA) certificate password - leave blank if none"`
	TimeoutSeconds int    `name:"timeout" usage:"Timeout in seconds before giving up" value:"10"`
}

func (c genCAConfig) validate() error {
	if len(c.URL) == 0 {
		return errors.New("URL is required")
	}
	if len(c.Name) == 0 {
		return errors.New("CA name is required")
	}
	if !strings.HasSuffix(c.URL, c.Name) {
		return errors.New("CA name must match certificate name in the URL, e.g. MyCA -> https://myvault.azure.net/certificates/MyCA")
	}
	return nil
}

func newCmdGenCACert() *cli.Command {
	var conf genCAConfig

	return &cli.Command{
		Name:        "ca-cert",
		Description: "Generate and upload a CA certificate",
		Flags:       flagtags.MustParseFlags(&conf),
		Action: func(c *cli.Context) error {
			if err := conf.validate(); err != nil {
				return err
			}
			return genCACert(conf)
		},
	}
}

func genCACert(conf genCAConfig) error {
	// Initialize context
	timeoutSeconds := 10
	if conf.TimeoutSeconds > 0 {
		timeoutSeconds = conf.TimeoutSeconds
	}
	timeout := time.Second * time.Duration(timeoutSeconds)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cert, key, err := certmanager.GenCACert(conf.Name)
	if err != nil {
		return err
	}

	return certmanager.UploadCert(ctx, conf.URL, cert, key, conf.CertPassword)
}

// Generate a client certificate signed by a CA.
func newCmdSignedCert() *cli.Command {
	var conf genSignedConfig

	return &cli.Command{
		Name:        "signed-cert",
		Description: "Generate a client certificate signed by a CA",
		Flags:       flagtags.MustParseFlags(&conf),
		Action: func(c *cli.Context) error {
			if err := conf.validate(); err != nil {
				return err
			}
			return genSignedCert(conf)
		},
	}
}

func genSignedCert(conf genSignedConfig) error {
	// Initialize context
	timeoutSeconds := 10
	if conf.TimeoutSeconds > 0 {
		timeoutSeconds = conf.TimeoutSeconds
	}
	timeout := time.Second * time.Duration(timeoutSeconds)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Parse domain names
	if len(conf.Domains) > 0 {
		domains := strings.Split(conf.Domains, ",")
		for i := range domains {
			domains[i] = strings.Trim(domains[i], " ")
		}
	}

	// Create output dir
	if err := os.MkdirAll(conf.OutDir, 0644); err != nil {
		return err
	}

	// Fetch CA cert and key
	caCert, caKey, err := certmanager.GetCert(ctx, conf.CAURL, conf.CACertPassword)
	if err != nil {
		return err
	}

	// Sign cert
	cert, key, err := certmanager.GenSignedCert(caCert, caKey, conf.CommonName, []string{"localhost"})
	if err != nil {
		return err
	}

	// Write files
	caCertPath := fmt.Sprintf("%v/%v.crt", conf.OutDir, caCert.Subject.CommonName)
	if err := writeCert(caCertPath, caCert); err != nil {
		return err
	}

	clientCertPath := fmt.Sprintf("%v/%v.crt", conf.OutDir, conf.CommonName)
	if err := writeCert(clientCertPath, cert); err != nil {
		return err
	}

	clientKeyPath := fmt.Sprintf("%v/%v.key", conf.OutDir, conf.CommonName)
	if err := writeKey(clientKeyPath, key); err != nil {
		return err
	}

	return nil
}
