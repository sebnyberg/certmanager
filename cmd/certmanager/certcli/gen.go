package certcli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/sebnyberg/certmanager"
	"github.com/sebnyberg/flagtags"
	"github.com/urfave/cli/v2"
)

type GenSignedClientConfig struct {
	CAURL          string `env:"CA_URL" name:"ca-url" usage:"URL to CA certificate secret e.g. https://myvault.azure.net/secrets/myca"`
	CACertPassword string `usage:"CA Certificate password - leave blank if none"`
	OutDir         string `usage:"Output directory, defaults to current directory"`
	TimeoutSeconds int    `name:"timeout" usage:"Timeout in seconds before giving up" value:"10"`
	ClientName     string `usage:"Identifier for the client, e.g. 'cli-client'"`
}

func (c GenSignedClientConfig) validate() error {
	if len(c.CAURL) == 0 {
		return errors.New("URL is required")
	}

	if len(c.ClientName) < 3 {
		return errors.New("client name is required")
	}

	return validateDir(c.OutDir)
}

func NewCmdGen() *cli.Command {
	return &cli.Command{
		Name:        "gen",
		Description: "generate certificates and keys",
		Subcommands: []*cli.Command{
			newCmdSignedClient(),
		},
	}
}

// Generate a client certificate signed by a CA.
func newCmdSignedClient() *cli.Command {
	var conf GenSignedClientConfig

	return &cli.Command{
		Name:        "signed-client",
		Description: "Generate a client certificate signed by a CA",
		Flags:       flagtags.MustParseFlags(&conf),
		Action: func(c *cli.Context) error {
			if err := conf.validate(); err != nil {
				return err
			}
			return genSignedClient(conf)
		},
	}
}

func genSignedClient(conf GenSignedClientConfig) error {
	timeoutSeconds := 10
	if conf.TimeoutSeconds > 0 {
		timeoutSeconds = conf.TimeoutSeconds
	}
	timeout := time.Second * time.Duration(timeoutSeconds)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Create output dir
	outDir := "."
	if len(conf.OutDir) > 0 {
		outDir = conf.OutDir
	}
	os.MkdirAll(outDir, 0644)

	// Fetch CA cert and key
	caCert, caKey, err := certmanager.GetCert(ctx, conf.CAURL, conf.CACertPassword)
	if err != nil {
		return err
	}

	// Sign client
	clientCert, clientKey, err := certmanager.GenSignedClientCert(caCert, caKey, conf.ClientName)
	if err != nil {
		return err
	}

	// Write files
	caCertPath := fmt.Sprintf("%v/%v.crt", outDir, caCert.Subject.CommonName)
	if err := writeCert(caCertPath, caCert); err != nil {
		return err
	}

	clientCertPath := fmt.Sprintf("%v/%v.crt", outDir, conf.ClientName)
	if err := writeCert(clientCertPath, clientCert); err != nil {
		return err
	}

	clientKeyPath := fmt.Sprintf("%v/%v.key", outDir, conf.ClientName)
	if err := writeKey(clientKeyPath, clientKey); err != nil {
		return err
	}

	return nil
}
