package certmanager

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.0/keyvault"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/Azure/go-autorest/autorest/azure/cli"
	"golang.org/x/crypto/pkcs12"
)

func getAzureKVCert(ctx context.Context, urlStr string, certPassword string) (*rsa.PrivateKey, *x509.Certificate, error) {
	kv := keyvault.New()

	var err error

	// Retrieve access credentials
	kv.Authorizer, err = newAzureCLIAuthorizer()
	if err != nil {
		kv.Authorizer, err = newAzureEnvAuthorizer()
		if err != nil {
			return nil, nil, appendErr("failed to authenticate against Azure", err)
		}
	}

	// Parse URL provided by caller
	baseURL, secretName, secretVersion, err := parseAzureSecretURL(urlStr)
	if err != nil {
		return nil, nil, appendErr("failed to parse secret URL", err)
	}

	// Retrieve secret and validate content type
	bundle, err := kv.GetSecret(ctx, baseURL, secretName, secretVersion)
	if err != nil {
		return nil, nil, appendErr("failed to retrieve secret", err)
	}
	expectedContentType := "application/x-pkcs12"
	if len(*bundle.ContentType) == 0 || *bundle.ContentType != expectedContentType {
		return nil, nil, fmt.Errorf("invalid secret content type '%v', should be '%v'", *bundle.ContentType, expectedContentType)
	}

	// Decode contents
	pfx, err := base64.StdEncoding.DecodeString(*bundle.Value)
	if err != nil {
		return nil, nil, appendErr("failed to base64-decode secret", err)
	}

	// Convert secret contents to PEM blocks
	blocks, err := pkcs12.ToPEM(pfx, certPassword)
	if err != nil {
		return nil, nil, appendErr("failed to convert pkcs12 to PEM", err)
	}
	if len(blocks) != 2 {
		return nil, nil, fmt.Errorf("PEM should contain two (2) blocks: cert and key - got: %v", len(blocks))
	}

	var (
		key  *rsa.PrivateKey
		cert *x509.Certificate
	)

	for _, block := range blocks {
		switch block.Type {
		case "PRIVATE KEY":
			if key, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
				return nil, nil, appendErr("failed to parse private key", err)
			}
		case "CERTIFICATE":
			if cert, err = x509.ParseCertificate(block.Bytes); err != nil {
				return nil, nil, appendErr("failed to parse certificate", err)
			}
		default:
			return nil, nil, fmt.Errorf("invalid PEM block (%v)", block.Type)
		}
	}

	return key, cert, nil
}

var kvResourceURL = "https://vault.azure.net"

func newAzureCLIAuthorizer() (autorest.Authorizer, error) {
	token, err := cli.GetTokenFromCLI(kvResourceURL)
	if err != nil {
		return nil, err
	}

	adalToken, err := token.ToADALToken()
	if err != nil {
		return nil, err
	}

	return autorest.NewBearerAuthorizer(&adalToken), nil
}

func newAzureEnvAuthorizer() (autorest.Authorizer, error) {
	// Since subsequent queries with invalid credentials just hang indefinitely,
	// we test for the most commonly used environment variable (service principal auth).
	for _, s := range []string{"AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_SECRET"} {
		if len(os.Getenv(s)) == 0 {
			return nil, fmt.Errorf("env var %v required when not logged into Azure CLI", s)
		}
	}
	if err := os.Setenv("AZURE_AD_RESORUCE", "KeyVault"); err != nil {
		return nil, err
	}

	return auth.NewAuthorizerFromEnvironment()
}

var errInvalidKeyVaultURL = errors.New("invalid key vault secret URL, expected format: https://{baseURL}/secrets/{secretName}(/{version})")

func parseAzureSecretURL(urlStr string) (baseURL, secretName, secretVersion string, err error) {
	var url *url.URL
	url, err = url.Parse(urlStr)
	if err != nil {
		return
	}

	var r *regexp.Regexp
	r, err = regexp.Compile("/secrets/([^/]+)/?([^/]+)?")
	if err != nil {
		err = errInvalidKeyVaultURL
		return
	}
	matches := r.FindStringSubmatch(url.Path)
	if len(matches) <= 1 || len(matches) > 3 {
		err = errInvalidKeyVaultURL
		return
	}

	baseURL = url.Scheme + "://" + url.Host
	secretName = matches[1]
	secretVersion = matches[2]

	return
}
