package certmanager

import (
	"context"
	"crypto/rand"
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
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func newAzureKVClient() (keyvault.BaseClient, error) {
	kv := keyvault.New()

	var err error

	// Retrieve access credentials
	kv.Authorizer, err = newAzureCLIAuthorizer()
	if err != nil {
		kv.Authorizer, err = newAzureEnvAuthorizer()
		if err != nil {
			return kv, appendErr("failed to authenticate against Azure", err)
		}
	}

	return kv, nil
}

func getAzureKVCert(ctx context.Context, urlStr string, certPassword string) (*x509.Certificate, *rsa.PrivateKey, error) {
	kv, err := newAzureKVClient()
	if err != nil {
		return nil, nil, err
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

	// Decode contents from base64
	pfx, err := base64.StdEncoding.DecodeString(*bundle.Value)
	if err != nil {
		return nil, nil, appendErr("failed to base64-decode secret", err)
	}

	// Decode pfx to x509.Certificate and rsa.PublicKey
	keyIface, cert, err := pkcs12.Decode(pfx, certPassword)
	if err != nil {
		return nil, nil, appendErr("failed to parse pkcs12", err)
	}
	key, ok := keyIface.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("failed to parse key as rsa.PrivateKey")
	}
	return cert, key, nil
}

func uploadAzureKVCert(ctx context.Context, urlStr string, cert *x509.Certificate, key *rsa.PrivateKey, certPassword string) error {
	kv, err := newAzureKVClient()
	if err != nil {
		return err
	}

	// Parse URL provided by caller
	baseURL, certName, err := parseAzureCertURL(urlStr)
	if err != nil {
		return appendErr("failed to parse certificate URL", err)
	}

	// Check if cert already exists
	exists, err := checkAzureKVCertExists(ctx, baseURL, certName)
	if err != nil {
		return appendErr("failed to check whether the certificate already exists", err)
	}
	if exists {
		return fmt.Errorf("a remote certificate with the name %v already exists, exiting...", certName)
	}

	// Encode certificate to pkcs12
	pfx, err := pkcs12.Encode(rand.Reader, key, cert, nil, certPassword)
	if err != nil {
		return appendErr("failed to encode pkcs12 cert", err)
	}
	base64Encoded := base64.StdEncoding.EncodeToString(pfx)

	// Upload cert
	kv.ImportCertificate(ctx, baseURL, certName, keyvault.CertificateImportParameters{
		Base64EncodedCertificate: &base64Encoded,
		Password:                 &certPassword,
	})

	return nil
}

func checkAzureKVCertExists(ctx context.Context, baseURL, certName string) (bool, error) {
	kv, err := newAzureKVClient()
	if err != nil {
		return false, err
	}

	_, err = kv.GetCertificate(ctx, baseURL, certName, "")
	if err != nil {
		if detailedErr, ok := err.(autorest.DetailedError); ok {
			if detailedErr.StatusCode == 404 {
				return false, nil
			}
		}
		return false, err
	}

	return true, nil
}

func newAzureCLIAuthorizer() (autorest.Authorizer, error) {
	kvResourceURL := "https://vault.azure.net"
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

var errInvalidKVSecretURL = errors.New("invalid key vault secret URL, expected format: https://{baseURL}/secrets/{secretName}(/{version})")
var errInvalidKVCertURL = errors.New("invalid key vault certificate URL, expected format: https://{baseURL}/certificates/{certName}")

func parseAzureSecretURL(urlStr string) (baseURL, secretName, secretVersion string, err error) {
	var url *url.URL
	url, err = url.Parse(urlStr)
	if err != nil {
		return
	}

	var r *regexp.Regexp
	r, err = regexp.Compile("/secrets/([^/]+)/?([^/]+)?")
	if err != nil {
		err = errInvalidKVSecretURL
		return
	}
	matches := r.FindStringSubmatch(url.Path)
	if len(matches) <= 1 || len(matches) > 3 {
		err = errInvalidKVSecretURL
		return
	}

	baseURL = url.Scheme + "://" + url.Host
	secretName = matches[1]
	secretVersion = matches[2]

	return
}

func parseAzureCertURL(urlStr string) (baseURL, certName string, err error) {
	var url *url.URL
	url, err = url.Parse(urlStr)
	if err != nil {
		return
	}

	var r *regexp.Regexp
	r, err = regexp.Compile("/certificates/([^/]+)")
	if err != nil {
		err = errInvalidKVCertURL
		return
	}
	matches := r.FindStringSubmatch(url.Path)
	if len(matches) != 2 {
		err = errInvalidKVCertURL
		return
	}

	baseURL = url.Scheme + "://" + url.Host
	certName = matches[1]

	return
}
