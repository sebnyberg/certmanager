# certmanager

Some certificate management things put into a CLI - primarily aimed at managing client / server certificates for mTLS.

## Installation

```bash
go get github.com/sebnyberg/certmanager/cmd/certmanager
```

## Azure Key Vault

### Finding the URL for a cert

When uploading certificates to Azure Key Vault, a corresponding pkcs12 secret is created (but not viewable in the UI).

You may list these URLs with:

```bash
az keyvault secret list --vault-name sisrisk-prod-kv --output tsv --query '[?contentType == "application/x-pkcs12"].id'
```

### Downloading a certificate and its key

To download the certificate and key, simply run:

```bash
certmanager download \
  --url "https://$YOUR_VAULT.vault.azure.net/secrets/$YOUR_CERT"
```

### Creating a new client certificate and key

To create a new client certificate and key signed by the remote CA, use the `gen signed-cert` command.

For client certificates, it does not matter what the Common Name is - the server will only verify that the certificate has been signed the the appropriate certificate authority.

```bash
certmanager gen signed-cert \
  --url "https://$YOUR_VAULT.vault.azure.net/secrets/$YOUR_CERT" \
  --common-name "cli-client"
```

### Creating a new server certificate and key

To create a new server certificate and key signed by the remote CA, use the `gen signed-cert` command.

For server certificates, it is important that the hostname of the server matches either in the common name, or list of Subject Alternative Names (SAN).

For example, if the server is running on `https://my.company.com`, then the common name, or one of the SANs need to match the URL, or the client will refuse the connection.

Example:

```bash
certmanager gen signed-cert \
  --url "https://$YOUR_VAULT.vault.azure.net/secrets/$YOUR_CERT" \
  --common-name "*.my.company.com" \
  --domains "localhost,*.my.alternative.domain.com"
```
