# certmanager

Just some certificate management things put into a CLI.

## Installation

```bash
go get github.com/sebnyberg/certmanager/cmd/certmanager
```

## Azure Key Vault

### Downloading a certificate and its key

When uploading certificates to Azure Key Vault, a corresponding pkcs12 secret is created (but not viewable in the UI).

You may list these URLs with:

```bash
az keyvault secret list --vault-name sisrisk-prod-kv --output tsv --query '[?contentType == "application/x-pkcs12"].id'
```

To download the certificate, simply run:

```bash
certmanager download --url "https://$YOUR_VAULT.vault.azure.net/secrets/$YOUR_CERT"
```
