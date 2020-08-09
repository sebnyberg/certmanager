# certmanager

Some certificate management things put into a CLI - primarily aimed at managing client / server certificates for mTLS using Azure Key Vault.

## Installation

```bash
go get github.com/sebnyberg/certmanager/cmd/certmanager
```

## Example use with Azure Key Vault

### Create a new Azure Key Vault

Let's say we have created a new gRPC service we wish to host with mTLS authentication.

Start by creating a new Azure Key Vault, let's call it "my-keyvault":

```bash
az keyvault create -g myrg -n my-keyvault
```

This vault will be given a FQDN (Base URL) of `https://my-keyvault.vault.azure.net`.

Being the owner (creator) of the vault does not automatically grant necessary access to the vault. Go to the Access policies view in the Azure Portal and add the following permissions:

* Secret: Get, List, Set, Delete
* Certificate: Get, List, Create, Import, Delete

### Generate the custom CA

Generate the CA certificate (we call it `customca`) via the CLI:

```bash
certmanager gen ca-cert \
  --url "https://my-kv.vault.azure.net/certificates/customca" \
  --cert-name "customca"
```

If the command times out, it is likely that you do not have the proper Access Policies in place, or that you mis-spelt the URL.

The CA certificate should show up in the Azure Portal, and also if you list certificate with Azure CLI:

```bash
az keyvault certificate list --vault-name sisrisk-prod-kv --query [].id
```

### Generate the server certificate

The CA-signed server cert and key can now be generated with:

```bash
certmanager gen signed-cert \
  --ca-url "https://my-kv.vault.azure.net/secrets/customca" \
  --common-name "*.my.company.com" \
  --domains "localhost,*.my.alternative.domain.com"
```

This will put the CA cert, server cert and server key in the local directory.

#### Using the server certificate with gRPC

To use the signed certificate, boot up the server with TLS credentials where the CA certificate is added to the list of root CAs (this is important!). For mTLS, it is also important that the server verifies the client certificate, or the server will be publicly available even for clients that do not have a properly signed certificate.

### Generate a client certificate

To connect to the gRPC service, the client needs to provide the CA cert and a valid cert / key that has been signed by the CA. Generate a client certificate and key with:

```bash
certmanager gen signed-cert \
  --ca-url "https://my-kv.vault.azure.net/secrets/customca" \
  --common-name "cli-client"
```

This will put the CA cert, client cert and client key in the local directory.

To test your service, you can run grpcurl (example running on `localhost:443` with schema introspection):

```bash
grpcurl \
  --cacert customca.crt \
  --cert cli-client.crt \
  --key cli-client.key \
  localhost:443 list
```

## FAQ

### How do I find the URL for a cert?

When uploading certificates to Azure Key Vault, a corresponding pkcs12 secret is created (but not viewable in the UI).

You may list these URLs with:

```bash
az keyvault secret list \
  --vault-name sisrisk-prod-kv \
  --output tsv \
  --query '[?contentType == "application/x-pkcs12"].id'
```