module github.com/sebnyberg/certmanager

go 1.14

require (
	github.com/Azure/azure-sdk-for-go v58.0.0+incompatible
	github.com/Azure/go-autorest/autorest v0.11.21
	github.com/Azure/go-autorest/autorest/adal v0.9.16 // indirect
	github.com/Azure/go-autorest/autorest/azure/auth v0.5.8
	github.com/Azure/go-autorest/autorest/azure/cli v0.4.3
	github.com/Azure/go-autorest/autorest/to v0.4.0 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.3.1 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/go-cmp v0.5.6
	github.com/sebnyberg/flagtags v0.0.0-20210812191134-9825f4cda663
	github.com/square/certstrap v1.2.0
	github.com/urfave/cli/v2 v2.3.0
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519 // indirect
	software.sslmate.com/src/go-pkcs12 v0.0.0-20210415151418-c5206de65a78
)

retract (
	v1.0.2
	v1.0.1
	v1.0.0
)
