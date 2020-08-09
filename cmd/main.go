package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"time"

	"github.com/sebnyberg/certmanager"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	key, _, err := certmanager.GetCert(ctx, testurl)
	if err != nil {
		log.Fatal(err)
	}
	b := x509.MarshalPKCS1PrivateKey(key)
	fmt.Println(string(b))
}
