package main

import (
	"fmt"
	"log"
	"os"

	"github.com/sebnyberg/certmanager/cmd/certmanager/certcli"
	"github.com/urfave/cli/v2"
)

const version = "v1.0.3"

func main() {
	app := &cli.App{
		Name:        "certmanager",
		HelpName:    "certmanager",
		Description: "certmanager contains some useful commands for working with certs",
		Usage:       "management of TLS certificates",
		Version:     version,
		Commands: []*cli.Command{
			certcli.NewCmdDownload(),
			certcli.NewCmdGen(),
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
