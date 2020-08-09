package main

import (
	"fmt"
	"log"
	"os"

	"github.com/sebnyberg/certmanager/cmd/certmanager/certcli"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:        "certmanager",
		HelpName:    "certmanager",
		Description: "certmanager contains some useful commands for working with certs",
		Usage:       "management of TLS certificates",
		Commands: []*cli.Command{
			certcli.NewCmdDownload(),
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
