package main

import (
	"github.com/kcmannem/eyaml"
	"gopkg.in/ukautz/clif.v1"
)

func main() {
	cli := clif.New("eyaml", "0.0.1", "Secrets made easy.")

	cli.Add(
		clif.NewCommand(
			"keygen",
			"generate public-private keypair",
			keygenCmd,
		).NewOption(
			"write",
			"w",
			"writes keypair to a store",
			"",
			false,
			false,
		),
	)

	cli.Add(
		clif.NewCommand(
			"encrypt",
			"encrypt values in a yaml doc",
			encryptCmd,
		).NewArgument(
			"file",
			"yaml file to encrypt",
			"",
			true,
			false,
		),
	)

	cli.Add(
		clif.NewCommand(
			"decrypt",
			"decrypt values from an eyaml doc",
			decryptCmd,
		).NewArgument(
			"file",
			"yaml file to encrypt",
			"",
			true,
			false,
		).NewOption(
			"path",
			"p",
			"specify a path to decrypt",
			"",
			false,
			false,
		),
	)

	cli.Run()
}

func keygenCmd(c *clif.Command) {
	eyaml.Keygen(c.Option("write").Bool())
}

func encryptCmd(c *clif.Command) {
	eyaml.Encrypt(c.Argument("file").String())
}

func decryptCmd(c *clif.Command) {
	eyaml.Decrypt(c.Argument("file").String(), c.Option("path").String())
}
