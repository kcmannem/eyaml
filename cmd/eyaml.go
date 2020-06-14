package cmd

import (
	"fmt"
	"os"

	"github.com/kcmannem/eyaml/cmd/actions"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "eyaml",
	Short: "Keep secrets hidden in yaml files",
}

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate public-private keypair",
	Run: actions.Keygen,
}

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "encrypt values in a yaml file",
	Args:  cobra.MinimumNArgs(1),
	Run: actions.Encrypt,
}

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "decrypt hidden values in a yaml file touched by eyaml",
	Args:  cobra.MinimumNArgs(1),
	Run:  actions.Decrypt,
}

func init() {
	keygenCmd.Flags().BoolVarP(
		&actions.Write,
		"write",
		"w",
		false,
		"write generated keys to keystore",
	)
	rootCmd.AddCommand(keygenCmd)
	rootCmd.AddCommand(encryptCmd)
	rootCmd.AddCommand(decryptCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
