package cmd

import (
	"github.com/spf13/cobra"
	"fmt"
	"github.com/getwhale/authproxy/pkg"
)

func init() {
	RootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of the authproxy software",
	Long:  "",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Whale AuthProxy version %s", pkg.Version)
	},
}