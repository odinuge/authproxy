package cmd

import (
	"crypto/rand"

	"github.com/getwhale/authproxy/pkg"
	"github.com/getwhale/contrib/cli"
	log "github.com/getwhale/contrib/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	cli.StringConfig(RootCmd, "gateUrl", "", "https://gate.whale.io", "Whale gate endpoint.")
	cli.StringConfig(RootCmd, "clientId", "", "", "Auth client id")
	cli.StringConfig(RootCmd, "clientSecret", "", "", "Auth client secret")
	cli.StringConfig(RootCmd, "oidcClientId", "", "", "OIDC client id")
	cli.StringConfig(RootCmd, "oidcClientSecret", "", "", "OIDC client secret")
	cli.StringConfig(RootCmd, "serverURL", "u", "", "The url this service is publicly visible, used for oauth redirects.")
	cli.StringConfig(RootCmd, "cookieName", "n", "whalesession", "The name of the whale session cookie. Should be the same on each instance if you run multiple instances.")
	cli.StringConfig(RootCmd, "cookieSecret", "s", "", "The secret used when generating cookies. Should be the same on each instance if you run multiple instances.")
}

var shortDescription = "Authproxy running inside on-premise clusters."

var RootCmd = &cobra.Command{
	Use:   "authproxy",
	Short: shortDescription,
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {
		var (
			secret           []byte
			gateUrl          = viper.GetString("gateUrl")
			clientId         = viper.GetString("clientId")
			clientSecret     = viper.GetString("clientSecret")
			oidcClientId     = viper.GetString("oidcClientId")
			oidcClientSecret = viper.GetString("oidcClientSecret")
		)

		serverURL := viper.GetString("serverURL")
		cookieName, cookieSecret := viper.GetString("cookieName"), viper.GetString("cookieSecret")

		if serverURL == "" {
			log.Fatal("The serverURL flag is required")
		}

		if cookieSecret == "" {
			log.Warn("No cookie secret provided, generating random secret")
			newSecret := make([]byte, 32)
			rand.Read(newSecret)
			secret = newSecret
		} else {
			secret = []byte(cookieSecret)
		}

		if gateUrl == "" || clientId == "" || clientSecret == "" {
			log.Fatal("gateUrl, clientId and clientSecret is required")
		}

		server := pkg.Server{
			ServerURL:        serverURL,
			CookieName:       cookieName,
			CookieSecret:     secret,
			ListenAddr:       ":8080",
			OIDCIssuer:       gateUrl,
			OIDCClient:       oidcClientId,
			OIDCClientSecret: oidcClientSecret,
			ClientId:         clientId,
			ClientSecret:     clientSecret,
		}

		return server.Run()
	},
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		cli.PrintHeader(shortDescription)
	},
}
