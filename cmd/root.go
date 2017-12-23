package cmd

import (
	"crypto/rand"
	"github.com/getwhale/authproxy/pkg"
	log "github.com/getwhale/contrib/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	RootCmd.PersistentFlags().StringP("cookieName", "n", "whalesession", "The name of the whale session cookie. Should be the same on each instance if you run multiple instances.")
	RootCmd.PersistentFlags().StringP("cookieSecret", "s", "", "The secret used when generating cookies. Should be the same on each instance if you run multiple instances.")
	RootCmd.PersistentFlags().StringP("oidcIssuer", "", "https://gate.whale.io", "OIDC issuer URL.")
	RootCmd.PersistentFlags().StringP("oidcClientID", "", "", "OIDC client ID.")
	RootCmd.PersistentFlags().StringP("oidcClientSecret", "", "", "OIDC client secret.")
	RootCmd.PersistentFlags().BoolP("whalePermissions", "", true, "Check permissions against Whale, the oidcIssuer has to be Whale for this feature to work.")
	viper.BindPFlag("cookieName", RootCmd.PersistentFlags().Lookup("cookieName"))
	viper.BindPFlag("cookieSecret", RootCmd.PersistentFlags().Lookup("cookieSecret"))
	viper.BindPFlag("oidcIssuer", RootCmd.PersistentFlags().Lookup("oidcIssuer"))
	viper.BindPFlag("oidcClientID", RootCmd.PersistentFlags().Lookup("oidcClientID"))
	viper.BindPFlag("oidcClientSecret", RootCmd.PersistentFlags().Lookup("oidcClientSecret"))
	viper.BindPFlag("whalePermissions", RootCmd.PersistentFlags().Lookup("whalePermissions"))
	viper.BindEnv("cookieName", "COOKIE_NAME")
	viper.BindEnv("cookieSecret", "COOKIE_SECRET")
	viper.BindEnv("oidcIssuer", "OIDC_ISSUER")
	viper.BindEnv("oidcClientID", "OIDC_CLIENT_ID")
	viper.BindEnv("oidcClientSecret", "OIDC_CLIENT_SECRET")
	viper.BindEnv("whalePermissions", "WHALE_PERMISSIONS")
}

var RootCmd = &cobra.Command{
	Use:   "authproxy",
	Short: "Authproxy running inside on-premise clusters.",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		var secret []byte

		cookieName, cookieSecret := viper.GetString("cookieName"), viper.GetString("cookieSecret")
		oidcIssuer, oidcClientID, oidcClientSecret := viper.GetString("oidcIssuer"), viper.GetString("oidcClientID"), viper.GetString("oidcClientSecret")
		whalePermissions := viper.GetBool("whalePermissions")

		if cookieSecret == "" {
			log.Warn("No cookie secret provided, generating random secret")
			newSecret := make([]byte, 32)
			rand.Read(newSecret)
			secret = newSecret
		} else {
			secret = []byte(cookieSecret)
		}

		if oidcIssuer == "" || oidcClientID == "" || oidcClientSecret == "" {
			log.Fatal("oidcIssuer, oidcClientID and oidcClientSecret is required")
		}

		server := pkg.Server{
			CookieName:       cookieName,
			CookieSecret:     secret,
			ListenAddr:       ":8080",
			OIDCIssuer:       oidcIssuer,
			OIDCClient:       oidcClientID,
			OIDCClientSecret: oidcClientSecret,
			WhalePermissions: whalePermissions,
		}

		err := server.Run()
		if err != nil {
			log.Fatal(err, "Internal Server Error")
		}
	},
}
