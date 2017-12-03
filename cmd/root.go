package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	log "github.com/getwhale/contrib/logging"
	"crypto/rand"
	"github.com/getwhale/authproxy/pkg"
)

func init() {
	RootCmd.PersistentFlags().StringP("apiURL", "a", "https://gate.whale.io", "The API server providing authproxy information.")
	RootCmd.PersistentFlags().StringP("token", "t","", "The token used by authproxy to access the API server.")
	RootCmd.PersistentFlags().StringP("cookieName", "n", "whalesession", "The name of the whale session cookie. Should be the same on each instance if you run multiple instances.")
	RootCmd.PersistentFlags().StringP("cookieSecret", "s", "", "The secret used when generating cookies. Should be the same on each instance if you run multiple instances.")
	RootCmd.PersistentFlags().StringP("oidcIssuer", "", "", "OIDC issuer URL.")
	RootCmd.PersistentFlags().StringP("oidcClientID", "", "", "OIDC client ID.")
	viper.BindPFlag("apiURL", RootCmd.PersistentFlags().Lookup("apiURL"))
	viper.BindPFlag("token", RootCmd.PersistentFlags().Lookup("token"))
	viper.BindPFlag("cookieName", RootCmd.PersistentFlags().Lookup("cookieName"))
	viper.BindPFlag("cookieSecret", RootCmd.PersistentFlags().Lookup("cookieSecret"))
	viper.BindPFlag("oidcIssuer", RootCmd.PersistentFlags().Lookup("oidcIssuer"))
	viper.BindPFlag("oidcClientID", RootCmd.PersistentFlags().Lookup("oidcClientID"))
	viper.BindEnv("apiURL", "API_URL")
	viper.BindEnv("token", "TOKEN")
	viper.BindEnv("cookieName", "COOKIE_NAME")
	viper.BindEnv("cookieSecret", "COOKIE_SECRET")
	viper.BindEnv("oidcIssuer", "OIDC_ISSUER")
	viper.BindEnv("oidcClientID", "OIDC_CLIENT_ID")
}

var RootCmd = &cobra.Command{
	Use:   "authproxy",
	Short: "Authproxy running inside on-premise clusters.",
	Long: ``,
	Run: func(cmd *cobra.Command, args []string) {
		var secret []byte

		apiURL, token := viper.GetString("apiURL"), viper.GetString("token")
		cookieName, cookieSecret := viper.GetString("cookieName"), viper.GetString("cookieSecret")
		oidcIssuer, oidcClientID := viper.GetString("oidcIssuer"), viper.GetString("oidcClientID")

		if apiURL == "" {
			log.Fatal("The apiURL flag has to be set")
		}

		if token == "" {
			log.Fatal("The token flag has to be set")
		}

		if cookieSecret == "" {
			log.Warn("No cookie secret provided, generating random secret")
			newSecret := make([]byte, 32)
			rand.Read(newSecret)
			secret = newSecret
		} else {
			secret = []byte(cookieSecret)
		}

		if oidcIssuer == "" || oidcClientID == "" {
			log.Fatal("oidcIssuer and oidcClientID is required")
		}

		server := pkg.Server{
			CookieName: cookieName,
			CookieSecret: secret,
			ListenAddr: ":8080",
			ApiURL: apiURL,
			Token: token,
			OIDCIssuer: oidcIssuer,
			OIDCClient: oidcClientID,
		}

		err := server.Run()
		if err != nil {
			log.Fatal(err, "Internal Server Error")
		}
	},
}
