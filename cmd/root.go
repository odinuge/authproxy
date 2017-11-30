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
	RootCmd.PersistentFlags().StringP("cookieSecret", "s", "", "The secret used when generating cookies. Should be the same on each instance if you run multiple instances.")
	viper.BindPFlag("apiURL", RootCmd.PersistentFlags().Lookup("apiURL"))
	viper.BindPFlag("token", RootCmd.PersistentFlags().Lookup("token"))
	viper.BindPFlag("cookieSecret", RootCmd.PersistentFlags().Lookup("cookieSecret"))
	viper.BindEnv("apiURL", "API_URL")
	viper.BindEnv("token", "TOKEN")
	viper.BindEnv("cookieSecret", "COOKIE_SECRET")
}

var RootCmd = &cobra.Command{
	Use:   "authproxy",
	Short: "Authproxy running inside on-premise clusters.",
	Long: ``,
	Run: func(cmd *cobra.Command, args []string) {
		var secret []byte

		apiURL, token := viper.GetString("apiURL"), viper.GetString("token")
		cookieSecret := viper.GetString("cookieSecret")

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

		server := pkg.Server{
			CookieName: "whalesession",
			CookieSecret: secret,
			ListenAddr: ":8080",
			ApiURL: apiURL,
			Token: token,
		}

		err := server.Run()
		if err != nil {
			log.Fatal(err)
		}
	},
}
