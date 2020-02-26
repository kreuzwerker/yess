package command

import (
	"log"
	"os"

	"github.com/kreuzwerker/yess/config"
	"github.com/kreuzwerker/yess/share"
	"github.com/kreuzwerker/yess/yubikey"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	conf  config.Config
	debug = log.New(os.Stderr, "[DEBUG] ", log.LstdFlags|log.Lshortfile)
	info  = log.New(os.Stderr, "[INFO] ", log.LstdFlags)
)

var rootCmd = &cobra.Command{
	Short:         "yess provides Yubikey enhanced secret sharing",
	SilenceErrors: true,
	SilenceUsage:  true,
	Use:           app,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {

		if err := viper.Unmarshal(&conf); err != nil {
			return err
		}

		if conf.Verbose {
			share.Debug = debug.Printf
			yubikey.Debug = debug.Printf
		}

		return nil

	},
}

func init() {

	flag(rootCmd.PersistentFlags(),
		false,
		"verbose",
		"v",
		"YESS_VERBOSE",
		"enable verbose logging - NOTE THAT THIS LEAK SECRETS TO STDERR",
	)

}

// out is the message function used inside the split service package
func out(msg string, args ...interface{}) {
	info.Printf(msg, args...)
}
