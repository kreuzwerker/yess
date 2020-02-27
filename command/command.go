package command

import (
	"fmt"
	"os"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const app = "yess"

var this = Version{}

// Execute is the main entry point into the app
func Execute(version, build, time string) {

	this.Build = build
	this.Time = time
	this.Version = version

	if _, err := rootCmd.ExecuteC(); err != nil {

		fmt.Fprintf(os.Stderr, "error: %s\n", err.Error())
		os.Exit(-1)

	}

}

// // flag adds configuration option with default value, long and short flags, a
// // matching environment (if not empty) and matching description
func flag(fs *pflag.FlagSet, def interface{}, long, short, env, desc string) {

	switch t := def.(type) {

	case bool:
		fs.BoolP(long, short, t, desc)
	case uint8:
		fs.Uint8P(long, short, t, desc)
	default:
		panic(fmt.Sprintf("unexpected default value for type %T", def))
	}

	viper.BindPFlag(long, fs.Lookup(long))

	// don't bind to empty env
	if env != "" {
		viper.BindEnv(long, env)
	}

	viper.SetDefault(long, fs.Lookup(long).DefValue)

}
