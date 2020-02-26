package command

import (
	"os"

	"github.com/kreuzwerker/yess/result"
	"github.com/kreuzwerker/yess/split"
	"github.com/spf13/cobra"
)

var combineCmd = &cobra.Command{

	Use:   "combine",
	Short: "Combined and decrypt a secret using Yubikeys",
	RunE: func(cmd *cobra.Command, args []string) error {

		result, err := result.Load(os.Stdin)

		if err != nil {
			return err
		}

		secret, err := split.New(out).Combine(result)

		if err != nil {
			return err
		}

		_, err = os.Stderr.Write(secret)

		return err

	},
}

func init() {
	rootCmd.AddCommand(combineCmd)
}
