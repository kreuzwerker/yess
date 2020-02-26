package command

import (
	"io/ioutil"
	"os"

	"github.com/kreuzwerker/yess/split"
	"github.com/spf13/cobra"
)

var splitCmd = &cobra.Command{

	Use:   "split",
	Short: "Split and encrypt a secret using Yubikeys",
	RunE: func(cmd *cobra.Command, args []string) error {

		in, err := ioutil.ReadAll(os.Stdin)

		if err != nil {
			return err
		}

		result, err := split.New(out).Split(in, int(conf.Parts), int(conf.Threshold))

		if err != nil {
			return err
		}

		return result.Save(os.Stdout)

	},
}

func init() {

	flag(splitCmd.Flags(),
		uint8(3),
		"parts",
		"p",
		"YESS_PARTS",
		"specifies the number of shares generated",
	)

	flag(splitCmd.Flags(),
		uint8(2),
		"threshold",
		"t",
		"YESS_THRESHOLD",
		"specifies number of shares required for reconstruction",
	)

	rootCmd.AddCommand(splitCmd)

}
