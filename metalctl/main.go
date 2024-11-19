package main

import (
	"fmt"
	"github.com/intunderflow/metal/metalctl/cmd"
	"os"
)

func main() {
	rootCmd := cmd.Cmd()

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
