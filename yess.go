package main

import (
	"github.com/kreuzwerker/yess/command"
)

var (
	build   string
	time    string
	version string
)

func main() {
	command.Execute(version, build, time)
}
