package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/matchory/crawl-signer/internal/config"
)

func main() {
	path := flag.String("config", "", "path to the JSON config file")
	flag.Parse()
	if _, err := config.Load(*path); err != nil {
		fmt.Fprintln(os.Stderr, "crawl-signer:", err)
		os.Exit(1)
	}
}
