package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/mattn/go-colorable"

	"github.com/dutchcoders/go-virustotal"
)

var VT *virustotal.VirusTotal = nil
var APIKEY = flag.String("key", os.Getenv("VTAPIKEY"), "virustotal api key envvar $VTAPIKEY is used as default")
var MaxDepth = flag.Int("m", 20, "max depth to request")

func init() {
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			"murl:\n\tmapping url\n\nUsage:\n\tmurl [options] target_url\n\n",
		)

		flag.PrintDefaults()
	}
}

func main() {
	flag.Parse()

	if *ModeLoadContent != "" {
		t, err := Load()
		if err != nil {
			log.Fatalln("failed to load stored result", err)
		}

		fmt.Fprintln(colorable.NewColorableStdout(), t)
		os.Exit(0)
	}

	if flag.NArg() != 1 {
		log.Fatalln("please specify target url. see --help.")
	}

	if *ModeSaveContent != "" {
		stat, err := os.Stat(*ModeSaveContent)
		if err == nil && stat.IsDir() == false {
			log.Fatalf("%s exsits. but it isn't directory.\n", *ModeSaveContent)
		}

		if err != nil && os.IsNotExist(err) {
			err := os.MkdirAll(*ModeSaveContent, os.ModePerm)
			if err != nil {
				log.Fatalln("failed to mkdir")
			}
		}
	}

	targetURL := Normalize(flag.Arg(0))

	VT, _ = virustotal.NewVirusTotal(*APIKEY)
	VTS = VirusTotal{apikey: *APIKEY}

	detail, err := GetURLDetails(targetURL, *MaxDepth)
	if err != nil {
		log.Fatalln("err")
	}

	fmt.Fprintln(colorable.NewColorableStdout(), detail)
	if *ModeSaveContent != "" {
		detail.Store()
	}
}
