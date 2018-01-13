package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/mattn/go-colorable"

	"github.com/bradfitz/iter"
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

	if flag.NArg() != 1 {
		log.Fatalln("please specify target url. see --help.")
	}

	VT, _ = virustotal.NewVirusTotal(*APIKEY)
	VTS = VirusTotal{apikey: *APIKEY}

	detail, err := GetURLDetails(flag.Arg(0), *MaxDepth)
	if err != nil {
		log.Fatalln("err")
	}

	for idx, item := range detail {

		for range iter.N(idx) {
			fmt.Print("  ")
		}

		fmt.Fprintln(colorable.NewColorableStdout(), item)
	}
}
