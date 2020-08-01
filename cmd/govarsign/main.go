package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/foxboron/goefi/efi"
	"github.com/foxboron/goefi/efi/util"
)

func main() {
	key := flag.String("key", "", "Key")
	cert := flag.String("cert", "", "Certificate")
	variable := flag.String("var", "", "variable")
	flag.Parse()
	args := flag.Args()
	if len(os.Args) == 1 {
		fmt.Println("govarsign: -key <key> -cert <cert> -var <variable> [input] [output]")
	}
	if len(os.Args) == 2 {
		fmt.Println("Missing input and output file")
		os.Exit(1)
	}
	b, err := ioutil.ReadFile(args[0])
	if err != nil {
		log.Fatal(err)
	}

	buf := efi.SignEFIVariable(util.ReadKey(*key), util.ReadCert(*cert), *variable, b)

	err = ioutil.WriteFile(args[1], buf, 0644)
	if err != nil {
		log.Fatal(err)
	}
}
