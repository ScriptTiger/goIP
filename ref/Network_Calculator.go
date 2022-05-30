package main

import (
	"github.com/ScriptTiger/goIP"
	"os"
	"strconv"
)

//Function to display help text and exit
func help(err int) {
	os.Stdout.WriteString(
		"Usage: Network_Calculator <ip address>/<prefix length>\n")
	os.Exit(err)
}

func main() {
	//If no arguments given, display help
	if len(os.Args) == 1 {help(0)}

	ip, err := goIP.NewIP(os.Args[1])
	if err != nil {
		os.Stdout.WriteString("\""+os.Args[1]+"\" cannot be parsed\n")
		help(1)
	}

	os.Stdout.WriteString(
		ip.Ip()+" / "+ip.Mask()+" ("+ip.Rmask()+"):\n"+
		ip.Prefix()+"/"+strconv.Itoa(ip.Prefixlen())+" - "+ip.Limit()+"\n")
}