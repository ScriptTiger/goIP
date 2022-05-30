package main

import (
	"github.com/ScriptTiger/abc"
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"bufio"
)

func extract(iFile, data string) (error) {

	// Establish full path of archive
	iFile = filepath.Join(data, filepath.Base(iFile))

	// Open archive
	archive, err := zip.OpenReader(iFile)
	if err != nil {return err}

	// Extract files from archive
	for _, pFile := range archive.File {

		fPath := filepath.Join(data, filepath.Base(pFile.Name))

		err = os.MkdirAll(filepath.Dir(fPath), os.ModePerm)
		if err != nil {return err}

		oFile, err := os.OpenFile(fPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, pFile.Mode())
		if err != nil {return err}

		uFile, err := pFile.Open()
		if err != nil {return err}

		_, err = io.Copy(oFile, uFile)

		oFile.Close()
		uFile.Close()

	        if err != nil {return err}
	}

	// Close archive
	archive.Close()

	// Delete archive
	err = os.Remove(iFile)
	if err != nil {return err}

	return nil
}

func main() {

	// Determine paths
	dir, err := os.Executable()
	if err != nil {panic(err)}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {panic(err)}
	dir = filepath.Dir(dir)
	data := filepath.Join(dir, "Data")

	// Initialize license from file
	os.Stdout.WriteString("Reading license...\n")
	MMLpath := filepath.Join(dir, "license.key")
	MMLFile, err := os.ReadFile(MMLpath)
	var MML string

	// If license cannot be read from file, prompt for input from user
	if err != nil {
		consoleReader := bufio.NewScanner(os.Stdin)
		os.Stdout.WriteString("There was a problem reading your license\nPlease input your license below to continue\n")
		consoleReader.Scan()
		if consoleReader.Text() == "" {os.Exit(0)}
		MML = consoleReader.Text()
		os.WriteFile(MMLpath, []byte(MML), 644)		
	} else {MML = string(MMLFile)}

	// Initialize download list
	downloads := [10]string{
		"https://download.maxmind.com/app/geoip_download?suffix=zip&license_key="+MML+"&edition_id=GeoLite2-City-CSV", "GeoLite2-City.zip",
		"https://download.maxmind.com/app/geoip_download?suffix=zip&license_key="+MML+"&edition_id=GeoLite2-ASN-CSV", "GeoLite2-ASN.zip",
		"https://check.torproject.org/exit-addresses", "exit-addresses",
		"http://reputation.alienvault.com/reputation.data", "reputation.data",
		"https://www.snort.org/downloads/ip-block-list", "ip-block-list",
	}

	// Download files from download list
	os.Stdout.WriteString("Downloading data files...\n")
	flags := uint8(7)
	for i := 0; i < 10; i += 2 {
		fPath := filepath.Join(data, downloads[i+1])
		abc.Download(&downloads[i], &fPath, nil, nil, nil, nil, &flags)
	}

	// Initialize list of archives to extract
	archives := [2]string{
		"GeoLite2-City.zip",
		"GeoLite2-ASN.zip",
	}

	// Extract archives from list
	os.Stdout.WriteString("Unpacking archives...\n")
	for _, archive := range archives {
		err = extract(archive, data)
		if err != nil {panic(err)}
	}
}