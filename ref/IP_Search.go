package main

// Imports
import (
	"github.com/ScriptTiger/goIP"
	"os"
	"path/filepath"
	"strconv"
	"encoding/csv"
	"strings"
	"errors"
	"io"
	"hash/fnv"
	"bufio"
	"net/http"
	"encoding/json"
	"encoding/binary"
	"bytes"
	"runtime"
)

// Memory structures

// Struct to store IPv6 prefix information
type prefixv6info struct {

	prefix uint64
	length uint8
	offset uint32

}

// Struct to store IPv4 prefix information
type prefixv4info struct {

	prefix uint32
	length uint8
	offset uint32

}

// Struct to store location index information
type clindexinfo struct {

	geo uint32
	offset uint32

}

// Struct to store dataset information for lookups
type datasetinfo struct {

	records []byte
	buffer *bytes.Buffer
	cb4p []prefixv4info
	ab4p []prefixv4info
	cb6p []prefixv6info
	ab6p []prefixv6info
	clIndex []clindexinfo
	tor string
	snort string
	av string

}

// Struct to store query information
type querysetinfo struct {

	query *goIP.Ipinfo
	ipv6Prefixes []uint64
	ipv4Prefixes []uint32
	cbentry int
	cboffset int
	abentry int
	aboffset int
	clentry int
	cloffset int
	bools uint8

}

// REST API handler
type restHandler struct {

	fileOut *string
	writer *csv.Writer

}

// JSON structures

type jsonWan struct {

	Network string `json:"network"`
	Geoname_id uint32 `json:"geoname_id"`
	Registered_country_geoname_id uint32 `json:"registered_country_geoname_id"`
	Represented_country_geoname_id uint32 `json:"represented_country_geoname_id"`
	Is_anonymous_proxy uint8 `json:"is_anonymous_proxy"`
	Is_satellite_provider uint8 `json:"is_satellite_provider"`
	Postal_code string `json:"postal_code"`
	Latitude float32 `json:"latitude"`
	Longitude float32 `json:"longitude"`
	Accuracy_radius uint16 `json:"accuracy_radius"`

}

type jsonAsn struct {

	Network string `json:"network"`
	Autonomous_system_number uint32 `json:"autonomous_system_number"`
	Autonomous_system_organization string `json:"autonomous_system_organization"`

}

type jsonLocation struct {

	Geoname_id uint32 `json:"geoname_id"`
	Locale_code string `json:"locale_code"`
	Continent_code string `json:"continent_code"`
	Continent_name string `json:"continent_name"`
	Country_iso_code string `json:"country_iso_code"`
	Country_name string `json:"country_name"`
	Subdivision_1_iso_code string `json:"subdivision_1_iso_code"`
	Subdivision_1_name string `json:"subdivision_1_name"`
	Subdivision_2_iso_code string `json:"subdivision_2_iso_code"`
	Subdivision_2_name string `json:"subdivision_2_name"`
	City_name string `json:"city_name"`
	Metro_code string `json:"metro_code"`
	Time_zone string `json:"time_zone"`
	Is_in_european_union uint8 `json:"is_in_european_union"`

}

type jsonOther struct {

	Is_tor_node uint8 `json:"is_tor_node"`
	Is_blocked uint8 `json:"is_blocked"`
	Is_malicious uint8 `json:"is_malicious"`

}

type jsonRoot struct {

	Ip string `json:"ip"`
	Wan jsonWan `json:"wan"`
	Asn jsonAsn `json:"asn"`
	Location jsonLocation `json:"location"`
	Other jsonOther `json:"other"`

}

// Global variables

var dataset datasetinfo

// Functions

// REST API responder function
func (handler *restHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) () {

	query := request.URL.Query().Get("ip")
	if query == "" {return}
	dataEntry := queryData(query)
	if dataEntry.cbentry == -1 || dataEntry.clentry == -1 {return}
	var dataEntryString string
	writeData(dataEntry, handler.fileOut, handler.writer, &dataEntryString)
	response.Write([]byte(dataEntryString))

}

// REST API handler creation function
func newRestHandler(fileOut *string, writer *csv.Writer) (*restHandler) {

	var newHandler restHandler
	newHandler = restHandler{fileOut: fileOut, writer: writer}
	return &newHandler

}

// Iterate over each network entry, checking if prefix is a match
func findPrefix(queryset querysetinfo) (querysetinfo) {

	if queryset.query.Isv6() {

		if dataset.cb6p == nil || dataset.ab6p == nil {
			err := errors.New("Trying to look up IPv6 address when IPv6 data set not loaded")
			debug(err)
		}
		for i := 0; i < len(dataset.cb6p); i++ {
			if queryset.ipv6Prefixes[dataset.cb6p[i].length] == dataset.cb6p[i].prefix {
				queryset.cbentry = i
				queryset.cboffset = int(dataset.cb6p[i].offset)

				break
			}
		}
		for i := 0; i < len(dataset.ab6p); i++ {
			if queryset.ipv6Prefixes[dataset.ab6p[i].length] == dataset.ab6p[i].prefix {
				queryset.abentry = i
				queryset.aboffset = int(dataset.ab6p[i].offset)
				break
			}
		}

	} else {

		if dataset.cb4p == nil || dataset.ab4p == nil {
			err := errors.New("Trying to look up IPv4 address when IPv4 data set not loaded")
			debug(err)
		}
		for i := 0; i < len(dataset.cb4p); i++ {
			if queryset.ipv4Prefixes[dataset.cb4p[i].length] == dataset.cb4p[i].prefix {
				queryset.cbentry = i
				queryset.cboffset = int(dataset.cb4p[i].offset)
				break
			}
		}
		for i := 0; i < len(dataset.ab4p); i++ {
			if queryset.ipv4Prefixes[dataset.ab4p[i].length] == dataset.ab4p[i].prefix {
				queryset.abentry = i
				queryset.aboffset = int(dataset.ab4p[i].offset)
				break
			}
		}
	}

	return queryset

}

// Generate precomputed list of all possible prefixes for a query
func genPrefixes(queryset querysetinfo) (querysetinfo) {

	var bits int
	if queryset.query.Isv6() {
		bits = 64
		queryset.ipv6Prefixes = make([]uint64, bits+1)
	} else {
		bits = 32
		queryset.ipv4Prefixes = make([]uint32, bits+1)
	}
	for i := 0; i <= bits; i++ {
		query, err := goIP.NewIP(queryset.query.Ip()+"/"+strconv.Itoa(i))
		if err != nil {debug(err)}
		if queryset.query.Isv6() {
			_, queryset.ipv6Prefixes[i] = query.Prefixint()
		} else {
			tmpUint64, _ := query.Prefixint()
			queryset.ipv4Prefixes[i] = uint32(tmpUint64)
		}
	}
	return queryset

}

// Parse city blocks CSV files
func readCity(filename string, isv6 bool) () {

	rawData, reader, lines := openCSV(filename)
	defer rawData.Close()

	// Initialize slices
	if isv6 {
		dataset.cb6p = make([]prefixv6info, lines)
	} else {
		dataset.cb4p = make([]prefixv4info, lines)
	}

	// Read data into slices
	for i := 0; i < lines; i++ {
		tokens, err := reader.Read()
		if err != nil {debug(err)}

		// Parse data

		goPrefix, err := goIP.NewIP(tokens[0])
		if err != nil {debug(err)}

		geo, err := strconv.Atoi("0"+tokens[1])
		if err != nil {debug(err)}

		reg, err := strconv.Atoi("0"+tokens[2])
		if err != nil {debug(err)}

		rep, err := strconv.Atoi("0"+tokens[3])
		if err != nil {debug(err)}

		bools, err := strconv.Atoi("0"+tokens[4])
		if err != nil {debug(err)}

		tmpBool, err := strconv.Atoi("0"+tokens[5])
		if err != nil {debug(err)}
		bools |= tmpBool<<1

		var lat float64
		if tokens[7] != "" {
			lat, err = strconv.ParseFloat(tokens[7], 10)
			if err != nil {debug(err)}
		}

		var long float64
		if tokens[8] != "" {
			long, err = strconv.ParseFloat(tokens[8], 10)
			if err != nil {debug(err)}
		}

		acc, err := strconv.Atoi("0"+tokens[9])
		if err != nil {debug(err)}

		// Push index data into global dataset
		if isv6 {
			_, dataset.cb6p[i].prefix = goPrefix.Ipint()
			dataset.cb6p[i].length = uint8(goPrefix.Prefixlen())
			dataset.cb6p[i].offset = uint32(dataset.buffer.Len())
		} else {
			tmpUint64, _ := goPrefix.Ipint()
			dataset.cb4p[i].prefix = uint32(tmpUint64)
			dataset.cb4p[i].length = uint8(goPrefix.Prefixlen())
			dataset.cb4p[i].offset = uint32(dataset.buffer.Len())
		}

		// Buffer record data
		binary.Write(dataset.buffer, binary.LittleEndian, uint32(geo))
		binary.Write(dataset.buffer, binary.LittleEndian, uint32(reg))
		binary.Write(dataset.buffer, binary.LittleEndian, uint32(rep))
		dataset.buffer.WriteByte(uint8(bools))
		dataset.buffer.WriteByte(uint8(len(tokens[6])))
		dataset.buffer.WriteString(tokens[6])
		binary.Write(dataset.buffer, binary.LittleEndian, float32(lat))
		binary.Write(dataset.buffer, binary.LittleEndian, float32(long))
		binary.Write(dataset.buffer, binary.LittleEndian, uint16(acc))

	}

}

// Parse ASN blocks CSV files
func readASN(filename string, isv6 bool) () {

	rawData, reader, lines := openCSV(filename)
	defer rawData.Close()

	// Initialize slices
	if isv6 {
		dataset.ab6p = make([]prefixv6info, lines)
	} else {
		dataset.ab4p = make([]prefixv4info, lines)
	}

	// Read data into slices
	for i := 0; i < lines; i++ {
		tokens, err := reader.Read()
		if err != nil {debug(err)}

		// Parse data

		goPrefix, err := goIP.NewIP(tokens[0])
		if err != nil {debug(err)}

		asn, err := strconv.Atoi("0"+tokens[1])
		if err != nil {debug(err)}

		// Push index data into global dataset
		if isv6 {
			_, dataset.ab6p[i].prefix = goPrefix.Ipint()
			dataset.ab6p[i].length = uint8(goPrefix.Prefixlen())
			dataset.ab6p[i].offset = uint32(dataset.buffer.Len())
		} else {
			tmpUint64, _ := goPrefix.Ipint()
			dataset.ab4p[i].prefix = uint32(tmpUint64)
			dataset.ab4p[i].length = uint8(goPrefix.Prefixlen())
			dataset.ab4p[i].offset = uint32(dataset.buffer.Len())
		}

		// Buffer record data
		binary.Write(dataset.buffer, binary.LittleEndian, uint32(asn))
		dataset.buffer.WriteByte(uint8(len(tokens[2])))
		dataset.buffer.WriteString(tokens[2])

	}

}

// Parse city locations CSV
func readLocations(filename string) () {

	rawData, reader, lines := openCSV(filename)
	defer rawData.Close()

	// Initialize slices
	dataset.clIndex = make([]clindexinfo, lines)

	// Read data into slices
	for i := 0; i < lines; i++ {
		tokens, err := reader.Read()
		if err != nil {debug(err)}

		// Push index data into global dataset
		tmpInt, err := strconv.Atoi("0"+tokens[0])
		if err != nil {debug(err)}
		dataset.clIndex[i].geo = uint32(tmpInt)
		dataset.clIndex[i].offset = uint32(dataset.buffer.Len())

		// Buffer record data
		dataset.buffer.WriteByte(uint8(len(tokens[1])))
		dataset.buffer.WriteString(tokens[1])

		dataset.buffer.WriteByte(uint8(len(tokens[2])))
		dataset.buffer.WriteString(tokens[2])

		dataset.buffer.WriteByte(uint8(len(tokens[3])))
		dataset.buffer.WriteString(tokens[3])

		dataset.buffer.WriteByte(uint8(len(tokens[4])))
		dataset.buffer.WriteString(tokens[4])

		dataset.buffer.WriteByte(uint8(len(tokens[5])))
		dataset.buffer.WriteString(tokens[5])

		dataset.buffer.WriteByte(uint8(len(tokens[6])))
		dataset.buffer.WriteString(tokens[6])

		dataset.buffer.WriteByte(uint8(len(tokens[7])))
		dataset.buffer.WriteString(tokens[7])

		dataset.buffer.WriteByte(uint8(len(tokens[8])))
		dataset.buffer.WriteString(tokens[8])

		dataset.buffer.WriteByte(uint8(len(tokens[9])))
		dataset.buffer.WriteString(tokens[9])

		dataset.buffer.WriteByte(uint8(len(tokens[10])))
		dataset.buffer.WriteString(tokens[10])

		dataset.buffer.WriteByte(uint8(len(tokens[11])))
		dataset.buffer.WriteString(tokens[11])

		dataset.buffer.WriteByte(uint8(len(tokens[12])))
		dataset.buffer.WriteString(tokens[12])

		tmpInt, err = strconv.Atoi("0"+tokens[13])
		if err != nil {debug(err)}
		dataset.buffer.WriteByte(uint8(tmpInt<<2))
	}

}

// Open CSV, create new reader, count lines, and position reader on second line
func openCSV(filename string) (rawData *os.File, reader *csv.Reader, lines int) {

	rawData, err := os.Open(filename)
	if err != nil {debug(err)}
	reader = csv.NewReader(rawData)

	// Get line count to initialize slice more efficiently
	// Skip header line
	reader.Read()
	for {
		_, err := reader.Read()
		if err == io.EOF {break}
		if err != nil {debug(err)}

		lines++
	}

	// Reset file pointer to beginning of file
	rawData.Seek(0, 0)
	reader = csv.NewReader(rawData)

	// Skip header line
	reader.Read()

	return

}


// Slurp arbitrary text files
func readFile(filename string) ([]string) {

	dataBytes, err := os.ReadFile(filename)
	if err != nil {debug(err)}
	return strings.Split(strings.Replace(string(dataBytes), "\r", "", -1), "\n")

}

// Match GeoNames ID from network record to language entry
func findGeo(cboffset int64) (int, int) {

	var geo uint32
	reader := bytes.NewReader(dataset.records)
	reader.Seek(cboffset, 0)
	binary.Read(reader, binary.LittleEndian, &geo)
	for i := 0; i < len(dataset.clIndex); i++ {
		if geo == dataset.clIndex[i].geo {
			return i, int(dataset.clIndex[i].offset)
		}
	}
	return -1, -1

}

// Display help
func help(err int) {
	os.Stdout.WriteString(
		"Usage: IP_Search [options...]\n"+
		" -i <file>            File with one IP per line to resolve\n"+
		" -o <file>            File to write results to in CSV format\n"+
		" -language <iso>      Language of output data\n"+
		" -rest <address:port> Start REST API on given socket\n"+
		" -ipv4                Only load IPv4 data\n"+
		" -ipv6                Only load IPv6 data\n")
	os.Exit(err)
}

// Handle errors
func debug(err error) {
	fnv1a := fnv.New32a()
	fnv1a.Write([]byte(err.Error()))
	errCode := int(fnv1a.Sum32())
	os.Stdout.WriteString("\n"+strconv.Itoa(errCode)+": "+err.Error()+"\n")
	os.Exit(errCode)
}

// Query Data
func queryData(query string) (querysetinfo) {

	var (
		queryset querysetinfo
		err error
	)
	queryset.query, err = goIP.NewIP(query)
	if err != nil {
		os.Stdout.WriteString("IP address "+query+" cannot be parsed\n")
		return querysetinfo{cbentry: -1, abentry: -1}
	}

	queryset = genPrefixes(queryset)

	// Look up city and ASN block records for query, initialize to -1
	queryset.cbentry = -1
	queryset.abentry = -1
	queryset = findPrefix(queryset)

	// Check if city block record found
	if queryset.cbentry == -1 {
		os.Stdout.WriteString("WAN not found for "+query+"\n")
		return queryset
	}

	// Check if ASN record found
	if queryset.abentry == -1 {
		os.Stdout.WriteString("ASN not found for "+query+"\n")
	}

	// Look up GeonNames ID record for query
	queryset.clentry, queryset.cloffset = findGeo(int64(queryset.cboffset))

	// Check if GeoNames record found
	if queryset.clentry == -1 {
		os.Stdout.WriteString("GeoNames ID not found for "+query+"\n")
		return queryset
	}

	// Check if query is present in Tor, Snort, or AV list
	if strings.Contains(dataset.tor, "\nExitAddress "+query+" ") {queryset.bools |= 8}
	if strings.Contains(dataset.snort, "\n"+query+"\n") {queryset.bools |= 16}
	if strings.Contains(dataset.av, "\n"+query+"#") {queryset.bools |= 32}

	return queryset

}

// Format data returned from a query and write to appropriate stream
func writeData(queryset querysetinfo, fileOut *string, writer *csv.Writer, dataEntryString *string) () {

	// Generate array of output strings
	var(
		dataEntry [31]string
		reader *bytes.Reader
		lp uint8
		strBuffer []byte
		geo uint32
		reg uint32
		rep uint32
		lat float32
		long float32
		acc uint16
		asn uint32
		bools uint8
		tmpBool uint8
	)

	dataEntry[0] = queryset.query.Ip()
	if queryset.query.Isv6() {

		dataEntry[1] = goIP.Iptostr(0, dataset.cb6p[queryset.cbentry].prefix, true)+"/"+strconv.Itoa(int(dataset.cb6p[queryset.cbentry].length))

		if queryset.abentry != -1 {
			dataEntry[11] =  goIP.Iptostr(0, dataset.ab6p[queryset.abentry].prefix, true)+"/"+strconv.Itoa(int(dataset.ab6p[queryset.abentry].length))
		}

	} else {

		dataEntry[1] = goIP.Iptostr(uint64(dataset.cb4p[queryset.cbentry].prefix), 0, false)+"/"+strconv.Itoa(int(dataset.cb4p[queryset.cbentry].length))

		if queryset.abentry != -1 {
			dataEntry[11] = goIP.Iptostr(uint64(dataset.ab4p[queryset.abentry].prefix), 0, false)+"/"+strconv.Itoa(int(dataset.ab4p[queryset.abentry].length))
		}

	}

	reader = bytes.NewReader(dataset.records)
	reader.Seek(int64(queryset.cboffset), 0)

	binary.Read(reader, binary.LittleEndian, &geo)
	dataEntry[2] = strconv.Itoa(int(geo))

	binary.Read(reader, binary.LittleEndian, &reg)
	dataEntry[3] = strconv.Itoa(int(reg))

	binary.Read(reader, binary.LittleEndian, &rep)
	dataEntry[4] = strconv.Itoa(int(rep))

	binary.Read(reader, binary.LittleEndian, &bools)
	dataEntry[5] = strconv.Itoa(int(bools&1))

	dataEntry[6] = strconv.Itoa(int((bools>>1)&1))

	binary.Read(reader, binary.LittleEndian, &lp)
	strBuffer = make([]byte, lp)
	binary.Read(reader, binary.LittleEndian, &strBuffer)
	dataEntry[7] = string(strBuffer)

	binary.Read(reader, binary.LittleEndian, &lat)
	dataEntry[8] = strconv.FormatFloat(float64(lat), 'f', 4, 32)

	binary.Read(reader, binary.LittleEndian, &long)
	dataEntry[9] = strconv.FormatFloat(float64(long), 'f', 4, 32)

	binary.Read(reader, binary.LittleEndian, &acc)
	dataEntry[10] = strconv.Itoa(int(acc))

	if queryset.abentry != -1 {
		reader.Seek(int64(queryset.aboffset), 0)
		binary.Read(reader, binary.LittleEndian, &asn)
		dataEntry[12] = strconv.Itoa(int(asn))
		binary.Read(reader, binary.LittleEndian, &lp)
		strBuffer = make([]byte, lp)
		binary.Read(reader, binary.LittleEndian, &strBuffer)
		dataEntry[13] = string(strBuffer)
	}

	reader.Seek(int64(queryset.cloffset), 0)

	dataEntry[14] = dataEntry[2]

	binary.Read(reader, binary.LittleEndian, &lp)
	strBuffer = make([]byte, lp)
	binary.Read(reader, binary.LittleEndian, &strBuffer)
	dataEntry[15] = string(strBuffer)

	binary.Read(reader, binary.LittleEndian, &lp)
	strBuffer = make([]byte, lp)
	binary.Read(reader, binary.LittleEndian, &strBuffer)
	dataEntry[16] = string(strBuffer)

	binary.Read(reader, binary.LittleEndian, &lp)
	strBuffer = make([]byte, lp)
	binary.Read(reader, binary.LittleEndian, &strBuffer)
	dataEntry[17] = string(strBuffer)

	binary.Read(reader, binary.LittleEndian, &lp)
	strBuffer = make([]byte, lp)
	binary.Read(reader, binary.LittleEndian, &strBuffer)
	dataEntry[18] = string(strBuffer)

	binary.Read(reader, binary.LittleEndian, &lp)
	strBuffer = make([]byte, lp)
	binary.Read(reader, binary.LittleEndian, &strBuffer)
	dataEntry[19] = string(strBuffer)

	binary.Read(reader, binary.LittleEndian, &lp)
	strBuffer = make([]byte, lp)
	binary.Read(reader, binary.LittleEndian, &strBuffer)
	dataEntry[20] = string(strBuffer)

	binary.Read(reader, binary.LittleEndian, &lp)
	strBuffer = make([]byte, lp)
	binary.Read(reader, binary.LittleEndian, &strBuffer)
	dataEntry[21] = string(strBuffer)

	binary.Read(reader, binary.LittleEndian, &lp)
	strBuffer = make([]byte, lp)
	binary.Read(reader, binary.LittleEndian, &strBuffer)
	dataEntry[22] = string(strBuffer)

	binary.Read(reader, binary.LittleEndian, &lp)
	strBuffer = make([]byte, lp)
	binary.Read(reader, binary.LittleEndian, &strBuffer)
	dataEntry[23] = string(strBuffer)

	binary.Read(reader, binary.LittleEndian, &lp)
	strBuffer = make([]byte, lp)
	binary.Read(reader, binary.LittleEndian, &strBuffer)
	dataEntry[24] = string(strBuffer)

	binary.Read(reader, binary.LittleEndian, &lp)
	strBuffer = make([]byte, lp)
	binary.Read(reader, binary.LittleEndian, &strBuffer)
	dataEntry[25] = string(strBuffer)

	binary.Read(reader, binary.LittleEndian, &lp)
	strBuffer = make([]byte, lp)
	binary.Read(reader, binary.LittleEndian, &strBuffer)
	dataEntry[26] = string(strBuffer)

	binary.Read(reader, binary.LittleEndian, &tmpBool)
	bools |= tmpBool | queryset.bools
	dataEntry[27] = strconv.Itoa(int((bools>>2)&1))

	dataEntry[28] = strconv.Itoa(int((bools>>3)&1))

	dataEntry[29] = strconv.Itoa(int((bools>>4)&1))

	dataEntry[30] = strconv.Itoa(int((bools>>5)&1))

	// Replace specific zeroes with empty strings
	if dataEntry[3] == "0" {dataEntry[3] = ""}
	if dataEntry[4] == "0" {dataEntry[4] = ""}

	// Format and write data to CSV file if an output file was named
	if fileOut != nil {

		writer.Write([]string{
			"A:"+dataEntry[0],
			"B:"+dataEntry[1],
			"C:"+dataEntry[2],
			"D:"+dataEntry[3],
			"E:"+dataEntry[4],
			"F:"+dataEntry[5],
			"G:"+dataEntry[7],
			"H:"+dataEntry[8],
			"I:"+dataEntry[9],
			"J:"+dataEntry[10],
			"K:"+dataEntry[16],
			"L:"+dataEntry[18],
			"M:"+dataEntry[20],
			"N:"+dataEntry[22],
			"O:"+dataEntry[25],
			"P:"+dataEntry[26],
			"Q:"+dataEntry[27],
			"R:"+dataEntry[11],
			"S:"+dataEntry[12],
			"T:"+dataEntry[28],
		})

	}

	// Format and write data to standard output if no output file was named and the pointer is nil
	if fileOut == nil && dataEntryString == nil {

		var eu, proxy, tor, snort, av string
		if dataEntry[27] == "0" {eu = "No"
		} else {eu = "Yes"}
		if dataEntry[5] == "0" {proxy = "No"
		} else {proxy = "Yes"}
		if dataEntry[28] == "0" {tor = "No"
		} else {tor = "Yes"}
		if dataEntry[29] == "0" {snort = "No"
		} else {snort = "Yes"}
		if dataEntry[30] == "0" {av = "No"
		} else {av = "Yes"}
		os.Stdout.WriteString(
			"----- IP -----"+eol+eol+
			"IP:                 "+dataEntry[0]+eol+
			eol+"----- WAN -----"+eol+eol+
			"WAN:                "+dataEntry[1]+eol+
			"Continent:          "+dataEntry[17]+eol+
			"Country:            "+dataEntry[19]+eol+
			"Major Subdivision:  "+dataEntry[21]+eol+
			"Minor Subdivision:  "+dataEntry[23]+eol+
			"City:               "+dataEntry[24]+eol+
			"Time Zone:          "+dataEntry[26]+eol+
			"EU:                 "+eu+eol+
			"Known Proxy:        "+proxy+eol+
			"Latitude:           "+dataEntry[8]+eol+
			"Longitude:          "+dataEntry[9]+eol+
			"Accuracy:           "+dataEntry[10]+" km"+eol+
			eol+"----- ASN -----"+eol+eol+
			"ASN Network:        "+dataEntry[11]+eol+
			"ASN:                "+dataEntry[12]+eol+
			"ISP:                "+dataEntry[13]+eol+
			eol+"-----Other-----"+eol+eol+
			"Known Tor Exit:     "+tor+eol+
			"Blocked by Snort:   "+snort+eol+
			"AlienVault Warning: "+av+eol)

	}

	// Format in JSON and write to the location given by the pointer if it is not nil
	if dataEntryString != nil {

		dataEntryBytes, err := json.MarshalIndent(jsonRoot{
			Ip: dataEntry[0],
			Wan: jsonWan{
				Network: dataEntry[1],
				Geoname_id: geo,
				Registered_country_geoname_id: reg,
				Represented_country_geoname_id: rep,
				Is_anonymous_proxy: bools&1,
				Is_satellite_provider: (bools>>1)&1,
				Postal_code: dataEntry[7],
				Latitude: lat,
				Longitude: long,
				Accuracy_radius: acc,
			},
			Asn: jsonAsn{
				Network: dataEntry[11],
				Autonomous_system_number: asn,
				Autonomous_system_organization: dataEntry[13],
			},
			Location: jsonLocation{
				Geoname_id: geo,
				Locale_code: dataEntry[15],
				Continent_code: dataEntry[16],
				Continent_name: dataEntry[17],
				Country_iso_code: dataEntry[18],
				Country_name: dataEntry[19],
				Subdivision_1_iso_code: dataEntry[20],
				Subdivision_1_name: dataEntry[21],
				Subdivision_2_iso_code: dataEntry[22],
				Subdivision_2_name: dataEntry[23],
				City_name: dataEntry[24],
				Metro_code: dataEntry[25],
				Time_zone: dataEntry[26],
				Is_in_european_union: (bools>>2)&1,
			},
			Other: jsonOther{
				Is_tor_node: (bools>>3)&1,
				Is_blocked: (bools>>4)&1,
				Is_malicious: (bools>>5)&1,
			},
		}, "", "\t")
		if err != nil {debug(err)}
		*dataEntryString = string(dataEntryBytes)
	}

}

func main() {

	var (
		//Data sets
		fileIn *string
		queries []string
		fileOut *string
		writer *csv.Writer
		language *string
		rest *string
		flags *uint8
		loadIPv4 bool
		loadIPv6 bool
	)

	//Push arguments to flag pointers
	for i := 1; i < len(os.Args); i++ {
		if strings.HasPrefix(os.Args[i], "-") {
			switch strings.TrimPrefix(os.Args[i], "-") {
				case "i":
					i++
					if fileIn == nil {fileIn = &os.Args[i]
					} else {help(1)}
					continue
				case "o":
					i++
					if fileOut == nil {fileOut = &os.Args[i]
					} else {help(1)}
					continue
				case "language":
					i++
					if language == nil {language = &os.Args[i]
					} else {help(1)}
					continue
				case "rest":
					i++
					if rest == nil {rest = &os.Args[i]
					} else {help(1)}
					continue
				case "ipv4":
					if flags == nil {flags = new(uint8)}
					if 1&*flags == 0 {*flags |= 1
					} else {help(1)}
					continue
				case "ipv6":
					if flags == nil {flags = new(uint8)}
					if 2&*flags == 0 {*flags |= 2
					} else {help(1)}
					continue
				default:
					help(1)
			}
		// If no flag prefix given, assume argument is input file
		} else if fileIn == nil {fileIn = &os.Args[i]
		// If no flag prefix given and input file already specified, assume argument is output file
		} else if fileOut == nil {fileOut = &os.Args[i]
		} else {help(1)}
	}

	// Interpret flags

	if fileIn != nil {queries = readFile(*fileIn)}
	if fileOut != nil {
		fileInfo, err := os.Stat(*fileOut)
		if err == nil {
			if fileInfo.IsDir() {
				err = errors.New("A directory with that name already exists")
				debug(err)
			}
			err = os.Remove(*fileOut)
			if err != nil {debug(err)}
		}
		//Create directory structure as needed
		os.MkdirAll(filepath.Dir(*fileOut), 0644)

		//Initialize CSV
		csvData, err := os.OpenFile(*fileOut, os.O_CREATE | os.O_WRONLY, 0644)
		if err != nil {debug(err)}
		defer csvData.Close()
		writer = csv.NewWriter(csvData)
		writer.UseCRLF = crlf
		writer.Write([]string{
			"ip_address",
			"city_network",
			"geoname_id",
			"registered_country_geoname_id",
			"represented_country_geoname_id",
			"is_anonymous_proxy",
			"postal_code",
			"latitude",
			"longitude",
			"accuracy_radius",
			"continent_code",
			"country_iso_code",
			"subdivision_1_iso_code",
			"subdivision_2_iso_code",
			"metro_code",
			"time_zone",
			"is_in_european_union",
			"asn_network",
			"autonomous_system_number",
			"is_tor_node",
		})
	}
	if language == nil {
		language = new(string)
		*language = "en"
	}
	if flags == nil {
		loadIPv4 = true
		loadIPv6 = true
	} else {
		if *flags&1 == 1 {loadIPv4 = true}
		if *flags&2 == 2 {loadIPv6 = true}
	}

	// Locate base directory of executable and use as base for referencing all future common resources
	dir, err := os.Executable()
	if err != nil {debug(err)}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {debug(err)}
	dir = filepath.Dir(dir)
	dir = filepath.Join(dir, "Data")

	os.Stdout.WriteString("Parsing data sets...\n")

	// Initialize dataset buffer
	dataset.buffer = new(bytes.Buffer)

	// Load MaxMind data

	if loadIPv4 {
		readCity(filepath.Join(dir, "GeoLite2-City-Blocks-IPv4.csv"), false)
		readASN(filepath.Join(dir, "GeoLite2-ASN-Blocks-IPv4.csv"), false)
	}

	if loadIPv6 {
		readCity(filepath.Join(dir, "GeoLite2-City-Blocks-IPv6.csv"), true)
		readASN(filepath.Join(dir, "GeoLite2-ASN-Blocks-IPv6.csv"), true)
	}

	readLocations(filepath.Join(dir, "GeoLite2-City-Locations-"+*language+".csv"))

	// Read dataset buffer into records []byte slice
	dataset.records = make([]byte, dataset.buffer.Len())
	dataset.buffer.Read(dataset.records)
	dataset.buffer.Reset()
	dataset.buffer = nil

	// Load additional data
	dataset.tor = "\n"+strings.Join(readFile(filepath.Join(dir, "exit-addresses")), "\n")+"\n"
	dataset.snort = "\n"+strings.Join(readFile(filepath.Join(dir, "ip-block-list")), "\n")+"\n"
	dataset.av = "\n"+strings.Join(readFile(filepath.Join(dir, "reputation.data")), "\n")+"\n"

	// Run garbage collection
	runtime.GC()

	// Interactive session if no input file given
	if fileIn == nil {
		// Initialize REST API thread if flagged
		if rest != nil {
			http.Handle("/api", newRestHandler(fileOut, writer))
			go http.ListenAndServe(*rest, nil)
			var restAddr string
			if strings.HasPrefix(*rest, ":") && strings.Count(*rest, ":") == 1 {
				restAddr = "localhost"+*rest
			} else {restAddr = *rest}
			os.Stdout.WriteString("Listening on "+restAddr+"\nExample: "+restAddr+"/api?ip=8.8.8.8\n")
		}
		// Initialize interactive console session for reading queries and writing results
		consoleReader := bufio.NewScanner(os.Stdin)
		prompt := "\nEnter an IP to query, or enter a blank line to exit\n"
		os.Stdout.WriteString(prompt)
		for consoleReader.Scan() {
			if consoleReader.Text() == "" {os.Exit(0)}
			dataEntry := queryData(consoleReader.Text())
			if dataEntry.cbentry != -1 && dataEntry.clentry != -1 {writeData(dataEntry, fileOut, writer, nil)}
			os.Stdout.WriteString(prompt)
		}
	}

	// Scripted session directed by input file
	if queries != nil {

		if fileOut != nil {os.Stdout.WriteString("Writing to file...\n")}

		for i, query := range queries {

			if query == "" {continue}

			if fileOut == nil && i > 1 {os.Stdout.WriteString(eol)}

			dataEntry := queryData(query)

			if dataEntry.cbentry != -1 && dataEntry.clentry != -1 {writeData(dataEntry, fileOut, writer, nil)}

		}
	}
	// Flush remaining writer buffer to file, if given, before exiting
	if fileOut != nil {writer.Flush()}
}