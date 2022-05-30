package goIP

import (
	"errors"
	"strings"
	"strconv"
)

// Public Ipinfo struct
type Ipinfo struct {
	ip uint64
	ipof uint64
	prefix uint64
	prefixof uint64
	limit uint64
	limitof uint64
	mask uint64
	maskof uint64
	rmask uint64
	rmaskof uint64
	prefixlen int
	suffixlen int
	isv6 bool
}

// Private functions

func ipv(ip string) (bool, error) {
	count := strings.Count(ip, ":")
	if count >= 2 && count <= 7 && !strings.Contains(ip, ".") {return true, nil}
	if strings.Count(ip, ".") == 3 && !strings.Contains(ip, ":") {return false, nil}
	return false, errors.New("IP formatted incorrectly")
}

func parse(ip string, isv6 bool) (pip, pipof uint64, prefix int, err error) {
	count := strings.Count(ip, "/")
	if count == 1 {
		tokens := strings.Split(ip, "/")
		pip, pipof, err = parseIP(tokens[0], isv6)
		if err != nil {return 0, 0, 0, err}
		prefix64, err := strconv.ParseUint(tokens[1], 10, 32)
		if err != nil {return 0, 0, 0, err}
		prefix = int(prefix64)
	} else if count > 1 {return 0, 0, 0, errors.New("Too many \"/\" in input")
	} else {
		pip, pipof, err = parseIP(ip, isv6)
		if err != nil {return 0, 0, 0, err}
		prefix = 0
	}
	return pip, pipof, prefix, nil
}

func parseIP(ip string, isv6 bool) (pip, pipof uint64, err error) {
	if isv6 {pip, pipof, err = parsev6(ip)
	} else {pip, err = parsev4(ip)}
	if err != nil {return 0, 0, err}
	return pip, pipof, nil
}

func parsev4(ip string) (pip uint64, err error) {
	octets := strings.Split(ip, ".")
	if len(octets) != 4 {return 0, errors.New("IP formatted incorrectly")}
	octet1, err := strconv.ParseUint(octets[0], 10, 8)
	if err != nil {return 0, errors.New("First octet malformed")}
	octet2, err := strconv.ParseUint(octets[1], 10, 8)
	if err != nil {return 0, errors.New("Second octet malformed")}
	octet3, err := strconv.ParseUint(octets[2], 10, 8)
	if err != nil {return 0, errors.New("Third octet malformed")}
	octet4, err := strconv.ParseUint(octets[3], 10, 8)
	if err != nil {return 0, errors.New("Fourth octet malformed")}
	pip = octet1<<24 | octet2<<16 | octet3<<8 | octet4
	return pip, nil
}

func parsev6(ip string) (pip, pipof uint64, err error) {
	if strings.Count(ip, "::") > 1 {return 0, 0, errors.New("IP formatted incorrectly")}
	var groups[] string
	if strings.Contains(ip, "::") {
		var zeros[] string
		if strings.HasPrefix(ip, "::") {ip = "0"+ip}
		if strings.HasSuffix(ip, "::") {ip = ip+"0"}
		groups = strings.Split(ip, "::")
		prefix := strings.Split(groups[0], ":")
		suffix := strings.Split(groups[1], ":")
		for l := 0; l < 8-(len(prefix)+len(suffix)); l++ {
			zeros = append(zeros, "0000")
		}
		groups = strings.Split(groups[0]+":"+strings.Join(zeros, ":")+":"+groups[1], ":")
	} else {
		groups = strings.Split(ip, ":")
		if len(groups) != 8 {return 0, 0, errors.New("IP formatted incorrectly")}
	}
	group1, err := strconv.ParseUint(groups[0], 16, 16)
	if err != nil {return 0, 0, errors.New("First group malformed")}
	group2, err := strconv.ParseUint(groups[1], 16, 16)
	if err != nil {return 0, 0, errors.New("Second group malformed")}
	group3, err := strconv.ParseUint(groups[2], 16, 16)
	if err != nil {return 0, 0, errors.New("Third group malformed")}
	group4, err := strconv.ParseUint(groups[3], 16, 16)
	if err != nil {return 0, 0, errors.New("Fourth group malformed")}
	group5, err := strconv.ParseUint(groups[4], 16, 16)
	if err != nil {return 0, 0, errors.New("Fifth group malformed")}
	group6, err := strconv.ParseUint(groups[5], 16, 16)
	if err != nil {return 0, 0, errors.New("Sixth group malformed")}
	group7, err := strconv.ParseUint(groups[6], 16, 16)
	if err != nil {return 0, 0, errors.New("Seventh group malformed")}
	group8, err := strconv.ParseUint(groups[7], 16, 16)
	if err != nil {return 0, 0, errors.New("Eighth group malformed")}
	pip = group5<<48 | group6<<32 | group7<<16 | group8
	pipof = group1<<48 | group2<<32 | group3<<16 | group4
	return pip, pipof, nil
}

func parseMasks(prefix int, isv6 bool) (suffix int, mask, maskof, rmask, rmaskof uint64) {
	if isv6 {
		suffix = 128-prefix
		if suffix == 64 {
			rmaskof = 0x0000000000000000
			rmask = 0xffffffffffffffff
		} else if suffix > 64 {
			for l := 0; l < suffix-64; l++ {rmaskof = ((rmaskof<<1))|1}
			rmask = 0xffffffffffffffff
		} else {
			for l := 0; l < suffix; l++ {rmask = ((rmask<<1))|1}
			rmaskof = 0x0000000000000000
		}
		maskof = rmaskof ^ 0xffffffffffffffff
		mask = rmask ^ 0xffffffffffffffff
	} else {
		suffix = 32-prefix
		for l := 0; l < suffix; l++ {rmask = ((rmask<<1))|1}
		mask = rmask ^ 0xffffffff
	}
	return
}

func parsePrefix(ip, ipof, mask, maskof uint64) (uint64, uint64) {
	return ip & mask, ipof & maskof
}

func v4tostr(v4 uint64) (string) {
	var builder strings.Builder
	builder.WriteString(strconv.FormatUint(v4>>24 & 0xff, 10))
	builder.WriteString(".")
	builder.WriteString(strconv.FormatUint(v4>>16 & 0xff, 10))
	builder.WriteString(".")
	builder.WriteString(strconv.FormatUint(v4>>8 & 0xff, 10))
	builder.WriteString(".")
	builder.WriteString(strconv.FormatUint(v4 & 0xff, 10))
	return builder.String()
}

func v6tostr(v6, v6of uint64) (v6str string) {
	var builder strings.Builder
	builder.WriteString(":")
	builder.WriteString(strconv.FormatUint((v6of>>48 & 0xffff), 16))
	builder.WriteString(":")
	builder.WriteString(strconv.FormatUint((v6of>>32 & 0xffff), 16))
	builder.WriteString(":")
	builder.WriteString(strconv.FormatUint((v6of>>16 & 0xffff), 16))
	builder.WriteString(":")
	builder.WriteString(strconv.FormatUint((v6of & 0xffff), 16))
	builder.WriteString(":")
	builder.WriteString(strconv.FormatUint((v6>>48 & 0xffff), 16))
	builder.WriteString(":")
	builder.WriteString(strconv.FormatUint((v6>>32 & 0xffff), 16))
	builder.WriteString(":")
	builder.WriteString(strconv.FormatUint((v6>>16 & 0xffff), 16))
	builder.WriteString(":")
	builder.WriteString(strconv.FormatUint((v6 & 0xffff), 16))
	builder.WriteString(":")
	v6str =	builder.String()
	if strings.Contains(v6str, ":0:0:") {
		v6str = strings.Replace(v6str, ":0:0:0:0:0:0:0:0:", "::", 1)
		v6str = strings.Replace(v6str, ":0:0:0:0:0:0:0:", "::", 1)
		v6str = strings.Replace(v6str, ":0:0:0:0:0:0:", "::", 1)
		v6str = strings.Replace(v6str, ":0:0:0:0:0:", "::", 1)
		v6str = strings.Replace(v6str, ":0:0:0:0:", "::", 1)
		if !strings.Contains(v6str, "::") {
			v6str = strings.Replace(v6str, ":0:0:0:", "::", 1)
			v6str = strings.Replace(v6str, ":0:0:", "::", 1)
		}
	}
	if !strings.HasPrefix(v6str, "::") {v6str = strings.TrimPrefix(v6str, ":")}
	if !strings.HasSuffix(v6str, "::") {v6str = strings.TrimSuffix(v6str, ":")}
	return
}

func parseLimit(ip, ipof, rmask, rmaskof uint64) (uint64, uint64) {
	return ip | rmask, ipof | rmaskof
}

// Public functions

// Initialize new instance of Ipinfo
func NewIP(ip string) (*Ipinfo, error) {
	isv6, err := ipv(ip)
	if err != nil {return nil, err}
	pip, pipof, prefixlen, err := parse(ip, isv6)
	if err != nil {return nil, err}
	if isv6 && prefixlen > 128 {
		err = errors.New("Prefix length too large")
		return nil, err
	}
	if !isv6 && prefixlen > 32 {
		err = errors.New("Prefix length too large")
		return nil, err
	}
	if prefixlen < 0 {
		err = errors.New("Prefix length cannot be negative")
		return nil, err
	}
	suffixlen, mask, maskof, rmask, rmaskof := parseMasks(prefixlen, isv6)
	prefix, prefixof := parsePrefix(pip, pipof, mask, maskof)
	limit, limitof := parseLimit(pip, pipof, rmask, rmaskof)
	newip := Ipinfo{
		ip: pip,
		ipof: pipof,
		prefix: prefix,
		prefixof: prefixof,
		limit: limit,
		limitof: limitof,
		mask: mask,
		maskof: maskof,
		rmask: rmask,
		rmaskof: rmaskof,
		prefixlen: prefixlen,
		suffixlen: suffixlen,
		isv6: isv6}
	return &newip, nil
}

// Convert 2 uint64, lower and upper bits, to string
func Iptostr(ip, ipof uint64, isv6 bool) (string) {
	if isv6 {return v6tostr(ip, ipof)
	} else {return v4tostr(ip)}
}

// Return 2 uint64, lower and upper bits, of IP
func (i Ipinfo) Ipint() (uint64, uint64) {
	return i.ip, i.ipof
}

// Return IP string
func (i Ipinfo) Ip() (string) {
	return Iptostr(i.ip, i.ipof, i.isv6)
}

// Return prefix length
func (i Ipinfo) Prefixlen() (int) {
	return i.prefixlen
}

// Return suffix length
func (i Ipinfo) Suffixlen() (int) {
	return i.suffixlen
}

// Return 2 uint64, lower and upper bits, of mask
func (i Ipinfo) Maskint() (uint64, uint64) {
	return i.mask, i.maskof
}

// Return mask string
func (i Ipinfo) Mask() (string) {
	return Iptostr(i.mask, i.maskof, i.isv6)
}

// Return 2 uin64, lower and upper bits, of reverse mask
func (i Ipinfo) Rmaskint() (uint64, uint64) {
	return i.rmask, i.rmaskof
}

// Return reverse mask string
func (i Ipinfo) Rmask() (string) {
	return Iptostr(i.rmask, i.rmaskof, i.isv6)
}

// Return bool of IPv6 or not
func (i Ipinfo) Isv6() (bool) {
	return i.isv6
}

// Return bool of IPv4 or not
func (i Ipinfo) Isv4() (bool) {
	return !i.isv6
}

// Return IP version number
func (i Ipinfo) V() (int) {
	if i.isv6 {return 6
	} else {return 4}
}

// Return 2 uint64, lower and upper bits, of prefix
func (i Ipinfo) Prefixint() (uint64, uint64) {
	return i.prefix, i.prefixof
}

// Return prefix string
func (i Ipinfo) Prefix() (string) {
	return Iptostr(i.prefix, i.prefixof, i.isv6)
}

// Return 2 uint64, lower and upper bits, of network upper bound
func (i Ipinfo) Limitint() (uint64, uint64) {
	return i.limit, i.limitof
}

// Return string of network upper bound
func (i Ipinfo) Limit() (string) {
	return Iptostr(i.limit, i.limitof, i.isv6)
}

// Check if IP is within network and return error if not
func (i Ipinfo) Ispeer(ip, ipof uint64) (bool, error) {
	if ipof > i.limitof || (ipof == i.limitof && ip > i.limit) {
		return false, errors.New("IP ascends out of network bounds")
	}
	if ipof < i.prefixof || (ipof == i.prefixof && ip < i.prefix) {
		return false, errors.New("IP descends out of network bounds")
	}
	return true, nil
}