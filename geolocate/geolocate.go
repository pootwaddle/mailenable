//Package geolocate
package geolocate

import (
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/romana/rlog"
)

type GeoIPData struct {
	IP          string
	Host        string
	ISP         string
	City        string
	CountryCode string
	CountryName string
	Latitude    string
	Longitude   string
	Located     bool
	Errmsg      string
	Code        string
	Block       bool
}

func Routable(IP string) bool {
	//10.0.0.0 to 10.255.255.255
	//172.16.0.0 to 172.31.255.255
	//192.168.0.0 to 192.168.255.255
	if strings.HasPrefix(IP, "192.168.") {
		return false
	}

	if strings.HasPrefix(IP, "10.") {
		return false
	}

	if strings.HasPrefix(IP, "172.") {
		a := strings.Split(IP, ".")
		if a[1] >= "16" && a[1] <= "31" {
			return false
		}
	}
	return true
}

func (g *GeoIPData) ConfirmBlock() {
	rlog.Trace(1, "begin ConfirmBlock")
	defer rlog.Trace(1, "end ConfirmBlock")

	//start off true, only decide to unblock if it matches any exception item
	g.Block = true

	if (g.CountryCode == "US") && !(strings.HasPrefix(g.Code, "5")) {
		g.Block = false
		rlog.Info(fmt.Sprintf("CountryCode Exception for IP %s", g.IP))
	}

	var whitelistedIP []string
	whitelistedIP = append(whitelistedIP,
		"60.251.40.",
		"60.251.40.",
		"213.239.228.",
	)

	for _, x := range whitelistedIP {
		if strings.HasPrefix(g.IP, x) {
			g.Block = false
			rlog.Info(fmt.Sprintf("WhitelistedIP Exception for IP %s", g.IP))
		}
	}

	var whitelistedISP []string
	whitelistedISP = append(whitelistedISP,
		"amazon",
		"twitter",
		"google",
	)

	var blacklistedISP []string
	blacklistedISP = append(blacklistedISP,
		"digital ocean",
		"digitalocean",
		"ocean",
	)

	for _, x := range whitelistedISP {
		if strings.HasPrefix(strings.ToLower(g.ISP), x) {
			g.Block = false
			rlog.Info(fmt.Sprintf("WhitelistedISP Exception for ISP %s", g.ISP))
		}
	}

	for _, x := range blacklistedISP {
		if strings.HasPrefix(strings.ToLower(g.ISP), x) {
			g.Block = true
			rlog.Info(fmt.Sprintf("BlacklistedISP -- ISP %s", g.ISP))
		}
	}

	if strings.HasPrefix(g.IP, "192.168.106.") {
		g.Block = false
		rlog.Info(fmt.Sprintf("LaughingJ Exception for IP %s", g.IP))
	}
	if g.Block == false {
		rlog.Info(fmt.Sprintf("%s %s not blocked ", g.IP, g.ISP))
	}
}

func GetGeoData(IP string) *GeoIPData {
	rlog.Trace(1, "begin GetGeoData")
	defer rlog.Trace(1, "end GetGeoData")

	Geo := GeoIPData{}
	Geo.IP = IP
	Geo.Located = false

	if !Routable(IP) {
		Geo.Errmsg = IP + "is Non-Routable"
		rlog.Info(Geo.Errmsg)
		return &Geo
	}

	url := fmt.Sprintf("http://api.geoiplookup.net/?query=%s", IP)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		Geo.Errmsg = fmt.Sprintf("Create NewRequest failed - %s", err)
		rlog.Error(Geo.Errmsg)
		return &Geo
	}

	req.Header.Add("Accept", "text/xml")
	req.Header.Add("Accept-Encoding", "gzip")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		Geo.Errmsg = fmt.Sprintf("Do(req) failed - %s", err)
		rlog.Error(Geo.Errmsg)
		return &Geo
	}
	defer resp.Body.Close()

	if resp.Status != "200 OK" {
		Geo.Errmsg = fmt.Sprintf("GetGeoData received invalid response - " + resp.Status)
		rlog.Error(Geo.Errmsg)
		return &Geo
	}

	var reader io.ReadCloser
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(resp.Body)
	default:
		reader = resp.Body
	}

	if err != nil {
		Geo.Errmsg = fmt.Sprintf("reader (gzip) - %s", err)
		rlog.Error(Geo.Errmsg)
		return &Geo
	}
	defer reader.Close()

	byt, err := ioutil.ReadAll(reader)
	if err != nil {
		Geo.Errmsg = fmt.Sprintf("Reading our reader failed - %s", err)
		rlog.Error(Geo.Errmsg)
		return &Geo
	}

	respStr := string(byt)

	respStr = strings.Replace(respStr, "</", "\t", -1)
	respStr = strings.Replace(respStr, "<", "\t", -1)
	respStr = strings.Replace(respStr, ">", "\t", -1)

	strArray := strings.Split(respStr, "\t")

	Geo.Host = strArray[14]
	Geo.ISP = strArray[18]
	Geo.City = strArray[22]
	Geo.CountryCode = strArray[26]
	Geo.CountryName = strArray[30]
	Geo.Latitude = strArray[34]
	Geo.Longitude = strArray[38]
	Geo.Errmsg = ""
	if Geo.CountryCode != "" && Geo.ISP != "" {
		Geo.Located = true
	}
	rlog.Debug(fmt.Sprintf("parsed Geo answer for IP:%s --> %v ", IP, Geo))
	return &Geo
}
