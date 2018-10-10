//Package geolocate
package geolocate

import (
	"compress/gzip"
	"errors"
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
}

func GetGeoData(IP string) (*GeoIPData, error) {
	rlog.Trace(1, "begin GetGeoData")
	defer rlog.Trace(1, "end GetGeoData")

	url := fmt.Sprintf("http://api.geoiplookup.net/?query=%s", IP)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		rlog.Error(fmt.Sprintf("Create NewRequest failed - %s", err))
		return nil, err
	}

	req.Header.Add("Accept", "text/xml")
	req.Header.Add("Accept-Encoding", "gzip")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		rlog.Error(fmt.Sprintf("Do(req) failed - %s", err))
		return nil, err
	}
	defer resp.Body.Close()

	if resp.Status != "200 OK" {
		rlog.Error("GetGeoData received invalid response - " + resp.Status)
		err := errors.New("GetGeoData received invalid response - " + resp.Status)
		return nil, err
	}

	var reader io.ReadCloser
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(resp.Body)
		defer reader.Close()
	default:
		reader = resp.Body
	}

	byt, err := ioutil.ReadAll(reader)
	if err != nil {
		rlog.Error(fmt.Sprintf("Reading our reader failed - %s", err))
		return nil, err
	}

	respStr := string(byt)

	respStr = strings.Replace(respStr, "</", "\t", -1)
	respStr = strings.Replace(respStr, "<", "\t", -1)
	respStr = strings.Replace(respStr, ">", "\t", -1)

	strArray := strings.Split(respStr, "\t")

	Geo := GeoIPData{}
	Geo.IP = strArray[10]
	Geo.Host = strArray[14]
	Geo.ISP = strArray[18]
	Geo.City = strArray[22]
	Geo.CountryCode = strArray[26]
	Geo.CountryName = strArray[30]
	Geo.Latitude = strArray[34]
	Geo.Longitude = strArray[38]
	rlog.Debug(fmt.Sprintf("parsed Geo answer for IP:%s --> %v ", IP, Geo))
	return &Geo, nil
}
