package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	//"strconv"
	"strings"
	"time"

	"mailenable/geolocate"

	"github.com/romana/rlog"
	_ "github.com/ziutek/mymysql/godrv"
)

func LoadFile(fileName string) []string {
	rlog.Trace(1, "begin LoadFile")
	defer rlog.Trace(1, "end LoadFile")

	content, err := ioutil.ReadFile(fileName)
	if err != nil {
		rlog.Error("LoadFile ReadFile error - " + fileName)
		os.Exit(1)
	}

	content = bytes.Replace(content, []byte("\r\n"), []byte("\n"), -1)

	l1 := strings.Split(string(content), "\n")
	return l1
}

func main() {

	//initialize logging
	//	ologfileName := fmt.Sprintf("logparse_%s", time.Now().Format("20060102_150405"))
	ologfileName := fmt.Sprintf("fileparse_%s", time.Now().Format("20060102"))
	os.Setenv("RLOG_LOG_FILE", filepath.Join("/archive/"+ologfileName+".log"))
	rlog.UpdateEnv()
	rlog.Info(os.Args[0] + " started")

	// initialize our maps
	ipInfo := make(map[geolocate.GeoIPData]int)

	//MySQL Connection:
	var server string = "tcp:192.168.106.253:3306"
	var database string = "geoip"
	var user string = "sb"
	var pwd string = "12345"
	con, err := sql.Open("mymysql", server+"*"+database+"/"+user+"/"+pwd)
	if err != nil {
		rlog.Error(fmt.Sprintf("Unable to connect to Database [%s], [%s], [%s]\r\n", database, user, err))
		os.Exit(1)
	}
	defer con.Close()

	//prepare statements:
	insqry, err := con.Prepare("insert ignore into collected (ip, host, isp, city, countrycode,countryname, latitude,longitude) values (?, ?, ?, ?,?,?,?,?)")
	if err != nil {
		rlog.Error(fmt.Sprintf("[%s], [%s], [%s]\r\n", database, user, err))
		os.Exit(1)
	}
	defer insqry.Close()

	if len(os.Args) < 2 {
		fmt.Println("Usage: fileparse <ffffffff>")
		os.Exit(1)
	}

	fileName := os.Args[1]
	fmt.Println(fileName)

	lineArray := LoadFile(fileName)
	rlog.Info(fmt.Sprintf("loaded %d lines from %s", len(lineArray), fileName))

	for x := 0; x < len(lineArray); x++ {
		y := lineArray[x]
		if len(y) > 6 {

			geo, err := geolocate.GetGeoData(y)

			if err != nil {
				rlog.Error(fmt.Sprintf("Geolocate failed - %s - %s", y, err))
			} else {
				rlog.Info(fmt.Sprintf("Line: %d  Code: %s  %s", x, y, geo.CountryCode))
				ipInfo[*geo]++
			}
		}
	}

	for i, j := range ipInfo {
		fmt.Println(i, j)
		_, err := insqry.Exec(i.IP,
			i.Host,
			i.ISP,
			i.City,
			i.CountryCode,
			i.CountryName,
			i.Latitude,
			i.Longitude,
		)
		if err != nil {
			rlog.Error(fmt.Sprintf("[%s], [%s], [%s]\r\n", database, user, err))
			os.Exit(1)
		}

	}

	fmt.Println(os.Args[0], "completed")
	rlog.Info(os.Args[0] + " completed.")
}
