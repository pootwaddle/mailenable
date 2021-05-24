package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pootwaddle/mailenable/geolocate"

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

func fullIP(ip string) string {
	ipsplit := strings.Split(ip, ".")

	if len(ipsplit) == 4 {
		return ip
	} else {
		//IP,192.168.232, add 112 as 4th octet
		return ip + ".112"
	}

}

func main() {

	//initialize logging
	//	ologfileName := fmt.Sprintf("logparse_%s", time.Now().Format("20060102_150405"))
	ologfileName := fmt.Sprintf("fileparse_%s", time.Now().Format("20060102"))
	os.Setenv("RLOG_LOG_FILE", filepath.Join("/archive/"+ologfileName+".log"))
	rlog.UpdateEnv()
	rlog.Info(os.Args[0] + " started")

	if len(os.Args) < 2 {
		rlog.Info("Usage: fileparse <ffffffff>")
		os.Exit(1)
	}

	fileName := os.Args[1]
	rlog.Info("Input File is ", fileName)

	lineArray := LoadFile(fileName)
	rlog.Info(fmt.Sprintf("loaded %d lines from %s", len(lineArray), fileName))

	//MySQL Connection:
	var server string = "tcp:192.168.106.253:3306"
	var database string = "geoip"
	var user string = "sb"
	var pwd string = "12345"
	rlog.Info("connect to database started")
	con, err := sql.Open("mymysql", server+"*"+database+"/"+user+"/"+pwd)
	if err != nil {
		rlog.Error(fmt.Sprintf("Unable to connect to Database [%s], [%s], [%s]\r\n", database, user, err))
		os.Exit(1)
	}
	defer con.Close()
	rlog.Info("connection to database established")

	//prepare statements:
	rlog.Info("prepare insqry")
	insqry, err := con.Prepare("insert ignore into collected (ip, host, isp, city, countrycode,countryname, latitude,longitude) values (?, ?, ?, ?,?,?,?,?)  ON DUPLICATE KEY UPDATE qty = qty + 1")
	if err != nil {
		rlog.Error(fmt.Sprintf("[%s], [%s], [%s]\r\n", database, user, err))
		os.Exit(1)
	}
	defer insqry.Close()
	rlog.Info("insqry prepared")

	var ip string

	for x := 0; x < len(lineArray); x++ {
		y := lineArray[x]
		y = strings.Replace(y, " ", "", -1)

		if len(y) > 6 {
			ip = fullIP(y[3:])

			geo := geolocate.GetGeoData(ip)

			if !geo.Located {
				rlog.Info(fmt.Sprintf("Line: %4d  Geolocate failed - %s - %s", x, ip, geo.Errmsg))
			} else {
				rlog.Info(fmt.Sprintf("Line: %4d Code: %s  %s, %s", x, y, ip, geo.CountryCode))

				//geo.ConfirmBlock() commented out because these IPs are confirmed spam senders
				geo.Block = true

				if geo.Block {
					_, err := insqry.Exec(geo.IP,
						geo.Host,
						geo.ISP,
						geo.City,
						geo.CountryCode,
						geo.CountryName,
						geo.Latitude,
						geo.Longitude,
					)
					if err != nil {
						rlog.Error(fmt.Sprintf("[%s], [%s], [%s]\r\n", database, user, err))
					}
					rlog.Info(fmt.Sprintf("Line: %4d Code: %s  %s, %s - Inserted into database", x, y, ip, geo.CountryCode))
				} else {
					rlog.Info(fmt.Sprintf("Line: %4d Code: %s  %s, %s - Not Inserted into databse", x, y, ip, geo.CountryCode))
				}

			}
		}
	}

	fmt.Println(os.Args[0], "completed")
	rlog.Info(os.Args[0] + " completed.")
}
