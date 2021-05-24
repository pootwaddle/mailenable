package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pootwaddle/mailenable/geolocate"

	"github.com/romana/rlog"
	_ "github.com/ziutek/mymysql/godrv"
)

func loadConfig() int {
	rlog.Trace(1, "begin loadConfig")
	defer rlog.Trace(1, "end loadConfig")

	content, err := ioutil.ReadFile(filepath.Join("./logparse.cfg"))
	if err != nil {
		return 0
	}

	value, err := strconv.Atoi(string(content))
	if err != nil {
		return 0
	}

	return value
}

func writeConfig(count int) {
	rlog.Trace(1, "begin writeConfig")
	defer rlog.Trace(1, "end writeConfig")

	file, err := os.Create(filepath.Join("./logparse.cfg"))
	if err != nil {
		rlog.Error(fmt.Sprintf("Cannot create file %s", err))
		os.Exit(1)
	}
	defer file.Close()

	fmt.Fprintf(file, fmt.Sprintf("%d", count))
}

func loadFile(fileName string) [][]string {
	rlog.Trace(1, "begin loadFile")
	defer rlog.Trace(1, "end loadFile")

	content, err := ioutil.ReadFile(fileName)
	if err != nil {
		rlog.Error("loadFile ReadFile error - " + fileName)
		os.Exit(1)
	}

	content = bytes.Replace(content, []byte("\r\n"), []byte("\n"), -1)

	l1 := strings.Split(string(content), "\n")
	var lines [][]string

	for _, line := range l1 {

		// future: return only SMTP-IN and only those lines since last pass
		fields := strings.Split(line, "\t")

		if len(fields) == 12 {
			if fields[1] == "SMTP-IN" {
				lines = append(lines, fields)
			}
		}
	}

	return lines
}

func exportCollectedIPs(selectIP *sql.Stmt, ipMap map[string]int) {
	rlog.Trace(1, "begin exportCollectedIPs")
	defer rlog.Trace(1, "end exportCollectedIPs")

	rows, err := selectIP.Query()
	if err != nil {
		rlog.Error(fmt.Sprintf("selectIP failed: %s", err))
	} else {
		//rows is *Rows
		defer rows.Close()

		for rows.Next() {
			var (
				IP string
			)
			if err := rows.Scan(&IP); err != nil {
				rlog.Error(err)
				os.Exit(1)
			}
			//substitute * for last octet
			newIP := modifyIP(IP, true)
			//append to map to de-duplicate
			ipMap[newIP]++
		}
	}
	rlog.Info(fmt.Sprintf("We have collected %d unique IP blocks", len(ipMap)))
}

func modifyIP(origIP string, addwildcard bool) string {
	rlog.Trace(1, "begin modifyIP")
	defer rlog.Trace(1, "end modifyIP")

	newIP := origIP
	octets := strings.Split(origIP, ".")
	if len(octets) == 4 {
		newIP = octets[0] + "." + octets[1] + "." + octets[2]

		if addwildcard {
			newIP += ".*"
		}
	}
	return newIP
}

func exportToFile(filepath string, collection map[string]int) {
	rlog.Trace(1, "begin exportToFile")
	defer rlog.Trace(1, "end exportToFile")

	file, err := os.Create(filepath)
	if err != nil {
		rlog.Error(fmt.Sprintf("Cannot create file %s %s", filepath, err))
		os.Exit(1)
	}
	defer file.Close()

	for i, _ := range collection {
		fmt.Fprintf(file, fmt.Sprintf("%s\t1\tCONNECT\tSYSTEM\r\n", i))
	}
}

func main() {
	//initialize logging
	//	ologfileName := fmt.Sprintf("logparse_%s", time.Now().Format("20060102_150405"))
	/*
		ologfileName := fmt.Sprintf("logparse_%s", time.Now().Format("20060102"))
		os.Setenv("RLOG_LOG_FILE", filepath.Join("D:/archive/"+ologfileName+".log"))
	*/
	os.Setenv("RLOG_LOG_FILE", filepath.Join("D:/OVERNITE/GREYLIST/logparse.log"))

	rlog.UpdateEnv()
	rlog.Info(os.Args[0] + " started")

	// initialize our maps
	ipInfo := make(map[geolocate.GeoIPData]int)
	collectedIPs := make(map[string]int)

	//MySQL Connection:
	var server string = "tcp:192.168.106.253:3306"
	var database string = "geoip"
	var user string = "sb"
	var pwd string = "12345"

	rlog.Debug("connect to database started")
	con, err := sql.Open("mymysql", server+"*"+database+"/"+user+"/"+pwd)
	if err != nil {
		rlog.Error(fmt.Sprintf("Unable to connect to Database [%s], [%s], [%s]\r\n", database, user, err))
		os.Exit(1)
	}
	defer con.Close()
	rlog.Debug("connection to database established")

	lastTime := loadConfig()
	potentialNewIP := false

	//prepare statements:
	rlog.Debug("prepare insqry")
	insqry, err := con.Prepare("insert ignore into collected (ip, host, isp, city, countrycode, countryname, latitude, longitude, qty) values (?, ?, ?, ?,?,?,?,?,?)  ON DUPLICATE KEY UPDATE qty = qty + ?")
	if err != nil {
		rlog.Error(fmt.Sprintf("[%s], [%s], [%s]", database, user, err))
		os.Exit(1)
	}
	defer insqry.Close()
	rlog.Debug("insqry prepared")

	rlog.Debug("prepare ins2cleanitqry")
	ins2cleanitqry, err := con.Prepare("insert ignore into cleanit (tag, value) values (?, ?)")
	if err != nil {
		rlog.Error(fmt.Sprintf("[%s], [%s], [%s]", database, user, err))
		os.Exit(1)
	}
	defer ins2cleanitqry.Close()
	rlog.Debug("ins2cleanitqry prepared")

	rlog.Debug("prepare selectIP")
	selectIP, err := con.Prepare("Select ip from collected where (TIMESTAMPDIFF(DAY,seen,now())) <=30")

	if err != nil {
		rlog.Error(fmt.Sprintf("Error creating selectIP, [%s]", err))
		os.Exit(1)
	}
	defer selectIP.Close()
	rlog.Debug("selectIP prepared")

	fileName := filepath.Join("./" + fmt.Sprintf("SMTP-Activity-%s.log", time.Now().Format("060102")))
	rlog.Info("parsing " + fileName)

	lineArray := loadFile(fileName)
	rlog.Info(fmt.Sprintf("%d lines from %s", len(lineArray), fileName))
	rlog.Info(fmt.Sprintf("%d last time", lastTime))

	if lastTime > len(lineArray) {
		rlog.Info("resetting our pointer")
		lastTime = 0
	}

	geo := &geolocate.GeoIPData{}

	for x := lastTime; x < len(lineArray); x++ {
		y := lineArray[x]
		// EHLO or HELO
		if (y[5] == "HELO") || (y[5] == "EHLO") {
			rlog.Info("Checking HELO - " + y[4] + " " + y[5] + y[6])
			geo = geolocate.GetGeoData(y[4])
			rlog.Info(fmt.Sprintf("Line: %d  IP: %s  CountryCode: %s  %s", x, y[4], geo.CountryCode, y[7][:3]))
			ipInfo[*geo]++
			potentialNewIP = true
		} else if len(y[7]) > 3 {
			if y[7][0:1] == "5" {
				geo.Code = y[7][0:3]
				geo = geolocate.GetGeoData(y[4])
				rlog.Info(fmt.Sprintf("Line: %d  IP: %s  CountryCode: %s  %s", x, y[4], geo.CountryCode, y[7][:3]))
				ipInfo[*geo]++
				potentialNewIP = true
			}
		}
	}

	if len(ipInfo) > 0 {

		//if located and not safe....

		rlog.Debug("map.ipInfo ==> mysql.collected")
		for i, j := range ipInfo {
			i.ConfirmBlock()
			if i.Block {
				rlog.Info(fmt.Sprintf("Inserting %s %s %s", i.IP, i.CountryCode, i.ISP))
				_, err := insqry.Exec(i.IP,
					i.Host,
					i.ISP,
					i.City,
					i.CountryCode,
					i.CountryName,
					i.Latitude,
					i.Longitude,
					j,
					j,
				)
				if err != nil {
					rlog.Error(fmt.Sprintf("[%s], [%s], [%s]\r\n", database, user, err))
					os.Exit(1)
				}
			}
		}

		rlog.Debug("map.ipInfo ==> mysql.cleanit")

		for i, _ := range ipInfo {
			_, err := ins2cleanitqry.Exec("IP", modifyIP(i.IP, false))
			if err != nil {
				rlog.Error(fmt.Sprintf("[%s], [%s], [%s]\r\n", database, user, err))
				os.Exit(1)
			}

		}

		if potentialNewIP {
			rlog.Debug("mysql.collected ==> map.collectedIPs")
			exportCollectedIPs(selectIP, collectedIPs)

			rlog.Debug("map.collectedIPs ==> moe.smtp-deny")
			outputFileName := filepath.Join("\\\\moe\\c\\Program Files (x86)\\Mail Enable\\Config\\SMTP-DENY.TAB")
			exportToFile(outputFileName, collectedIPs)

			rlog.Debug("map.collectedIPs ==> file.archive")
			outputFileName = fmt.Sprintf("SMTP-DENY_%s", time.Now().Format("20060102_150405"))
			outputFileName = filepath.Join("\\\\moe\\d\\archive\\" + outputFileName + ".tab")
			exportToFile(outputFileName, collectedIPs)
		} else {
			rlog.Info("no potential new IPs")
		}
	} else {
		rlog.Info("no rogue IPs collected.")
	}
	writeConfig(len(lineArray))
	rlog.Info(os.Args[0] + " completed.")
}
