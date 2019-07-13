//This program interfaces with the MailEnable greylist folder and
//deletes entries that would result in a spam email.  The MailEnable
//greylist keeps a zero-byte file with the file name itself named
//for the IP address (1st 3 octets), sender email address and
//recipient email address which
//we parse into IP, TLD, Domain, Sender pieces.
//We then check each of these pieces against our maps in memory
//and delete the file if it matches a value in one of the maps.
//We have a HAMDOM map which contains domains we consider ham senders
//which are also tested against and if found in the HAMDOM map the
//file is considered an exception and left in place.
//Example of the file names in the greylist folder:
/*
104.149.174 bounce-1064-5565776-1064-248@qtshz.com bjarvis@laughingj.com.tab
104.47.32 AMM418@pitt.edu jeff@jayfoxproductions.com.tab
104.47.36 AMM418@pitt.edu jeff@jayfoxproductions.com.tab
104.47.36 joyaditya.laik@pitt.edu jeff@jayfoxproductions.com.tab
104.47.40 AMM418@pitt.edu jeff@jayfoxproductions.com.tab
104.47.42 AMM418@pitt.edu jeff@jayfoxproductions.com.tab
184.170.251 KristiDonegan@browntech.net jeff@jayfoxproductions.com.tab
192.200.209 Leland@insideurmind.com jeff@jayfoxproductions.com.tab
77.224.109 bwiyehle@comunitel.net pootwaddle@pootwaddle.com.tab
85.214.106 Yeager_Lakeisha@p-monmarty-amr.com jeff@jayfoxproductions.com.tab
*/

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	AllCharsLessDigits = " !\"#$%&'()*+,-./:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
)

func filter(s, allow string) string {
	return strings.Map(func(r rune) rune {
		for _, r0 := range allow {
			if r == r0 {
				return r
			}
		}
		return -1
	}, s)
}

// our struct to hold the parsed parts of the file name, the major portions of which are space-separated.
type em1 struct {
	tld           string
	domain        string
	domainLessTLD string
	sender        string
	fname         string
	email         string
	ip            string
	recip         string
	reasons       []string
	exceptions    []string
}

type trigger struct {
	Trigger string `json:"trigger"`
	Count   int    `json:"count"`
}

func loadCSVfile(iFilename string) ([][]string, error) {
	var lines [][]string

	iFile, err := ioutil.ReadFile(iFilename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open %s\n", iFilename)
		return lines, err
	}

	iFile = bytes.Replace(iFile, []byte("\r"), []byte(""), -1)

	var l1 []string

	//skip BOM if it exists
	if iFile[0] == 0xEf {
		l1 = strings.Split(string(iFile[3:]), "\n")
	} else {
		l1 = strings.Split(string(iFile), "\n")
	}

	for _, line := range l1 {
		line := strings.Trim(line, " ")
		if line != "" {
			fields := strings.Split(line, ",")

			if len(fields) == 2 {
				lines = append(lines, fields)
			}
		}
	}
	return lines, nil
}

func main() {

	x1 := time.Now()
	sequence := fmt.Sprintf("%03d%02d%02d%02d", x1.YearDay(), x1.Hour(), x1.Minute(), x1.Second())

	recip := make(map[string]int)        //spamtrap/honeypot recipients map
	tlds := make(map[string]int)         //tld - map
	domains := make(map[string]int)      //domain -- map
	sender_match := make(map[string]int) //sender_match - map
	hamdom := make(map[string]int)       //ham domain - map	var lines [][]string
	ips := make(map[string]int)          //ip address - map 198.2.30
	except := make(map[string]int)       //email map of exceptions - emails we want to make sure get through

	phrases := []string{}            //slice used to do substring search
	triggers := make(map[string]int) //map for holding counts of "triggering" criteria

	//cleanit.csv is our comma-separated values to read into our maps
	//Example file records:
	/*
	   DOMAIN,gamezjunkie.com
	   IP,41.137.63
	   PHRASES,wallmart
	   HAMDOM,cityoflewisville.com
	   SENDER,avoid_heart_attack
	   TLD,.vn
	   RECIP,tj_droid@laughingj.com
	*/
	fmt.Printf("\nInitializing...\n")

	lines, err := loadCSVfile(filepath.Join("C:/AUTOJOB/" + "cleanit.csv"))
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, y := range lines {
		y[0] = strings.Trim(strings.ToUpper(y[0]), " ")
		y[1] = strings.Trim(strings.ToLower(y[1]), " ")
		switch y[0] {
		case "RECIP":
			recip[y[1]]++
		case "TLD":
			tlds[y[1]]++
		case "IP":
			ips[y[1]]++
		case "SENDER":
			sender_match[y[1]]++
		case "DOMAIN":
			domains[y[1]]++
		case "HAMDOM":
			hamdom[y[1]]++
		case "EXCEPT":
			except[y[1]]++

		case "PHRASES":
			phrases = append(phrases, y[1]) //phrases is slice, not a map...
		default:
			fmt.Println(fmt.Sprintf("%s doesn't match (%s)", y[0], y[1]))
		}
	}

	fmt.Printf("Initializing...Done\r\n")
	fmt.Printf(fmt.Sprintf("HAMDOM map contains %d entries\r\n", len(hamdom)))
	fmt.Printf(fmt.Sprintf("SENDER map contains %d entries\r\n", len(sender_match)))
	fmt.Printf(fmt.Sprintf("DOMAINS map contains %d entries\r\n", len(domains)))
	fmt.Printf(fmt.Sprintf("TLD map contains %d entries\r\n", len(tlds)))
	fmt.Printf(fmt.Sprintf("IPS map contains %d entries\r\n", len(ips)))
	fmt.Printf(fmt.Sprintf("RECIP map contains %d entries\r\n", len(recip)))
	fmt.Printf(fmt.Sprintf("EXCEPT map contains %d entries\r\n", len(except)))
	fmt.Printf(fmt.Sprintf("PHRASES array contains %d entries\r\n\r\n", len(phrases)))

	//filenames we are deleting are actually being moved to a secondary folder
	//greylist folder filename.tab ==> C:\GG\filename~nnnnnn~.x1

	/*
		var tldArray []string
		for k, v := range tlds {
			fmt.Println(k, "   ", v)
			tldArray = append(tldArray, k)
			}
		for x, y := range tldArray {
			fmt.Println(x, y)
			fmt.Println(fmt.Sprintf("%x", "|"+tldArray[x]+"|"))
		}

		for k, _ := range hamdom {
				fmt.Printf(fmt.Sprintf("key: %s\n", k))
			}
			for k, _ := range sender_match {
				fmt.Printf(fmt.Sprintf("key: %s\n", k))
			}
			for k, _ := range domains {
				fmt.Printf(fmt.Sprintf("key: %s\n", k))
			}
			for k, _ := range tlds {
				fmt.Printf(fmt.Sprintf("key: %s\n", k))
			}
	*/

	var sender em1

	files, err := ioutil.ReadDir(".")
	if err != nil {
		fmt.Println("Directory Read Error:", err)
		os.Exit(1)
	}

	var filecount int
	var homedir bool = false
	for x, _ := range files {
		if strings.Contains(files[x].Name(), ".tab") {
			filecount++
		}

		if strings.Contains(files[x].Name(), "Exceptions") {
			homedir = true
		}
	}

	if homedir == false {
		fmt.Printf("Not in home folder\r\n\r\n")
		os.Exit(1)
	}

	fmt.Printf(fmt.Sprintf("Greylist contains %d entries\r\n\r\n", filecount))

	//Any match to our lists?

	files, err = ioutil.ReadDir(".")
	if err != nil {
		fmt.Println("Directory Read Error:", err)
		os.Exit(1)
	}

	for x, _ := range files {
		sender.reasons = sender.reasons[:0]
		sender.exceptions = sender.exceptions[:0]
		excpt := false

		if strings.Contains(files[x].Name(), ".tab") {
			sender.fname = files[x].Name()
			parts := strings.Split(strings.ToLower(files[x].Name()), " ")

			r := parts[2]
			if len(r) > 4 {
				r = r[:len(r)-4] //recipient is the 3rd part of the file name, includes .tab
			}

			s := parts[1]
			sender.email = strings.Trim(s, " ")
			sender.domain = strings.Trim(strings.Split(s, "@")[1], " ")
			sender.sender = strings.Trim(strings.Split(s, "@")[0], " ")
			sender.tld = strings.Trim(sender.domain[strings.LastIndex(sender.domain, "."):], " ")
			sender.domainLessTLD = strings.Trim(sender.domain[:strings.LastIndex(sender.domain, ".")], " ")
			//	sender.domain = strings.ToLower(sender.domain)
			//	sender.sender = strings.ToLower(sender.sender)
			//	sender.tld = strings.ToLower(sender.tld)
			sender.ip = strings.Trim(parts[0], " ")
			sender.recip = strings.Trim(r, " ")

			//in our hamdom map? then mark this as an exception to all the other rules
			if hamdom[sender.domain] != 0 {
				excpt = true
				sender.exceptions = append(sender.exceptions, "HAMDOM")
				fmt.Println("hamdom exception")
			}

			//in our exception map?  this is an email that we want to mark as an exception
			if except[sender.email] != 0 {
				excpt = true
				sender.exceptions = append(sender.exceptions, "EMAIL")
				fmt.Println("sender email exception")
			}

			//fmt.Println("Recip:", sender.recip, "--> ", recip[sender.recip])
			if recip[sender.recip] != 0 {
				fmt.Println(" RECIP MATCH: ", sender.recip)
				sender.reasons = append(sender.reasons, "RECIP: "+sender.recip)
			}

			//			fmt.Println("Sender:", sender.sender, "--> ", sender_match[sender.sender])
			if sender_match[sender.sender] != 0 {
				fmt.Println("SENDER MATCH: ", sender.sender)
				sender.reasons = append(sender.reasons, "SENDER: "+sender.sender)
			}

			//			fmt.Println("Domain:", sender.domain, "--> ", domains[sender.domain])
			if domains[sender.domain] != 0 {
				fmt.Println("DOMAIN MATCH: ", sender.domain)
				sender.reasons = append(sender.reasons, "DOMAIN: "+sender.domain)
			}

			//I want to mark domains that are all digits as spam, so if my domainLessTLD is ""
			//after filtering it , then mark it as spam....
			if filter(sender.domainLessTLD, AllCharsLessDigits) == "" {
				fmt.Println("DOMAIN ALL DIGITS:", sender.domain)
				sender.reasons = append(sender.reasons, "ALL DIGITS: "+sender.domain)
			}

			//			fmt.Println("TLD:", len(tlds), "  ", sender.tld, "--> ", tlds[sender.tld])
			if tlds[sender.tld] != 0 {
				fmt.Println("   TLD MATCH: ", sender.tld)
				sender.reasons = append(sender.reasons, "TLD MATCH: "+sender.tld)
			}

			if ips[sender.ip] != 0 {
				fmt.Println("    IP MATCH: ", sender.ip)
				sender.reasons = append(sender.reasons, "IP MATCH: "+sender.ip)
			}

			for _, val := range phrases {
				if strings.Contains(sender.domain, val) {
					fmt.Println("DOMAIN Contains: ", val)
					sender.reasons = append(sender.reasons, "PHRASE(DOMAIN): "+val)
				}

				if strings.Contains(sender.sender, val) {
					fmt.Println("SENDER Contains: ", val)
					sender.reasons = append(sender.reasons, "PHRASE(SENDER): "+val)
				}
			}

			if excpt {
				fmt.Println("EXCEPTIONS: ")
				fmt.Println(sender.email)
				for x, _ := range sender.exceptions {
					fmt.Println(sender.exceptions[x])
				}
				sender.reasons = sender.reasons[:0]
			}

			if len(sender.reasons) > 0 {
				err := os.Rename(sender.fname, "C:\\GG\\"+strings.Replace(sender.fname, " ", "~", -1)[:len(sender.fname)-4]+"~"+"reason"+"~"+sequence+"~.x1")

				if err != nil {
					fmt.Println(err)
					//return
				}

				fmt.Println("SPAM: ")
				fmt.Println(sender.email)
				for x, _ := range sender.reasons {
					fmt.Println(sender.reasons[x])
					triggers[sender.reasons[x]]++
				}
			}
		}
	}

	var trigs []trigger
	var t trigger
	fmt.Println("Triggers found:")
	for k, _ := range triggers {
		fmt.Println("Key:", k, " Count:", triggers[k])
		t = trigger{k, triggers[k]}
		trigs = append(trigs, t)
	}

	if trigs != nil {
		j, err := json.Marshal(trigs)
		if err != nil {
			fmt.Println("failure marshalling trigs")
		}
		//[
		//{"trigger":"S~news","count":1},
		//{"trigger":"T~.vn","count":3},
		//{"trigger":"I~192.168.11","count":2},
		//{"trigger":"Ps~toilet","count":1},
		//{"trigger":"Pd~iphone","count":3},
		//{"trigger":"D~3bbmail.com","count":3},
		//]
		//https://kev.inburke.com/kevin/golang-json-http/
		fmt.Println(string(j))
	}

	fmt.Printf("Finished!\r\n\r\n")
}
