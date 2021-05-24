//This program interfaces with the MailEnable greylist folder and
//deletes entries that would result in a spam email.  The MailEnable
//greylist keeps a zero-byte file with the file name itself named
//for the IP address (1st 3 octets), sender email address and
//recipient email address which
//we parse into IP, TLD, Domain and Sender pieces.
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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mailenable/scrubbing"
)

func main() {
	x1 := time.Now()
	sequence := fmt.Sprintf("%03d%02d%02d%02d", x1.YearDay(), x1.Hour(), x1.Minute(), x1.Second())

	//triggers := make(map[string]int) //map for holding counts of "triggering" criteria

	fmt.Printf("\nInitializing...\n")
	var scrub scrubbing.Scrubbers
	scrub.New(filepath.Join("C:/AUTOJOB/" + "cleanit.csv"))
	fmt.Printf("HAMDOM   map contains %d entries\r\n", len(scrub.Hamdoms))
	fmt.Printf("SENDER   map contains %d entries\r\n", len(scrub.Senders))
	fmt.Printf("DOMAINS  map contains %d entries\r\n", len(scrub.Domains))
	fmt.Printf("TLD      map contains %d entries\r\n", len(scrub.TLDs))
	fmt.Printf("IPS      map contains %d entries\r\n", len(scrub.IPs))
	fmt.Printf("RECIP    map contains %d entries\r\n", len(scrub.Recipients))
	fmt.Printf("EXCEPT   map contains %d entries\r\n", len(scrub.Exceptions))
	fmt.Printf("PHRASES  map contains %d entries\r\n", len(scrub.PhrasesMap))
	fmt.Printf("PHRASES  array contains %d entries\r\n\r\n", len(scrub.Phrases))
	fmt.Printf("KILL     map contains %d entries\r\n", len(scrub.PhrasesMap))
	fmt.Printf("KILL     array contains %d entries\r\n\r\n", len(scrub.Phrases))
	fmt.Printf("Initializing...Done\r\n")

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
		fmt.Println("\r\nNot in home folder")
		os.Exit(1)
	}

	fmt.Printf("Greylist contains %d entries\r\n\r\n", filecount)

	// Clean read, and process greylist files
	files, err = ioutil.ReadDir(".")
	if err != nil {
		fmt.Println("Directory Read Error:", err)
		os.Exit(1)
	}

	for x, _ := range files {
		if strings.Contains(files[x].Name(), ".tab") {
			fmt.Println(files[x].Name())

			var greyRecord scrubbing.GreyRec
			greyRecord.Filename = files[x].Name()
			greyRecord.Sequence = sequence

			greyRecord.SplitRecord()
			greyRecord.ScrubRecord(&scrub)
			greyRecord.MoveFileToSpam()
			fmt.Println()
			fmt.Println()
		}
	}

	fmt.Printf("\r\nFinished!\r\n")
}
