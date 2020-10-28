/*spamparse is designed to read the files in our collected spam folder
and parse the file names into various maps and slices, then create files
that list that information for me to then analyze information about collected
spam*/
package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"mailenable/geolocate"
	"mailenable/scrubbing"
)

// A data structure to hold a key/value pair.
type Pair struct {
	Key   string
	Value int
}

// A slice of Pairs that implements sort.Interface to sort by Value.
type PairList []Pair

func (p PairList) Swap(i, j int) { p[i], p[j] = p[j], p[i] }
func (p PairList) Len() int      { return len(p) }
func (p PairList) Less(i, j int) bool {
	return p[i].Value < p[j].Value || ((p[i].Value == p[j].Value) && (p[i].Key > p[j].Key))
}

// A function to turn a map into a PairList, then sort and return it.
func sortMapByValue(m map[string]int) PairList {
	p := make(PairList, len(m))
	i := 0
	for k, v := range m {
		p[i] = Pair{k, v}
		i++
	}
	sort.Sort(sort.Reverse(p))
	return p
}

func createFileFromMap(m map[string]int, fn string, h string) {
	OFile, err := os.Create(fn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create %s\r\n", fn)
		return
	}

	OFileW := bufio.NewWriter(OFile)
	//sort our map by values (descending)
	sorted := sortMapByValue(m)

	for x := range sorted {
		if h != "" {
			OFileW.WriteString(fmt.Sprintf("%s,%s\r\n", h, sorted[x].Key))
		} else {
			OFileW.WriteString(fmt.Sprintf("%s,\t%d\r\n", sorted[x].Key, sorted[x].Value))
		}
	}

	OFileW.Flush()
	OFile.Close()
}

func createGeoFileFromMap(m map[string]int, fn string) {
	OFile, err := os.Create(fn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create %s\r\n", fn)
		return
	}

	OFileW := bufio.NewWriter(OFile)

	for k, _ := range m {
		geo := geolocate.GetGeoData(k + ".112")
		OFileW.WriteString(fmt.Sprintf("%s: %s  %s  %s  %s \r\n", k, geo.ISP, geo.City, geo.CountryCode, geo.CountryName))
	}

	OFileW.Flush()
	OFile.Close()
}

func main() {
	var (
		filenameCount    = make(map[string]int)
		ipCount          = make(map[string]int)
		senderEmailCount = make(map[string]int)
		domainCount      = make(map[string]int)
		tldCount         = make(map[string]int)
		fileTrailCount   = make(map[string]int)
		trailCount       = make(map[string]int)
		reasonCount      = make(map[string]int)
		spamReview       = make(map[string]int)
		ipGeoCount       = make(map[string]int)
	)

	fmt.Printf("\nInitializing...\n")
	var scrub scrubbing.Scrubbers
	scrub.New(filepath.Join("C:/AUTOJOB/" + "cleanit.csv"))
	fmt.Printf("HAMDOM map contains %d entries\r\n", len(scrub.Hamdoms))
	fmt.Printf("SENDER map contains %d entries\r\n", len(scrub.Senders))
	fmt.Printf("DOMAINS map contains %d entries\r\n", len(scrub.Domains))
	fmt.Printf("TLD map contains %d entries\r\n", len(scrub.TLDs))
	fmt.Printf("IPS map contains %d entries\r\n", len(scrub.IPs))
	fmt.Printf("RECIP map contains %d entries\r\n", len(scrub.Recipients))
	fmt.Printf("EXCEPT map contains %d entries\r\n", len(scrub.Exceptions))
	fmt.Printf("PHRASES  map contains %d entries\r\n", len(scrub.PhrasesMap))
	fmt.Printf("PHRASES array contains %d entries\r\n\r\n", len(scrub.Phrases))
	fmt.Printf("Initializing...Done\r\n")

	files, err := ioutil.ReadDir(".")
	if err != nil {
		fmt.Println("directory read error")
		os.Exit(1)
	}

	for x, _ := range files {
		if strings.Contains(files[x].Name(), ".spm") {
			fmt.Println(files[x].Name())

			var greyRecord scrubbing.GreyRec
			greyRecord.Filename = files[x].Name()

			greyRecord.SplitRecord()
			greyRecord.ScrubRecord(&scrub)

			// add to our maps
			filenameCount[greyRecord.Filename[:strings.Index(greyRecord.Filename, ".tab")]]++
			ipCount[greyRecord.IP]++
			ipGeoCount[greyRecord.IP]++
			senderEmailCount[greyRecord.SenderEmail]++
			domainCount[greyRecord.Domain]++
			tldCount[greyRecord.TLD]++
			fileTrailCount[greyRecord.Trail+" ==> "+greyRecord.Filename[:strings.Index(greyRecord.Filename, ".tab")]]++
			trailCount[greyRecord.Trail]++
			for _, v := range greyRecord.Reasons {
				reasonCount[v]++
			}
			//			spamReview  = make(map[string]int)
			spamReview[greyRecord.TLD+"=="+greyRecord.IP+"=="+greyRecord.Domain+"=="+greyRecord.Sender+"=="+greyRecord.Trail+"==>"+greyRecord.Recipient]++

		}
	}

	createFileFromMap(filenameCount, "filenameCount.csv", "")
	createFileFromMap(ipCount, "IPCount.csv", "IP")
	createFileFromMap(senderEmailCount, "senderEmailCount.csv", "")
	createFileFromMap(domainCount, "domainCount.csv", "DOMAIN")
	createFileFromMap(tldCount, "TLDCount.csv", "")
	createFileFromMap(fileTrailCount, "filetrailCount.csv", "")
	createFileFromMap(trailCount, "trailCount.csv", "")
	createFileFromMap(reasonCount, "reasonCount.csv", "")
	createFileFromMap(spamReview, "spamReview.csv", "")
	createGeoFileFromMap(ipGeoCount, "IP Geo.csv")
}
