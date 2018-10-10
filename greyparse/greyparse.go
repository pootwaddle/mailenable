/*greyparse is designed to read the files in our greylist folder
and parse the file names into various maps and slices, then create files
that list that information for me to then analyze information about greylisted emails
*/
package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strings"
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

func main() {
	var (
		ipCount     = make(map[string]int)
		senderCount = make(map[string]int)
		domainCount = make(map[string]int)
		tldCount    = make(map[string]int)
		emailCount  = make(map[string]int)
		recipCount  = make(map[string]int)
		reviewCount = make(map[string]int)
	)

	files, err := ioutil.ReadDir(".")
	if err != nil {
		fmt.Println("directory read error")
		os.Exit(1)
	}

	for x, _ := range files {
		if strings.Contains(files[x].Name(), ".tab") {
			parts := strings.Split(files[x].Name(), " ")
			if len(parts) == 3 {
				ip := parts[0]
				from := parts[1] //is a string containing email adress
				fromSplit := strings.Split(from, "@")

				sender := fromSplit[0]
				domain := fromSplit[1]
				tld := domain[strings.LastIndex(domain, "."):]
				recip := parts[2]

				ipCount[strings.ToLower(ip)]++
				tldCount[strings.ToLower(tld)]++
				domainCount[strings.ToLower(domain)]++
				senderCount[strings.ToLower(sender)]++
				emailCount[strings.ToLower(from)]++
				recipCount[strings.ToLower(recip)]++
				reviewCount[strings.ToLower(ip+","+
					sender+","+
					domain+","+
					recip)]++
			}
			//	fmt.Println(files[x].Name())
		}
	}

	//filenames
	OFile, err := os.Create("greylist.txt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create greylist.txt\r\n")
		return
	}
	OFileW := bufio.NewWriter(OFile)

	for x := range files {
		if strings.Contains(files[x].Name(), ".tab") {
			OFileW.WriteString(files[x].Name() + "\r\n")
		}
	}

	OFileW.Flush()
	OFile.Close()
	//end filenames

	//tld
	OFile, err = os.Create("greyTLD.csv")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create greyTLD.csv\r\n")
		return
	}
	OFileW = bufio.NewWriter(OFile)
	OFileW.WriteString("greyTLD,Count\r\n")

	//sort our map by values (descending)
	sorted := sortMapByValue(tldCount)

	for x := range sorted {
		OFileW.WriteString(fmt.Sprintf("%s, %d\r\n", sorted[x].Key, sorted[x].Value))
	}

	OFileW.Flush()
	OFile.Close()
	//end tld

	//ip
	OFile, err = os.Create("greyIP.csv")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create greyIP.csv\r\n")
		return
	}
	OFileW = bufio.NewWriter(OFile)
	OFileW.WriteString("greyIP,Count\r\n")

	//sort our map by values (descending)
	sorted = sortMapByValue(ipCount)

	for x := range sorted {
		OFileW.WriteString(fmt.Sprintf("%s, %d\r\n", sorted[x].Key, sorted[x].Value))
	}

	OFileW.Flush()
	OFile.Close()
	//end ip

	//domains
	OFile, err = os.Create("greyDomains.csv")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create greyDomains.csv\r\n")
		return
	}
	OFileW = bufio.NewWriter(OFile)
	OFileW.WriteString("greyDomains,Count\r\n")

	//sort our map by values (descending)
	sorted = sortMapByValue(domainCount)

	for x := range sorted {
		OFileW.WriteString(fmt.Sprintf("%s, %d\r\n", sorted[x].Key, sorted[x].Value))
	}

	OFileW.Flush()
	OFile.Close()
	//end domains

	//senders
	OFile, err = os.Create("greySenders.csv")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create greySenders.csv\r\n")
		return
	}
	OFileW = bufio.NewWriter(OFile)
	OFileW.WriteString("greySenders,Count\r\n")

	//sort our map by values (descending)
	sorted = sortMapByValue(senderCount)

	for x := range sorted {
		OFileW.WriteString(fmt.Sprintf("%s, %d\r\n", sorted[x].Key, sorted[x].Value))
	}

	OFileW.Flush()
	OFile.Close()
	//end senders

	//email
	OFile, err = os.Create("greyEmail.csv")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create greyEmail.csv\r\n")
		return
	}
	OFileW = bufio.NewWriter(OFile)
	OFileW.WriteString("greyEmail,Count\r\n")

	//sort our map by values (descending)
	sorted = sortMapByValue(emailCount)

	for x := range sorted {
		OFileW.WriteString(fmt.Sprintf("%s, %d\r\n", sorted[x].Key, sorted[x].Value))
	}

	OFileW.Flush()
	OFile.Close()
	//end email

	//recipient
	OFile, err = os.Create("greyRecip.csv")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create greyRecip.csv\r\n")
		return
	}
	OFileW = bufio.NewWriter(OFile)
	OFileW.WriteString("greyRecip,Count\r\n")

	//sort our map by values (descending)
	sorted = sortMapByValue(recipCount)

	for x := range sorted {
		OFileW.WriteString(fmt.Sprintf("%s, %d\r\n", sorted[x].Key, sorted[x].Value))
	}

	OFileW.Flush()
	OFile.Close()
	//end recipient

	/*greyparse */
	//DOMAIN
	OFile, err = os.Create("GREYDOM.csv")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create GREYDOM.csv\r\n")
		return
	}
	OFileW = bufio.NewWriter(OFile)

	//sort our map by values (descending)
	sorted = sortMapByValue(domainCount)

	for x := range sorted {
		OFileW.WriteString(fmt.Sprintf("GREYDOM,%s\r\n", sorted[x].Key))
	}

	OFileW.Flush()
	OFile.Close()
	//end DOMAIN

	//SENDER
	OFile, err = os.Create("GREYSENDER.csv")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create GREYSENDER.csv\r\n")
		return
	}
	OFileW = bufio.NewWriter(OFile)

	//sort our map by values (descending)
	sorted = sortMapByValue(senderCount)

	for x := range sorted {
		OFileW.WriteString(fmt.Sprintf("GREYSENDER,%s\r\n", sorted[x].Key))
	}

	OFileW.Flush()
	OFile.Close()
	//end SENDER

	//REVIEW
	OFile, err = os.Create("GREYREVIEW.csv")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create GREYREVIEW.csv\r\n")
		return
	}
	OFileW = bufio.NewWriter(OFile)

	//sort our map by values (descending)
	sorted = sortMapByValue(reviewCount)

	for x := range sorted {
		OFileW.WriteString(fmt.Sprintf("N,%s\r\n", sorted[x].Key))
	}

	OFileW.Flush()
	OFile.Close()
	//end REVIEW

}
