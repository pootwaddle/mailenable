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
		filexCount  = make(map[string]int)
		reasonCount = make(map[string]int)
		spamReview  = make(map[string]int)
	)

	files, err := ioutil.ReadDir(".")
	if err != nil {
		fmt.Println("directory read error")
		os.Exit(1)
	}

	for x, _ := range files {
		if strings.Contains(files[x].Name(), ".x1") {
			parts := strings.Split(strings.ToLower(files[x].Name()), "~")
			if len(parts) == 6 {
				ip := parts[0]
				from := parts[1] //is a string containing email adress
				fromSplit := strings.Split(from, "@")

				sender := fromSplit[0]
				domain := fromSplit[1]
				tld := domain[strings.LastIndex(domain, "."):]
				recip := parts[2]
				reason := parts[3]

				ipCount[ip]++
				tldCount[tld]++
				//			domainCount[domain]++
				senderCount[sender]++
				emailCount[from]++
				recipCount[recip]++
				reasonCount[reason]++
				filexCount[strings.Join(parts[1:], "~")]++
				spamReview[tld+"=="+domain+"=="+reason+"=="+sender+"==>"+recip]++

				if (tld == ".com") || (tld == ".net") || (tld == ".org") {
					domainCount[domain]++
				}

			}
			//	fmt.Println(files[x].Name())
		}
	}

	//filenames
	OFile, err := os.Create("spamlist.txt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create spamlist.txt\r\n")
		return
	}
	OFileW := bufio.NewWriter(OFile)

	for x := range files {
		if strings.Contains(files[x].Name(), ".x1") {
			OFileW.WriteString(files[x].Name() + "\r\n")
		}
	}

	OFileW.Flush()
	OFile.Close()
	//end filenames

	//tld
	OFile, err = os.Create("spamTLD.csv")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create spamTLD.csv\r\n")
		return
	}
	OFileW = bufio.NewWriter(OFile)
	OFileW.WriteString("spamTLD,Count\r\n")

	//sort our map by values (descending)
	sorted := sortMapByValue(tldCount)

	for x := range sorted {
		OFileW.WriteString(fmt.Sprintf("%s, %d\r\n", sorted[x].Key, sorted[x].Value))
	}

	OFileW.Flush()
	OFile.Close()
	//end tld

	//ip
	OFile, err = os.Create("spamIP.csv")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create spamIP.csv\r\n")
		return
	}
	OFileW = bufio.NewWriter(OFile)
	//OFileW.WriteString("spamIP,Count\r\n")

	//sort our map by values (descending)
	sorted = sortMapByValue(ipCount)

	for x := range sorted {
		//OFileW.WriteString(fmt.Sprintf("%s, %d\r\n", sorted[x].Key, sorted[x].Value))
		OFileW.WriteString(fmt.Sprintf("IP,%s\r\n", sorted[x].Key))
	}

	OFileW.Flush()
	OFile.Close()
	//end ip

	//domains
	OFile, err = os.Create("spamDomains.csv")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create spamDomains.csv\r\n")
		return
	}
	OFileW = bufio.NewWriter(OFile)
	OFileW.WriteString("spamDomains,Count\r\n")

	//sort our map by values (descending)
	sorted = sortMapByValue(domainCount)

	for x := range sorted {
		OFileW.WriteString(fmt.Sprintf("%s, %d\r\n", sorted[x].Key, sorted[x].Value))
	}

	OFileW.Flush()
	OFile.Close()
	//end domains

	//senders
	OFile, err = os.Create("spamSenders.csv")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create spamSenders.csv\r\n")
		return
	}
	OFileW = bufio.NewWriter(OFile)
	OFileW.WriteString("spamSenders,Count\r\n")

	//sort our map by values (descending)
	sorted = sortMapByValue(senderCount)

	for x := range sorted {
		OFileW.WriteString(fmt.Sprintf("%s, %d\r\n", sorted[x].Key, sorted[x].Value))
	}

	OFileW.Flush()
	OFile.Close()
	//end senders

	//email
	OFile, err = os.Create("spamEmail.csv")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create spamEmail.csv\r\n")
		return
	}
	OFileW = bufio.NewWriter(OFile)
	OFileW.WriteString("spamEmail,Count\r\n")

	//sort our map by values (descending)
	sorted = sortMapByValue(emailCount)

	for x := range sorted {
		OFileW.WriteString(fmt.Sprintf("%s, %d\r\n", sorted[x].Key, sorted[x].Value))
	}

	OFileW.Flush()
	OFile.Close()
	//end email

	//recipient
	OFile, err = os.Create("spamRecip.csv")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create spamRecip.csv\r\n")
		return
	}
	OFileW = bufio.NewWriter(OFile)
	OFileW.WriteString("spamRecip,Count\r\n")

	//sort our map by values (descending)
	sorted = sortMapByValue(recipCount)

	for x := range sorted {
		OFileW.WriteString(fmt.Sprintf("%s, %d\r\n", sorted[x].Key, sorted[x].Value))
	}

	OFileW.Flush()
	OFile.Close()
	//end recipient

	//reason
	OFile, err = os.Create("spamReason.csv")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create spamReason.csv\r\n")
		return
	}
	OFileW = bufio.NewWriter(OFile)
	OFileW.WriteString("spamReason,Count\r\n")

	//sort our map by values (descending)
	sorted = sortMapByValue(reasonCount)

	for x := range sorted {
		OFileW.WriteString(fmt.Sprintf("%s, %d\r\n", sorted[x].Key, sorted[x].Value))
	}

	OFileW.Flush()
	OFile.Close()
	//end reason

	/*spam parse only (greyparse will be different here) */
	//DOMAIN
	OFile, err = os.Create("DOMAIN.csv")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create DOMAIN.csv\r\n")
		return
	}
	OFileW = bufio.NewWriter(OFile)

	//sort our map by values (descending)
	sorted = sortMapByValue(domainCount)

	for x := range sorted {
		OFileW.WriteString(fmt.Sprintf("DOMAIN,%s\r\n", sorted[x].Key))
	}

	OFileW.Flush()
	OFile.Close()
	//end DOMAIN

	//SENDER
	OFile, err = os.Create("SENDER.csv")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create SENDER.csv\r\n")
		return
	}
	OFileW = bufio.NewWriter(OFile)

	//sort our map by values (descending)
	sorted = sortMapByValue(senderCount)

	for x := range sorted {
		OFileW.WriteString(fmt.Sprintf("SENDER,%s\r\n", sorted[x].Key))
	}

	OFileW.Flush()
	OFile.Close()
	//end SENDER

	//SPAMReview
	OFile, err = os.Create("spamReview.csv")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create spamReview.csv\r\n")
		return
	}
	OFileW = bufio.NewWriter(OFile)

	//sort our map by values (descending)
	sorted = sortMapByValue(filexCount)

	for x := range sorted {
		OFileW.WriteString(fmt.Sprintf("%s\r\n", sorted[x].Key))
	}

	OFileW.Flush()
	OFile.Close()
	//end SPAMReview

	//SPAMReview2
	OFile, err = os.Create("spamReview2.csv")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create spamReview2.csv\r\n")
		return
	}
	OFileW = bufio.NewWriter(OFile)

	//sort our map by values (descending)
	sorted = sortMapByValue(spamReview)

	for x := range sorted {
		OFileW.WriteString(fmt.Sprintf("%s, %d\r\n", sorted[x].Key, sorted[x].Value))
	}

	OFileW.Flush()
	OFile.Close()
	//end SPAMReview
}
