//Example of the file names in the D:/OVERNITE/OFFENDERS folder:
/*
109.236.94~bounce-656-44901464-656-248@no-reply.aqqtq.win~pootwaddle@pootwaddle.com~T~195001024~.x1
109.236.94~bounce-656-44901464-656-248@no-reply.aqqtq.win~pootwaddle@pootwaddle.com~T~195011002~.x1
109.236.94~bounce-656-44901464-656-248@no-reply.aqqtq.win~pootwaddle@pootwaddle.com~T~195021024~.x1
109.236.94~bounce-656-44901464-656-248@no-reply.aqqtq.win~pootwaddle@pootwaddle.com~T~195031024~.x1
109.236.94~bounce-656-44901464-656-248@no-reply.aqqtq.win~pootwaddle@pootwaddle.com~T~195041024~.x1
*/

package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"sort"
	"strings"
)

// our struct to hold the parsed parts of the file name, the major portions of which are tilde-separated.
type em1 struct {
	tld    string
	domain string
	sender string
	fname  string
	email  string
	ip     string
	recip  string
}

type trigger struct {
	Trigger string `json:"trigger"`
	Count   int    `json:"count"`
}

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

	recip := make(map[string]int)        //spamtrap/honeypot recipients map
	tlds := make(map[string]int)         //tld - map
	domains := make(map[string]int)      //domain -- map
	sender_match := make(map[string]int) //sender_match - map
	hamdom := make(map[string]int)       //ham domain - map
	ips := make(map[string]int)          //ip address - map 198.2.30
	phrases := []string{}                //slice used to do substring search
	triggers := make(map[string]int)     //map for holding counts of "triggering" criteria

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

	iFile, err := os.Open("C:\\AUTOJOB\\cleanit.csv")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open %s\r\n", "C:\\AUTOJOB\\cleanit.csv")
		return
	}
	defer iFile.Close()

	iFileScanner := csv.NewReader(iFile)
	iFileScanner.Comma = ','
	iFileScanner.TrimLeadingSpace = true
	iFileScanner.FieldsPerRecord = -1

	fmt.Printf("\r\nInitializing...\r\n")

	for {
		record, err := iFileScanner.Read()
		if err == io.EOF || record[0] == "\x1A" {
			break
		} else if err != nil {
			fmt.Println("Error:", err)
			break
		}

		record[1] = strings.ToLower(record[1])

		switch strings.ToUpper(record[0]) {
		case "RECIP":
			recip[record[1]]++
		case "TLD":
			tlds[record[1]]++
		case "IP":
			ips[record[1]]++
		case "SENDER":
			sender_match[record[1]]++
		case "DOMAIN":
			domains[record[1]]++
		case "HAMDOM":
			hamdom[record[1]]++
		case "PHRASES":
			phrases = append(phrases, record[1]) //phrases is an array, not a map...
		default:
			fmt.Println(fmt.Sprintf("%s doesn't match", record[0]))
		}
	}

	fmt.Printf("Initializing...Done\r\n")
	fmt.Printf(fmt.Sprintf("HAMDOM map contains %d entries\r\n", len(hamdom)))
	fmt.Printf(fmt.Sprintf("SENDER map contains %d entries\r\n", len(sender_match)))
	fmt.Printf(fmt.Sprintf("DOMAINS map contains %d entries\r\n", len(domains)))
	fmt.Printf(fmt.Sprintf("TLD map contains %d entries\r\n", len(tlds)))
	fmt.Printf(fmt.Sprintf("IPS map contains %d entries\r\n", len(ips)))
	fmt.Printf(fmt.Sprintf("RECIP map contains %d entries\r\n", len(recip)))
	fmt.Printf(fmt.Sprintf("PHRASES array contains %d entries\r\n\r\n", len(phrases)))

	var sender em1

	files, err := ioutil.ReadDir(".")
	if err != nil {
		fmt.Println("Directory Read Error:", err)
		os.Exit(1)
	}

	var filecount int
	for x, _ := range files {
		if strings.Contains(files[x].Name(), ".x1") {
			filecount++
		}
	}
	fmt.Printf(fmt.Sprintf("Offenders contains %d entries\r\n\r\n", filecount))

	//Any match to our lists?

	files, err = ioutil.ReadDir(".")
	if err != nil {
		fmt.Println("Directory Read Error:", err)
		os.Exit(1)
	}

	for x, _ := range files {
		reasons := ""
		excpt := false

		if strings.Contains(files[x].Name(), ".x1") {
			sender.fname = files[x].Name()
			parts := strings.Split(files[x].Name(), "~")

			r := parts[2]

			s := parts[1]
			sender.email = s
			sender.domain = strings.Split(s, "@")[1]
			sender.sender = strings.Split(s, "@")[0]
			sender.tld = sender.domain[strings.LastIndex(sender.domain, "."):]
			sender.domain = strings.ToLower(sender.domain)
			sender.sender = strings.ToLower(sender.sender)
			sender.tld = strings.ToLower(sender.tld)
			sender.ip = parts[0]
			sender.recip = r

			if hamdom[sender.domain] != 0 {
				excpt = true
			}

			if recip[sender.recip] != 0 {
				fmt.Println(" RECIP MATCH: ", sender.recip)
				reasons = reasons + "R"
				triggers["R~"+sender.recip]++
			}

			if sender_match[sender.sender] != 0 {
				fmt.Println("SENDER MATCH: ", sender.sender)
				reasons = reasons + "S"
				if !excpt {
					triggers["S~"+sender.sender]++
				}
			}

			if domains[sender.domain] != 0 {
				fmt.Println("DOMAIN MATCH: ", sender.domain)
				reasons = reasons + "D"
				if !excpt {
					triggers["D~"+sender.domain]++
				}
			}

			if tlds[sender.tld] != 0 {
				fmt.Println("   TLD MATCH: ", sender.tld)
				reasons = reasons + "T"
				if !excpt {
					triggers["T~"+sender.tld]++
				}
			}

			if ips[sender.ip] != 0 {
				fmt.Println("    IP MATCH: ", sender.ip)
				reasons = reasons + "I"
				if !excpt {
					triggers["I~"+sender.ip]++
				}
			}

			for _, val := range phrases {
				if strings.Contains(sender.domain, val) {
					fmt.Println("DOMAIN Contains: ", val)
					reasons = reasons + "Pd"
					if !excpt {
						triggers["Pd~"+val]++
					}
				}
				if strings.Contains(sender.sender, val) {
					fmt.Println("SENDER Contains: ", val)
					reasons = reasons + "Ps"
					if !excpt {
						triggers["Ps~"+val]++
					}
				}

			}
			if (reasons != "") && (hamdom[sender.domain] != 0) {
				if !(strings.Contains(reasons, "R")) {
					fmt.Println("EXCEPTION: ", sender.domain)
					fmt.Println(sender.email)
					fmt.Println("")
					reasons = ""
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

	OFile, err := os.Create("SpamReasonCounts.csv")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create SpamReasonCounts.csv\r\n")
		return
	}
	defer OFile.Close()
	OFileW := bufio.NewWriter(OFile)
	OFileW.WriteString("SpamReason,Count\r\n")

	//sort our map by values (descending)
	sorted := sortMapByValue(triggers)

	for x, _ := range sorted {
		OFileW.WriteString(fmt.Sprintf("%5s, %d\r\n", sorted[x].Key, sorted[x].Value))
	}

	OFileW.Flush()

	fmt.Printf("Finished!\r\n\r\n")
}
