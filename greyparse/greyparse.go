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

	"github.com/pootwaddle/scrubbing"
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
	//header record
	//OFileW.WriteString(h + "\r\n")

	//sort our map by values (no counts)
	sorted := sortMapByValue(m)

	for x := range sorted {
		OFileW.WriteString(fmt.Sprintf("%s\r\n", sorted[x].Key))
	}

	OFileW.Flush()
	OFile.Close()
	//end tld
}

func main() {
	var (
		reviewCount = make(map[string]int)
	)

	files, err := ioutil.ReadDir(".")
	if err != nil {
		fmt.Println("directory read error")
		os.Exit(1)
	}

	for x, _ := range files {
		if strings.Contains(files[x].Name(), ".tab") {
			fmt.Println(files[x].Name())

			var greyRecord scrubbing.GreyRec
			greyRecord.Filename = files[x].Name()

			greyRecord.SplitRecord()

			reviewCount["N,"+strings.ToLower(
				greyRecord.IP+","+
					greyRecord.Sender+","+
					greyRecord.Domain+","+
					greyRecord.Recipient)]++
		}
	}
	createFileFromMap(reviewCount, "GREYREVIEW.csv", "")

}
