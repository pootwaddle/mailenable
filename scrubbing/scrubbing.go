package scrubbing

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/dimchansky/utfbom"
)

// Scrubbers is our struct to hold the scrubbing criteria
type Scrubbers struct {
	Cleanit    [][]string
	Recipients map[string]int
	TLDs       map[string]int
	Domains    map[string]int
	Senders    map[string]int
	Hamdoms    map[string]int
	IPs        map[string]int
	Exceptions map[string]int
	PhrasesMap map[string]int
	Phrases    []string
}

func (s *Scrubbers) New(path string) {
	s.loadCSVfile(path)
	s.loadMaps()
}

func (s *Scrubbers) loadCSVfile(path string) {
	byteData, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open %s - %s\n", path, err)
		os.Exit(1)
	}

	// just skip BOM
	iFile, err := ioutil.ReadAll(utfbom.SkipOnly(bytes.NewReader(byteData)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error skipping BOM  %s\n", err)
		os.Exit(1)
	}

	iFile = bytes.Replace(iFile, []byte("\r"), []byte(""), -1)

	l1 := strings.Split(string(iFile), "\n")

	for _, line := range l1 {
		line := strings.Trim(line, " ")
		if line != "" {
			fields := strings.Split(line, ",")

			if len(fields) == 2 {
				s.Cleanit = append(s.Cleanit, fields)
			}
		}
	}
}

func (s *Scrubbers) loadMaps() {
	s.Recipients = make(map[string]int)
	s.TLDs = make(map[string]int)
	s.IPs = make(map[string]int)
	s.Senders = make(map[string]int)
	s.Domains = make(map[string]int)
	s.Hamdoms = make(map[string]int)
	s.Exceptions = make(map[string]int)
	s.PhrasesMap = make(map[string]int)
	for _, y := range s.Cleanit {
		y[0] = strings.Trim(strings.ToUpper(y[0]), " ")
		y[1] = strings.Trim(strings.ToLower(y[1]), " ")
		switch y[0] {
		case "RECIP":
			s.Recipients[y[1]]++
		case "TLD":
			s.TLDs[y[1]]++
		case "IP":
			s.IPs[y[1]]++
		case "SENDER":
			s.Senders[y[1]]++
		case "DOMAIN":
			s.Domains[y[1]]++
		case "HAMDOM":
			s.Hamdoms[y[1]]++
		case "EXCEPT":
			s.Exceptions[y[1]]++
		case "PHRASES":
			s.PhrasesMap[y[1]]++
		default:
			fmt.Println(fmt.Sprintf("%s doesn't match (%s)", y[0], y[1]))
		}
	}

	for k, _ := range s.PhrasesMap {
		s.Phrases = append(s.Phrases, k) //Phrases is slice, not a map...
	}
}

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

// our struct to hold the parsed parts of the (greylist) file name, the major portions of which are space-separated.
type GreyRec struct {
	Sequence      string
	Filename      string
	IP            string
	SenderEmail   string
	Recipient     string
	Sender        string
	Domain        string
	TLD           string
	DomainLessTLD string
	Exception     bool
	Reasons       []string
	Exceptions    []string
	Trail         string
}

func (g *GreyRec) SplitRecord() {
	parts := strings.Split(strings.ToLower(g.Filename), " ")

	g.IP = strings.Trim(parts[0], " ")
	g.SenderEmail = strings.Trim(parts[1], " ")
	g.Recipient = strings.Trim(parts[2], " ")

	if len(g.Recipient) > 4 && strings.Index(g.Recipient, ".tab") >= 0 {
		g.Recipient = g.Recipient[:strings.Index(g.Recipient, ".tab")] //Recipient is the 3rd part of the file name, includes .tab
	}

	g.Sender = strings.Trim(strings.Split(g.SenderEmail, "@")[0], " ")
	g.Domain = strings.Trim(strings.Split(g.SenderEmail, "@")[1], " ") //Domain, including .TLD
	g.TLD = strings.Trim(g.Domain[strings.LastIndex(g.Domain, "."):], " ")
	g.DomainLessTLD = strings.Trim(g.Domain[:strings.LastIndex(g.Domain, ".")], " ")
}

func (g *GreyRec) ScrubRecord(scrub *Scrubbers) {
	g.Exception = false

	// check our Exceptions
	g.CheckHAMdom(scrub)
	g.CheckException(scrub)

	if g.Exception {
		return
	}

	// check the spam Reasons
	g.CheckRecipient(scrub)
	g.CheckSender(scrub)
	g.CheckDomain(scrub)
	g.CheckAllDigits(scrub)
	g.CheckTLD(scrub)
	g.CheckIP(scrub)
	g.CheckPhrasesDomain(scrub)
	g.CheckPhrasesSender(scrub)
}

func (g *GreyRec) CheckHAMdom(scrub *Scrubbers) {
	//in our hamdom map? then mark this as an Exception to all the other rules
	if scrub.Hamdoms[g.Domain] != 0 {
		g.Exception = true
		g.Exceptions = append(g.Exceptions, "HAMDOM")
		fmt.Printf("HAMDOM Exception %s\n", g.Domain)
	}
}

func (g *GreyRec) CheckException(scrub *Scrubbers) {
	//in our Exception map?  this is an email Sender that we want to allow
	if scrub.Exceptions[g.SenderEmail] != 0 {
		g.Exception = true
		g.Exceptions = append(g.Exceptions, "EMAIL")
		fmt.Printf("Sender email Exception - %s\n", g.SenderEmail)
	}
}

func (g *GreyRec) CheckRecipient(scrub *Scrubbers) {
	//in our Honeypot of Recipients?
	if scrub.Recipients[g.Recipient] != 0 {
		fmt.Printf(" RECIP MATCH: %s\n", g.Recipient)
		g.Reasons = append(g.Reasons, "RECIP:"+g.Recipient)
		g.Trail += "R"
	}
}

func (g *GreyRec) CheckSender(scrub *Scrubbers) {
	//in our map of Sender names?
	if scrub.Senders[g.Sender] != 0 {
		fmt.Printf("Sender MATCH: %s\n", g.Sender)
		g.Reasons = append(g.Reasons, "Sender:"+g.Sender)
		g.Trail += "S"
	}
}

func (g *GreyRec) CheckDomain(scrub *Scrubbers) {
	//in our map of Domains (example.com))
	if scrub.Domains[g.Domain] != 0 {
		fmt.Printf("Domain MATCH: %s\n", g.Domain)
		g.Reasons = append(g.Reasons, "Domain:"+g.Domain)
		g.Trail += "D1"
	}
}

func (g *GreyRec) CheckAllDigits(scrub *Scrubbers) {
	//I want to mark Domains that are all digits as spam, so if my DomainLessTLD is ""
	//after filtering it , then mark it as spam....
	if filter(g.DomainLessTLD, AllCharsLessDigits) == "" {
		fmt.Printf("Domain ALL DIGITS: %s\n", g.Domain)
		g.Reasons = append(g.Reasons, "DIGITS:"+g.Domain)
		g.Trail += "D2"
	}
}

func (g *GreyRec) CheckTLD(scrub *Scrubbers) {
	// in our map of TLDs?
	if scrub.TLDs[g.TLD] != 0 {
		fmt.Printf("   TLD MATCH: %s\n", g.TLD)
		g.Reasons = append(g.Reasons, "TLD:"+g.TLD)
		g.Trail += "T"
	}
}

func (g *GreyRec) CheckIP(scrub *Scrubbers) {
	// in our map of IPs?
	if scrub.IPs[g.IP] != 0 {
		fmt.Printf("    IP MATCH: %s\n", g.IP)
		g.Reasons = append(g.Reasons, "IP:"+g.IP)
		g.Trail += "I"
	}
}

func (g *GreyRec) CheckPhrasesDomain(scrub *Scrubbers) {
	for _, val := range scrub.Phrases {
		if strings.Contains(g.Domain, val) {
			fmt.Printf("Domain Contains: %s\n", val)
			g.Reasons = append(g.Reasons, "PHRASE(Domain):"+val)
			g.Trail += "Pd"
		}
	}
}

func (g *GreyRec) CheckPhrasesSender(scrub *Scrubbers) {
	for _, val := range scrub.Phrases {
		if strings.Contains(g.Sender, val) {
			fmt.Printf("Sender Contains: %s\n", val)
			g.Reasons = append(g.Reasons, "PHRASE(Sender):"+val)
			g.Trail += "Ps"
		}
	}
}

func (g *GreyRec) MoveFileToSpam() {
	if len(g.Reasons) > 0 {
		err := os.Rename(g.Filename, "C:\\GG\\"+g.Filename+" SEQ"+g.Sequence+".spm")
		if err != nil {
			fmt.Println(err)
			//return
		}
	}
}