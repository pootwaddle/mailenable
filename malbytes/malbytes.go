package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"time"
)

type blocked struct {
	ApplicationVersion             string    `json:"applicationVersion"`
	ClientID                       string    `json:"clientID"`
	ClientType                     string    `json:"clientType"`
	ComponentsUpdatePackageVersion string    `json:"componentsUpdatePackageVersion"`
	CPU                            string    `json:"cpu"`
	DbSDKUpdatePackageVersion      string    `json:"dbSDKUpdatePackageVersion"`
	DetectionDateTime              time.Time `json:"detectionDateTime"`
	FileSystem                     string    `json:"fileSystem"`
	ID                             string    `json:"id"`
	IsUserAdmin                    bool      `json:"isUserAdmin"`
	LicenseState                   string    `json:"licenseState"`
	LinkagePhaseComplete           bool      `json:"linkagePhaseComplete"`
	LoggedOnUserName               string    `json:"loggedOnUserName"`
	MachineID                      string    `json:"machineID"`
	Os                             string    `json:"os"`
	SchemaVersion                  int       `json:"schemaVersion"`
	SourceDetails                  struct {
		Type string `json:"type"`
	} `json:"sourceDetails"`
	Threats []struct {
		LinkedTraces []interface{} `json:"linkedTraces"`
		MainTrace    struct {
			CleanAction                  string `json:"cleanAction"`
			CleanResult                  string `json:"cleanResult"`
			CleanResultErrorCode         int    `json:"cleanResultErrorCode"`
			CleanTime                    string `json:"cleanTime"`
			GeneratedByPostCleanupAction bool   `json:"generatedByPostCleanupAction"`
			ID                           string `json:"id"`
			LinkType                     string `json:"linkType"`
			ObjectMD5                    string `json:"objectMD5"`
			ObjectPath                   string `json:"objectPath"`
			ObjectSha256                 string `json:"objectSha256"`
			ObjectType                   string `json:"objectType"`
			WebsiteData                  struct {
				BlockType   int    `json:"blockType"`
				IP          string `json:"ip"`
				IsInbound   bool   `json:"isInbound"`
				Port        int    `json:"port"`
				ProcessPath string `json:"processPath"`
				URL         string `json:"url"`
			} `json:"websiteData"`
		} `json:"mainTrace"`
		RuleID       int    `json:"ruleID"`
		RulesVersion string `json:"rulesVersion"`
		ThreatID     int    `json:"threatID"`
		ThreatName   string `json:"threatName"`
	} `json:"threats"`
	ThreatsDetected int `json:"threatsDetected"`
}

func loadFile(fileName string) ([]byte, error) {
	content, err := ioutil.ReadFile(fileName)
	if err != nil {
		fmt.Println("loadFile ReadFile error - " + fileName)
		return nil, err
	}

	content = bytes.Replace(content, []byte("\r\n"), []byte("\n"), -1)
	return content, nil
}

func checkCommandLine(expected int, usage string) error {

	if len(os.Args) < expected {
		fmt.Fprintf(os.Stderr, "Too Few Arguments\r\n")
		fmt.Fprintf(os.Stderr, "Expecting: %s %s\r\n", os.Args[0], usage)
		return errors.New(fmt.Sprintf("Expecting: %s %s\r\n", os.Args[0], usage))
	}

	finfo, err := os.Stat(os.Args[1]) //by convention, Args[1] will be input filename
	if err != nil {
		// no such file or dir
		fmt.Fprintf(os.Stderr, "%s Not Found\r\n", os.Args[1])
		return err
	}
	if finfo.IsDir() {
		// it's a Directory
		fmt.Fprintf(os.Stderr, "%s Is Not A File\r\n", os.Args[1])
		return errors.New(fmt.Sprintf("%s is not a file.\r\n", os.Args[1]))
	}
	return nil
}

func main() {

	err := checkCommandLine(2, "<filename>")
	if err != nil {
		os.Exit(1)
	}

	content, err := loadFile(os.Args[1])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	startpos := bytes.Index(content, []byte("{"))

	badweb := blocked{}
	err = json.Unmarshal(content[startpos:], &badweb)
	if err != nil {
		panic(err)
	}

	if len(badweb.Threats) > 0 {
		fmt.Println(fmt.Sprintf("IP,%s", badweb.Threats[0].MainTrace.WebsiteData.IP))
	}
}
