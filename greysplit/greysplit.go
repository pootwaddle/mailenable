package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

func loadCSVfile(iFilename string) ([][]string, error) {
	var lines [][]string

	iFile, err := ioutil.ReadFile(iFilename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open %s\n", iFilename)
		return lines, err
	}

	iFile = bytes.Replace(iFile, []byte("\r\n"), []byte("\n"), -1)

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

			lines = append(lines, fields)
		}
	}
	return lines, nil
}

func AppendFile(oFilename string, line string) error {
	file, err := os.OpenFile(oFilename, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	len, err := file.WriteString(line + "\n")
	if err != nil {
		return err
	}

	fmt.Printf("\nLength: %d bytes", len)
	fmt.Printf("\nFile Name: %s\n", file.Name())
	return nil
}

func CreateFile(oFilename string) error {
	fmt.Println(oFilename)
	file, err := os.Create(oFilename)
	if err != nil {
		return err
	}
	defer file.Close()

	return nil
}

//CheckCommandLine helps qualify the inbound arguments from
//the DOS command line.  It holds the number of expected arguments
//and if there aren't enough it displays a reminder of what
//arguments are expected for the program calling this.
func CheckCommandLine(expected int, usage string) int {

	if len(os.Args) < expected {
		fmt.Fprintf(os.Stderr, "Too Few Arguments\r\n")
		fmt.Fprintf(os.Stderr, "Expecting: %s %s\r\n", os.Args[0], usage)
		return 1
	}

	finfo, err := os.Stat(os.Args[1]) //by convention, Args[1] will be input filename
	if err != nil {
		// no such file or dir
		fmt.Fprintf(os.Stderr, "%s Not Found\r\n", os.Args[1])
		return 1
	}
	if finfo.IsDir() {
		// it's a Directory
		fmt.Fprintf(os.Stderr, "%s Is Not A File\r\n", os.Args[1])
		return 1
	}
	return 0
} // end CheckCommandLine

func main() {
	if CheckCommandLine(2, "inputfile") != 0 {
		return
	}

	var (
		err         error
		recordCount int = 0
	)

	progName := os.Args[0]                 //executable
	iFileName := filepath.Base(os.Args[1]) //input file
	parsedFileName := strings.TrimSuffix(iFileName, filepath.Ext(iFileName))
	extension := filepath.Ext(iFileName)

	lines, err := loadCSVfile(iFileName)
	if err != nil {
		fmt.Println(err)
		return
	}

	//  filepath.Join("C:/AUTOJOB/" + "cleanit.csv")
	oFileName1 := filepath.Join("C:/AUTOJOB/" + "cleanit.csv")

	fmt.Printf("%s Processing %s  %s  %s  %s\n", progName, iFileName, parsedFileName, oFileName1, extension)

	for _, l := range lines {
		for _, a := range l[0] {
			fmt.Println(string(a))
			switch string(a) {
			case "H":
				AppendFile(oFileName1, "HAMDOM,"+l[3])
				CreateFile(filepath.Join("C:/Program Files (x86)/Mail Enable/Config/Connections/Greylist/Exceptions/" + l[3] + ".tab"))
				//CreateFile(filepath.Join("./Exceptions/" + l[3] + ".tab"))
			case "D":
				AppendFile(oFileName1, "DOMAIN,"+l[3])
			case "S":
				AppendFile(oFileName1, "SENDER,"+l[2])
			case "I":
				AppendFile(oFileName1, "IP,"+l[1])
			case "N":
			}
		}

	}
	fmt.Printf("\nDone. Processed %d records.\n", recordCount)
}
