// I'm sure programs already exist to do this, but this is my implementation of a hash-based integrity checker for downloaded binaries, to encourage me to double check more often. - vkraven
// Version 0.2 - SmartChkk implemented
// 		SmartChkk allows the checksums to be generated only when required. This makes chkk perform better on mobile or embedded chips checking the integrity of larger files. 
//		SmartChkk also implements a smarter way to parse checksum files. Now chkk scans by words on a newline sentence, instead of by sentence line.
package main

import (
	"crypto/sha256"
	"crypto/sha1"
	"crypto/md5"
	"fmt"
	"bufio"
	"os"
	"io"
	"log"
	"encoding/hex"
	"strings"
	"unicode"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func splitter(c rune) bool {
	return !unicode.IsLetter(c) && !unicode.IsNumber(c)
}

func main() {
	// How-to
	if len(os.Args) != 3 {
		fmt.Printf("Usage: chkk <File to be checked> <Hash checksum>\n")
		os.Exit(0)
	}
	
	// Open file to be checked
	file1 := "./"
	if os.Args[1][0] == '/' {
		file1 = os.Args[1]
	} else { file1 = file1 + os.Args[1] }

	fileinput, err := os.Open(file1)
	check(err)
	defer fileinput.Close()
	
	// Generate checksums. SmartChkk will do so lazily
	// Declare vars for smartchkk
	var data []byte
	var deeone []byte
	var mdeefive []byte
	data1 := ""
	dee1 := ""
	dee5 := ""

	generatesha256 := func() {
		shainfo := sha256.New()
		if _, err := io.Copy(shainfo, fileinput); err != nil {
			log.Fatal(err)
		}
		data = shainfo.Sum(nil)
		data1 = hex.EncodeToString(data)
		_, err = fileinput.Seek(0,0)
		check(err)
	}

	generatesha1 := func() {
		shaone:= sha1.New()
		if _, err := io.Copy(shaone, fileinput); err != nil {
			log.Fatal(err)
		}

		deeone = shaone.Sum(nil)
		dee1 = hex.EncodeToString(deeone)
		//	fmt.Printf("%x\n", deeone)	remnants of debugging
		//	fmt.Printf("%s\n", dee1)
		_, err = fileinput.Seek(0,0)
		check(err)
	}

	generatemd5 := func() {
		mdee5 := md5.New()
		if _, err := io.Copy(mdee5, fileinput); err != nil {
			log.Fatal(err)
		}
		mdeefive = mdee5.Sum(nil)
		dee5 = hex.EncodeToString(mdeefive)
		//	fmt.Printf("%x\n", mdeefive)	remnants of debugging
		//	fmt.Printf("%s\n", dee5)
		_, err = fileinput.Seek(0,0)
		check(err)
	}

	any := false
	comparefile := "./"
	if os.Args[2][0] == '/' {
		comparefile = os.Args[2]
	} else if len(os.Args[2]) == 64 {
		if data1 == "" { generatesha256() }
		if strings.ToLower(os.Args[2]) == strings.ToLower(data1) {
			fmt.Printf("SHA256:\tPassed.\tHash: %x\n", data)
			any = true
		}
	} else if len(os.Args[2]) == 32 {
		if dee5 == "" { generatemd5() }
		if strings.ToLower(os.Args[2]) == strings.ToLower(dee5) {
			fmt.Printf("MD5:\tPassed.\tHash: %x\n", mdeefive)
			any = true
		}
	} else if len(os.Args[2]) == 40 {
		if dee1 == "" { generatesha1() }
		if strings.ToLower(os.Args[2]) == strings.ToLower(dee1) {
			fmt.Printf("SHA1:\tPassed.\tHash: %x\n", deeone)
			any = true
		}
	} 
	
	if any == false {
		comparefile = comparefile + os.Args[2]
		compare, err := os.Open(comparefile)
		if err != nil {
			fmt.Printf("%s failed to verify file %s\n", os.Args[2], os.Args[1])
			fmt.Printf("Assuming %s is a checksum-containing text file:\n\tCould not open file %s\n\n", os.Args[2], os.Args[2])
			fmt.Printf("All verification tests failed. ALERT.\n")
			os.Exit(2)
		}
		defer compare.Close()
		scanee := bufio.NewScanner(compare)
		for scanee.Scan() {
			wordlist := strings.FieldsFunc(scanee.Text(), splitter)
		//	fmt.Printf("Fields are: %q\n", wordlist)  remnants of debugging
			for _, word := range wordlist {
		//		fmt.Printf("Current word is %s\n", word) remnants of debugging
				length := len(word)
		//		fmt.Printf("Current word length is %d\n", length) remnants of debugging
				if length == 64 {
					if data1 == "" { generatesha256() }
					if strings.ToLower(word) == strings.ToLower(data1) {
						fmt.Printf("SHA256:\tPassed.\tHash: %x\n", data)
						any = true
					}
				} else if length == 32 {
					if dee5 == "" { generatemd5() }
					if strings.ToLower(word) == strings.ToLower(dee5) {
						fmt.Printf("MD5:\tPassed.\tHash: %x\n", mdeefive)
						any = true
					}
				} else if length == 40 {
					if dee1 == "" { generatesha1() }
					if strings.ToLower(word) == strings.ToLower(dee1) {
						fmt.Printf("SHA1:\tPassed.\tHash: %x\n", deeone)
						any = true
					}
				}
			}
		}
		if any == false {
			fmt.Printf("All verification tests failed. ALERT.\n")
		}
	} else { os.Exit(0) }
}
