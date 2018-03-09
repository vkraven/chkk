// MULTICHKK - 
// multichkk.go is a multithreaded implementation of chkk.
// Some, but minimal performance gains might be gotten from using this multi-threaded code.
// Performance gains will be more apparent on many-cored, low-powered processors. Like those new ARM chips in android phones.

// My main purpose is to prove to myself that I can do multi-threaded programming correctly. multichkk.go satisfied that.
// I am pondering ways to improve performance, especially in a way which does not require too much ram usage.

// Notes from chkk.go: I'm sure programs already exist to do this, but this is my implementation of a hash-based integrity checker for downloaded binaries, to encourage me to double check more often. - vkraven
// 
// Version 0.1 - Multichkk.go with smartchkk and multithreading
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
	"sync"
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
	var mutex = &sync.Mutex{}
	
	// Generate checksums. SmartChkk will do so lazily
	// Declare vars for smartchkk
	var data []byte
	var deeone []byte
	var mdeefive []byte
	data1 := ""
	dee1 := ""
	dee5 := ""
	// generate multiple copies in memory so summing can occur in parallel
	shainfo := sha256.New()
	
	shaone:= sha1.New()

	mdee5 := md5.New()

	generatesha256 := func() {
		mutex.Lock()
		if _, err := io.Copy(shainfo, fileinput); err != nil {
			log.Fatal(err)
		}
		_, err = fileinput.Seek(0,0)
		check(err)
		mutex.Unlock()
		data = shainfo.Sum(nil)
		data1 = hex.EncodeToString(data)
	}

	generatesha1 := func() {
		mutex.Lock()
		if _, err := io.Copy(shaone, fileinput); err != nil {
			log.Fatal(err)
		}
		_, err = fileinput.Seek(0,0)
		check(err)
		mutex.Unlock()
		deeone = shaone.Sum(nil)
		dee1 = hex.EncodeToString(deeone)
		//	fmt.Printf("%x\n", deeone)	remnants of debugging
		//	fmt.Printf("%s\n", dee1)
	}

	generatemd5 := func() {
		mutex.Lock()
		if _, err := io.Copy(mdee5, fileinput); err != nil {
			log.Fatal(err)
		}
		_, err = fileinput.Seek(0,0)
		check(err)
		mutex.Unlock()
		mdeefive = mdee5.Sum(nil)
		dee5 = hex.EncodeToString(mdeefive)
		//	fmt.Printf("%x\n", mdeefive)	remnants of debugging
		//	fmt.Printf("%s\n", dee5)
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
		var wg sync.WaitGroup
		chan256 := make(chan int, 1)
		chan1 := make(chan int, 1)
		chand5 := make(chan int, 1)
		analyse := func(textline string) {
			defer wg.Done()
			wordlist := strings.FieldsFunc(textline, splitter)
	//		fmt.Printf("Fields are: %q\n", wordlist)
			for _, word := range wordlist {
	//			fmt.Printf("Current word is %s\n", word)
				length := len(word)
	//			fmt.Printf("Current word length is %d\n", length)
				if length == 64 {
					chan256 <-1
					if data1 == "" { generatesha256() }
	//				fmt.Println(data1)
					if strings.ToLower(word) == strings.ToLower(data1) {
						fmt.Printf("SHA256:\tPassed.\tHash: %x\n", data)
						mutex.Lock()
						any = true
	//					fmt.Println("Any has been made true!")
						mutex.Unlock()
					}
					<-chan256
				} else if length == 32 {
					chand5 <-1
					if dee5 == "" { generatemd5() }
	//				fmt.Println(dee5)
					if strings.ToLower(word) == strings.ToLower(dee5) {
						fmt.Printf("MD5:\tPassed.\tHash: %x\n", mdeefive)
						mutex.Lock()
						any = true
	//					fmt.Println("Any has been made true!")
						mutex.Unlock()
					}
					<-chand5
				} else if length == 40 {
					chan1 <-1
					if dee1 == "" { generatesha1() }
	//				fmt.Println(dee1)
					if strings.ToLower(word) == strings.ToLower(dee1) {
						fmt.Printf("SHA1:\tPassed.\tHash: %x\n", deeone)
						mutex.Lock()
						any = true
	//					fmt.Println("Any has been made true!")
						mutex.Unlock()
					}
					<-chan1
				}
			}
	//		fmt.Println("I am decrementing the waitgroup!")
		}
		for scanee.Scan() {
			thisline := scanee.Text()
	//		fmt.Println(thisline)
			wg.Add(1)
			go analyse(thisline)
		}
		wg.Wait()
		close(chan256)
		close(chand5)
		close(chan1)
		if any == false {
			fmt.Printf("All verification tests failed. ALERT.\n")
		}
	} else { os.Exit(0) }
}
