// MULTICHKK - 
// multichkk.go is a multithreaded implementation of chkk.
// Some, but minimal performance gains might be gotten from using this multi-threaded code.
// Performance gains will be more apparent on many-cored, low-powered processors. Like those new ARM chips in android phones.

// My main purpose is to prove to myself that I can do multi-threaded programming correctly. multichkk.go satisfied that.
// I am pondering ways to improve performance, especially in a way which does not require too much ram usage.

// Notes from chkk.go: I'm sure programs already exist to do this, but this is my implementation of a hash-based integrity checker for downloaded binaries, to encourage me to double check more often. - vkraven
// 
// Version 0.3 - Multichkk.go with informative fails, pooling, smartchkk and multithreading
// 		SmartChkk allows the checksums to be generated only when required. This makes chkk perform better on mobile or embedded chips checking the integrity of larger files. 
//		SmartChkk also implements a smarter way to parse checksum files. Now chkk scans by words on a newline sentence, instead of by sentence line.

//		Go runs in parallel by default
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
	// Generate multiple copies in memory so summing can occur in parallel
	shainfo := sha256.New()
	shaone:= sha1.New()
	mdee5 := md5.New()

	// Use Go's cool multiwriter functionality to prepare the crypto packages for all 3 checksums at once.
	// NOTE:	This resulted in significant performance gains. Go has optimised code here. Basically a tee.
	// 			Using io also means it doesn't have to be loaded into memory. Critical for large-sized files.
	w := io.MultiWriter(shainfo, shaone, mdee5)
	if _, err := io.Copy(w, fileinput); err != nil {
		log.Fatal(err)
	}

	// SmartChkk - Prepare the checksum functions. These functions will be called ONLY IF chkk identifies possible 
	// SHA256/SHA1/MD5 hashes. In other words, they are "lazily" executed. This is more efficient.
	generatesha256 := func() {
		data = shainfo.Sum(nil)
		data1 = hex.EncodeToString(data)
	}

	generatesha1 := func() {
		deeone = shaone.Sum(nil)
		dee1 = hex.EncodeToString(deeone)
	}

	generatemd5 := func() {
		mdeefive = mdee5.Sum(nil)
		dee5 = hex.EncodeToString(mdeefive)
	}

	// Begin to parse and compare.
	// This section involves guessing that the user provided a raw checksum to chkk, and so chkk will not try
	// to open it as if it were a digest file. 
	// NOTE: This is single threaded, as nothing can be gained from multithreading it.
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
	
	// If a validating checksum could not be found, chkk will then assume the user provided a file containing
	// checksums, and parse it using Pooling.
	if any == false {
		comparefile = comparefile + os.Args[2]
		compare, err := os.Open(comparefile)
		// If the operating system fails to open the file for whatever reason, chkk will return this message.
		if err != nil {
			fmt.Printf("%s failed to verify file %s\n", os.Args[2], os.Args[1])
			fmt.Printf("Assuming %s is a checksum-containing text file:\n\tCould not open file %s\n\n", os.Args[2], os.Args[2])
			fmt.Printf("All verification tests failed. ALERT.\n")
			os.Exit(2)
		}

		defer compare.Close()
		
		// Pooling - The key mechanisms of the pooling method are declared here: the Reader/Scanner, the
		// concurrency/parallelism WaitGroups, and the three pools (i.e. buffered Go channels), each able to hold 
		// 1000 potential hashes.
		scanee := bufio.NewScanner(compare)
		var wg sync.WaitGroup
		var ops sync.WaitGroup
		chan256 := make(chan string, 1000)
		chan1 := make(chan string, 1000)
		chand5 := make(chan string, 1000)

		// The pool's functions are defined. This defines how chkk empties the pools.
		pool256 := func(c256 chan string) {
			for { 
				candidate, more := <-c256
				if more {
					if data1 == "" { generatesha256() }
					if strings.ToLower(candidate) == strings.ToLower(data1) {
						fmt.Printf("SHA256:\tPassed.\tHash: %x\n", data)
						mutex.Lock()
						any = true
						mutex.Unlock()
					}
				} else {
//					done256 <- true 			The channels have been replaced with waitgroups, so multichkk will be hash-neutral.
					ops.Done()
					return
				}
			}
		}
		pool1 := func(c1 chan string) {
			for {
				candidate, more := <-c1
				if more {
					if dee1 == "" { generatesha1() }
					if strings.ToLower(candidate) == strings.ToLower(dee1) {
						fmt.Printf("SHA1:\tPassed.\tHash: %x\n", deeone)
						mutex.Lock()
						any = true
						mutex.Unlock()
					}
				} else {
//					done1 <- true
					ops.Done()
					return
				}
			}
		}
		poold5 := func(cd5 chan string) {
			for {
				candidate, more := <-cd5
				if more {
					if dee5 == "" { generatemd5() }
					if strings.ToLower(candidate) == strings.ToLower(dee5) {
						fmt.Printf("MD5:\tPassed.\tHash: %x\n", mdeefive)
						mutex.Lock()
						any = true
						mutex.Unlock()
					}
				} else {
//					doned5 <- true
					ops.Done()
					return
				}
			}
		}

		// The parsing function is defined. This explains how chkk fills the pools with potential hashes.
		splitme := func(textline string) {
			defer wg.Done()
			wordlist := strings.FieldsFunc(textline, splitter)
			for _, word := range wordlist {
				length := len(word)
				if length == 64 {
					chan256 <-word
				} else if length == 32 {
					chand5 <-word
				} else if length == 40 {
					chan1 <-word
				}
			}
		}

		// The emptying functions are called concurrently, prior to the filling functions. This way, chkk
		// will be ready to clear the pools as they are simultaneously filled.
		ops.Add(3)
		go pool256(chan256)
		go pool1(chan1)
		go poold5(chand5)
		// The filling function is then called.
		for scanee.Scan() {
			thisline := scanee.Text()
	//		fmt.Println(thisline)
			wg.Add(1)
			go splitme(thisline)
		}
		// Wait for the whole checksum file to be fully scanned before closing the channels. I.e. no more filling will occur.
		wg.Wait()
		close(chan256)
		close(chand5)
		close(chan1)
		// Wait for all three pools to empty.
		ops.Wait()

		noexist := func() bool {
			return data1 == "" && dee1 == "" && dee5 == ""
		}
		// If no checksum ever verified the file, return a simple no match fail message. If no valid checksum was even found, return
		// a message indicating so.
		if any == false && noexist() {
			fmt.Printf("No valid checksums were provided. All verification tests failed. ALERT.\n")
		} else if any == false {
			fmt.Printf("No matching checksums found. All verification tests failed. ALERT.\n")
		}
	} else { os.Exit(0) }
}


/*
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
		} */

