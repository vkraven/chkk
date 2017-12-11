// I'm sure programs already exist to do this, but this is my implementation of a hash-based integrity checker for downloaded binaries, to encourage me to double check more often. - vkraven

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
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: chkk <File to be checked> <Hash checksum>\n")
		os.Exit(0)
	}

	file1 := "./"
	if os.Args[1][0] == '/' {
		file1 = os.Args[1]
	} else { file1 = file1 + os.Args[1] }

	fileinput, err := os.Open(file1)
	check(err)
	defer fileinput.Close()

	shainfo := sha256.New()
	if _, err := io.Copy(shainfo, fileinput); err != nil {
		log.Fatal(err)
	}
	data := shainfo.Sum(nil)
	data1 := hex.EncodeToString(data)
	_, err = fileinput.Seek(0,0)
	check(err)

	shaone:= sha1.New()
	if _, err := io.Copy(shaone, fileinput); err != nil {
		log.Fatal(err)
	}

	deeone := shaone.Sum(nil)
	dee1 := hex.EncodeToString(deeone)
//	fmt.Printf("%x\n", deeone)	remnants of debugging
//	fmt.Printf("%s\n", dee1)
	_, err = fileinput.Seek(0,0)
	check(err)

	mdee5 := md5.New()
	if _, err := io.Copy(mdee5, fileinput); err != nil {
		log.Fatal(err)
	}
	mdeefive := mdee5.Sum(nil)
	dee5 := hex.EncodeToString(mdeefive)
//	fmt.Printf("%x\n", mdeefive)	remnants of debugging
//	fmt.Printf("%s\n", dee5)

	any := false
	comparefile := "./"
	if os.Args[2][0] == '/' {
		comparefile = os.Args[2]
	} else if len(os.Args[2]) == 64 {
		if os.Args[2] == data1 {
			fmt.Printf("SHA256:\tPassed.\tHash: %x\n", data)
			any = true
		}
	} else if len(os.Args[2]) == 32 {
		if os.Args[2] == dee5 {
			fmt.Printf("MD5:\tPassed.\tHash: %x\n", mdeefive)
			any = true
		}
	} else if len(os.Args[2]) == 40 {
		if os.Args[2] == dee1 {
			fmt.Printf("SHA1:\tPassed.\tHash: %x\n", deeone)
			any = true
		}
	} 
	
	if any == false {
		comparefile = comparefile + os.Args[2]
		compare, err := os.Open(comparefile)
		check(err)
		defer compare.Close()
		scanee := bufio.NewScanner(compare)
		for scanee.Scan() {
			length := len(scanee.Text())
			if length == 64 {
				if scanee.Text() == data1 {
					fmt.Printf("SHA256:\tPassed.\tHash: %x\n", data)
					any = true
				}
			} else if length == 32 {
				if scanee.Text() == dee5 {
					fmt.Printf("MD5:\tPassed.\tHash: %x\n", mdeefive)
					any = true
				}
			} else if length == 40 {
				if scanee.Text() == dee1 {
					fmt.Printf("SHA1:\tPassed.\tHash: %x\n", deeone)
					any = true
				}
			}
		}
		if any == false {
			fmt.Printf("All verification tests failed. ALERT.\n")
		}
	} else { os.Exit(0) }
}
