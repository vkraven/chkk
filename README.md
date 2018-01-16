# Introducing chkk
A checksummer tool written in Go, meant to be extremely simple to use.
It was originally intended to encourage me to check the integrity of my downloads more often (and it has!).

## Usage
From the command line, enter:
```
chkk <File to be checked> <Hash checksum>
```

chkk takes both a hex-formatted string (the jumbled code that developers usually provide beside their download links) and a file containing hex-formatted strings. For example:
```
chkk LibreOffice_5.4.4_Linux_x86-64_deb.tar.gz b7dd2cf3a595a3b5ea70ecc36029c2090bb64e54
```
Or:
```
chkk LibreOffice_5.4.4_Linux_x86-64_deb.tar.gz checksumfile.txt
```

For now, chkk supports MD5, SHA1 and SHA256 checksums.

## Installation
chkk is written in Go lang, which has extensive OS and microarchitecture support. If Go is already installed on your computer, execute the following instruction to build chkk:
```
go build chkk.go
```

On Linux and most Unix-like OSes, adding the new binary to your PATH will allow it to be run from anywhere in bash. For instance:
```
sudo cp chkk /usr/local/bin/
```

## Conclusion
Hope it helps!
