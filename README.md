<div align="center">

<a href="https://github.com/Keyj33k/WScan/archive/refs/heads/main.zip"><img src="https://github.com/Keyj33k/WScan/blob/main/img/banner.svg" alt="banner"/></a>
  
![version](https://img.shields.io/badge/Version-0.0.2-informational?style=flat&logo=&logoColor=white&color=red) ![stars](https://img.shields.io/github/stars/Keyj33k/WScan?style=social) ![forks](https://img.shields.io/github/forks/Keyj33k/WScan?label=Forks&logo=&logoColor=white&color=blue) ![languages](https://img.shields.io/github/languages/count/Keyj33k/WScan?style=social&logo=&logoColor=white&color=blue) ![issues](https://img.shields.io/github/last-commit/Keyj33k/WScan?style=flat&logo=&logoColor=white&color=blue) ![platform](https://img.shields.io/badge/Platform-Linux/Termux-informational?style=flat&logo=&logoColor=white&color=green) 
  
</div>

## What WScan Will Scan For  
- server details like ipv4/ipv6 addresses, status code, the HTTP header and whois lookup<br>
- all links with the associated status codes<br>
- ipv4 data like country, region, city, lat, lon, timezone etc.<br>
- optional port scanning config with service detection<br>
- scan target server for subdomains


## :rocket: Getting Started: 

1 ) Make sure, you have `python` installed:
```
python3 --version
```
2 ) If it isn't installed (Debian/-based):
```
sudo apt-get install python3
```
3 ) Clone the repository:
```
git clone https://github.com/Keyj33k/WScan.git
```
4 ) Install the needed requirements:
```
pip3 install -r requirements.txt
```
5 ) `Run wscan` using the following command:
```
python3 wscan.py -h
```

## Options/Usage

```                                 
__  _  ________ ____ _____    ____  
\ \/ \/ /  ___// ___\\__  \  /    \ 
 \     /\___ \\  \___ / __ \|   |  \
  \/\_//____  >\___  >____  /___|  /
            \/     \/     \/     \/ 

			Version 0.0.2
+-+-+-+ +-+-+-+-+-+-+ +-+-+-+-+-+-+-+
|W|e|b| |S|e|r|v|e|r| |S|c|a|n|n|e|r|
+-+-+-+ +-+-+-+-+-+-+ +-+-+-+-+-+-+-+

usage: wscan.py [-h] -u target url [-a] [-c] [-r] [-i] [-s] [-w wordlist] [-p] [-f first port] [-l last port]

WScan - Web Server Scanner

options:
  -h, --help            show this help message and exit
  -u target url, --url target url
                        target url ( format=example.com )
  -a, --all             complete scan
  -k, --lookup          whois lookup
  -c, --links           collect links + status codes
  -r, --head            server header
  -i, --ipv4            ipv4 informations
  -s, --sub             scan for subdomains
  -w wordlist, --wordl wordlist
                        wordlist for subdomain scanning ( default for standard wordlist )
  -p, --pscan           port scan
  -f first port, --first first port
                        the first port for port scan if enabled
  -l last port, --last last port
                        the last port for port scan if enabled

examples:
  wscan.py -f 1 -l 100 -a -u example.com
  wscan.py -r -u example.com -i
  wscan.py -u example.com -p -f 50 -l 100
  wscan.py -u example.com -s -w default

```

## 🎬 WScan Example
<div align="center">
  
![demo](https://github.com/Keyj33k/WScan/blob/main/img/wscan_example.png?raw=true)
  
</div>

## Feedback And Bug Report

If you found a bug, or wanna start a discussion, please use ![Github issues](https://github.com/Keyj33k/WScan/issues). You are also invited to <br>
send an email to the following address: `K3yjeek@proton.me`

## LICENSE
```
Copyright (c) 2022 Keyjeek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

<div align="center">

### Tested on 5.15.0-48-generic-Ubuntu

</div>

---
