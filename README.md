# Scroo Bitcoin Brute Forcer, memcached workaround the memory issue and fixed keygen

A Bitcoin wallet collider that brute forces random wallet addresses from a databases of known addresses

# About This Fork

Workaround for memory usage using memcached. Also fixes/replaces Plutus' keygen 

BEWARE: MANY BUGS MAY YET STILL LURK, please review code carefully before using for production

See the TODO list at the bottom for potential issues

PLEASE NOTE: filldb.py (from pickle files) is no longer supported. filldb-text.py is the way to go using a text file containing the addresses to be tested against.

# About memcached

You will need to download a 64bit version of memcached. 
On windows 10 performance testing showed that memcached 1.4.5 performed better than recent versions (1.6...) taking 3.5mn to test 1 million addresses (instead of 5mn) on a i7-10750h laptop
Thus an older version of memcached seems considerably faster.
Thus at this time on Windows 10 the version of memcached I would recommend can be found at http://downloads.northscale.com/memcached-1.4.5-amd64.zip

# Wanna Support Me?

```
Please consider kind support !

https://ko-fi.com/zanfr

BTC: bc1q5gkn0tln6su3tvwnld7xf7p20fjssaufles47d
ETH: 0xD7A75bF1b64e302ad07b0843A9D295F9a9E3db8E
DOT: 146LV65VWKxM3HsGWNMdjvB3YKg7JHYnRkeX2K3vSTJYxsdB 
```

# Quick Start

```
$ memcached -n 70 -m 5200 -M -t 12
$ python filldb-text.py
$ python scroo.py
```
Note: depending on the current size of the database you may need to adjust the -m option on memcached.

# Proof Of Concept

A private key is a secret number that allows Bitcoins to be spent. If a wallet has Bitcoins in it, then the private key will allow a person to control the wallet and spend whatever balance the wallet has. So this program attempts to find Bitcoin private keys that correlate to wallets with positive balances. However, because it is impossible to know which private keys control wallets with money and which private keys control empty wallets, we have to randomly look at every possible private key that exists and hope to find one that has a balance.

This program is essentially a brute forcing algorithm. It continuously generates random Bitcoin private keys, converts the private keys into their respective wallet addresses, then checks the balance of the addresses. If a wallet with a balance is found, then the private key, public key and wallet address are saved to the text file `plutus.txt` on the user's hard drive. The ultimate goal is to randomly find a wallet with a balance out of the 2<sup>160</sup> possible wallets in existence. 

# Efficiency

The efficiency of scroo has not been tested. You are welcome to post results and improve upon them.
Sanity checks happen against a known address in the database on each thread after 100k requests if it fails the program exits as this may mean a problem with memcached.
Loading from pickles to memcached to slow, this needs to be worked on

# Database FAQ

An offline database is used to find the balance of generated Bitcoin addresses.
Using filldb-text.py you can load a text file (data.txt) with a list of public addresses. (without balance)
Please use responsibly, do not burden servers that list bitcoin addresses by constantly downloading copies of the database. Keep a local copy.

# Expected Output

Every time this program checks the balance of a generated address, it will print the result to the user. If an empty wallet is found, then the wallet address will be printed to the terminal. An example is:

>1Kz2CTvjzkZ3p2BQb5x5DX6GEoHX2jFS45

However, if a wallet with a balance is found, then all necessary information about the wallet will be saved to the text file `plutus.txt`. An example is:

>hex private key: 5A4F3F1CAB44848B2C2C515AE74E9CC487A9982C9DD695810230EA48B1DCEADD<br/>
>WIF private key: 5JW4RCAXDbocFLK9bxqw5cbQwuSn86fpbmz2HhT9nvKMTh68hjm<br/>
>public key: 04393B30BC950F358326062FF28D194A5B28751C1FF2562C02CA4DFB2A864DE63280CC140D0D540EA1A5711D1E519C842684F42445C41CB501B7EA00361699C320<br/>
>address: 1Kz2CTvjzkZ3p2BQb5x5DX6GEoHX2jFS45<br/>

# Memory Consumption

This program uses approximately 4.1GB of RAM (with current database) total + some overhead (about 8 megs) for each core/cpu. 

# Recent Improvements & TODO

- [X] Fixed memory use
- [X] Fixed keygen
- [X] Split database loading from rest of code so "client" machines can now be used by changing connection IP in scroo.py
- [X] Display some stats
- [X] Improve loading times, now supports reading directly for data.txt (expect 3mn to load about 38 million addresses from data.txt)
- [X] Check performance, performance is better with an older version of memcached on Windows. numba doesn't change performance if anything it is slower.
- [X] Fixed sanity checking, see scroo.py and filldb-text.py
- [ ] Ensure proper RAM usage/size for memcached vs database
- [ ] Optimize code
