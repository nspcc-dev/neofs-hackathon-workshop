# Practical introduction to NeoFS for N3 Hackathon

This repository contains materials used in practical introduction to NeoFS 
workshop (22 June 2021).

## Extended ACL changer

Extended ACL changer app is located in `neofs-eacl-changer`. To try it 
yourself you need to modify source code:
- specify container ID string,
- specify container owner wallet,
- specify "special" wallet.

Build it with go1.16

```
$ cd neofs-eacl-changer
$ go build -o eacl-changer main.go
$ ./eacl-changer
```