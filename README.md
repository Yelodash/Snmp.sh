# Snmp.sh

All in one SNMP Enumeration Tool that I use for CTFs. it will autodetect the snmp version, do a scan of the mibs and make a folder with all the txt with leaked information about the target.

```
Required:
  -t, --target <IP/HOST>   Target IP or hostname

SNMP Options:
  -c, --community <STR>    SNMP community string (default: public)
  -v, --version <VER>      SNMP version: 1, 2c, or 3 (default: 2c)
  --v3-user <USER>         SNMPv3 username
  --v3-level <LEVEL>       SNMPv3 security level (noAuthNoPriv|authNoPriv|authPriv)
  --v3-auth-proto <PROTO>  SNMPv3 auth protocol (MD5|SHA)
  --v3-auth-pass <PASS>    SNMPv3 auth password
  --v3-priv-proto <PROTO>  SNMPv3 privacy protocol (DES|AES)
  --v3-priv-pass <PASS>    SNMPv3 privacy password

Enumeration Options:
  --brute                  Brute-force community strings
  --wordlist <FILE>        Custom wordlist for brute-force
  --threads <NUM>          Number of threads for parallel operations (default: 10)
  --extras                 Enable extra enumeration modules
  --write-test            Test SNMP write access (DANGEROUS!)

Output Options:
  --output-dir <DIR>       Output directory (default: output)
  --json                   Generate JSON output
  --html                   Generate HTML report
  --verbose               Enable verbose output
```

Usage example:

```
Examples:
  # Basic scan
  /home/blacklotus/Desktop/Scripts/snmp.sh -t 10.10.10.100

  # Comprehensive scan with all features
  /home/blacklotus/Desktop/Scripts/snmp.sh -t 10.10.10.100 --brute --extras --json --html

  # SNMPv3 scan
  /home/blacklotus/Desktop/Scripts/snmp.sh -t 10.10.10.100 -v 3 --v3-user admin --v3-level authPriv \
     --v3-auth-proto SHA --v3-auth-pass MyAuthPass \
     --v3-priv-proto AES --v3-priv-pass MyPrivPass
```
