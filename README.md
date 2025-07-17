# Snmp.sh

**All in one SNMP Enumeration Tool**

A tool that I made for CTFs when SNMP is up. it will autodetect the snmp version, do a scan of the mibs and make a folder with all the txt with leaked information about the target. it  Enumerates MIBs using various tools on from the Kali repo.

Requirements:
- `snmpwalk`
- `snmpbulkwalk`
- `snmpget`
- `snmpset`
- `snmp-mibs-downloader`
- `jq`
- `parallel`

In  `/etc/snmp/snmp.conf`

- please ensure that **mibs** is commented.

Example:
```
# As the snmp packages come without MIB files due to license reasons, loading
# of MIBs is disabled by default. If you added the MIBs you can reenable
# loading them by commenting out the following line.
#mibs :
```

Usage example (which works most of the time for CTFs when Snmp is open):

```
Examples:
  # Basic scan, autodetect version and string and scan using mibs directly
  snmp.sh -t 10.10.10.100 --extras

**Options**

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




