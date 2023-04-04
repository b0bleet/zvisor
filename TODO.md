## Tasks for ScanEngine
1. Python üzərində thread yaratdığımız zaman daemon arqumenti istifadə edirik pythonun threading dokumentasiyasına istinadən bildirilir ki bu şəkildə worker thread-ləri shutdown etmək
düzgün variant deyil:
```
Daemon threads are abruptly stopped at shutdown. Their resources (such as open files, database transactions, etc.) may not be released properly. 
If you want your threads to stop gracefully, make them non-daemonic and use a suitable signalling mechanism such as an Event.
```
Ona görədə worker thread-lər üzərində event məntiqinin implementasiyası edilməlidir və bunun üçün unit test yazılmalıdır.

2. Hal hazırda Nuclei scanner DAST scanner olaraq implementasiya edilib həmçinin bizə DNS subdomain scanner implementasiyası lazımdır hal hazırda. 
Bunun üçün red-team tərəfindən uyğun tool adını alıb implementasiya etmək lazımdır. Bununla yanaşı aşağıdaki NetScan və DAST scanner toollar implementasiya edilə bilər.v

NetScan kateqoriyasında implementasiya edilə biləcək toollar:
1. https://github.com/darkoperator/dnsrecon
2. https://github.com/gitleaks/gitleaks
3. https://github.com/smicallef/spiderfoot
4. https://github.com/rbsec/sslscan

Kateqoriyalar üzrə:
#### Recon/Sub-domain Enumeration
```
Massdns
Sublist3r
AMass
Subfinder
Dnscan
crt.sh
Censys
Project Sonar
AltDNS
DNSGen
Spoofcheck.py
Hunter.io
```

3. Aşağıda qeyd edilən inteqrasiyaların əlavasi:
```
OWASP ZAP integration
Shodan API integration
Censys API integration
Hunter.io API integration
Metasploit integration
Nessus integration
OpenVAS API integration
WPScan API integration
```
