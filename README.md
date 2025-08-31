# guardian htb

### https://app.hackthebox.com/machines/Guardian

```
Hexada@hexada ~/Downloads$ nmap -sC -sV -Pn -T5 --max-rate 10000 10.10.11.84 -oN guardian.htb                                                              130 ↵  
Starting Nmap 7.97 ( https://nmap.org ) at 2025-08-30 22:13 +0300
Warning: 10.10.11.84 giving up on port because retransmission cap hit (2).
Nmap scan report for guardian.htb (10.10.11.84)
Host is up (0.066s latency).
Not shown: 543 closed tcp ports (conn-refused), 455 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 9c:69:53:e1:38:3b:de:cd:42:0a:c8:6b:f8:95:b3:62 (ECDSA)
|_  256 3c:aa:b9:be:17:2d:5e:99:cc:ff:e1:91:90:38:b7:39 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Guardian University - Empowering Future Leaders
Service Info: Host: _default_; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 117.37 seconds
```


<img width="1635" height="649" alt="image" src="https://github.com/user-attachments/assets/d59ad7ca-e38c-46a5-b179-29199967da1b" />

```
Hexada@hexada ~/pentest-env/vrm/Guardian.htb/xlsx-payload/xl$ ffuf -u http://guardian.htb/ -H "Host: FUZZ.guardian.htb" -w /home/Hexada/pentest-env/pentesting-wordlists/2m-subdomains.txt -mc 403,302,200 -t 150 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://guardian.htb/
 :: Wordlist         : FUZZ: /home/Hexada/pentest-env/pentesting-wordlists/2m-subdomains.txt
 :: Header           : Host: FUZZ.guardian.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 150
 :: Matcher          : Response status: 403,302,200
________________________________________________

portal                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 115ms]
gitea                   [Status: 200, Size: 13498, Words: 1049, Lines: 245, Duration: 72ms]
```

<img width="1716" height="980" alt="image" src="https://github.com/user-attachments/assets/c0b1f588-bd81-46b2-bbe6-7339186b932d" />

<img width="1398" height="980" alt="image" src="https://github.com/user-attachments/assets/fa0a0513-d643-49b8-9193-609e74c2d225" />

GU0142023:GU0142023

GU0142023

<img width="1651" height="394" alt="image" src="https://github.com/user-attachments/assets/54aa450b-4b34-4e43-ad97-fa84b8e15e71" />

```html
<option value="1">admin</option>
<option value="2">jamil.enockson</option>
<option value="3">mark.pargetter</option>
<option value="4">valentijn.temby</option>
<option value="5">leyla.rippin</option>
<option value="6">perkin.fillon</option>
<option value="7">cyrus.booth</option>
<option value="8">sammy.treat</option>
<option value="9">crin.hambidge</option>
<option value="10">myra.galsworthy</option>
<option value="12">vivie.smallthwaite</option>
<option value="15">GU0702025</option>
<option value="16">GU0762023</option>
<option value="17">GU9492024</option>
<option value="18">GU9612024</option>
<option value="19">GU7382024</option>
<option value="20">GU6632023</option>
<option value="21">GU1922024</option>
<option value="22">GU8032023</option>
<option value="23">GU5852023</option>
<option value="24">GU0712023</option>
<option value="25">GU1592025</option>
<option value="26">GU1112023</option>
<option value="27">GU6432025</option>
<option value="28">GU3042024</option>
<option value="29">GU1482025</option>
<option value="30">GU3102024</option>
<option value="31">GU7232023</option>
<option value="32">GU8912024</option>
<option value="33">GU4752025</option>
<option value="34">GU9602024</option>
<option value="35">GU4382025</option>
<option value="36">GU7352023</option>
<option value="37">GU3042025</option>
<option value="38">GU3872024</option>
<option value="39">GU7462025</option>
<option value="40">GU3902023</option>
<option value="41">GU1832025</option>
<option value="42">GU3052024</option>
<option value="43">GU3612023</option>
<option value="44">GU7022023</option>
<option value="45">GU1712025</option>
<option value="46">GU9362023</option>
<option value="47">GU5092024</option>
<option value="48">GU5252023</option>
<option value="49">GU8802025</option>
<option value="50">GU2222023</option>
<option value="51">GU9802023</option>
<option value="52">GU3122025</option>
<option value="53">GU2062025</option>
<option value="54">GU3992025</option>
<option value="55">GU1662024</option>
<option value="56">GU9972025</option>
<option value="57">GU6822025</option>
<option value="58">GU7912023</option>
<option value="59">GU3622024</option>
<option value="60">GU2002023</option>
<option value="61">GU3052023</option>
<option value="62">GU1462023</option>
```

<img width="1644" height="559" alt="image" src="https://github.com/user-attachments/assets/e94620df-0a16-4035-878c-9f10fab4a7fd" />

<img width="594" height="391" alt="image" src="https://github.com/user-attachments/assets/bed113e5-464d-4120-a145-3591b578361f" />

<img width="1843" height="916" alt="image" src="https://github.com/user-attachments/assets/3ad67c7d-0389-40b9-aae2-0f45e77d34fa" />



