> Author: Ph0Jav7
> Keywords：PHP, DataCube3, Shell Code Injection

# Product Description

The DataCube3 from [F-logic](https://www.f-logic.jp/) is a compact terminal measurement system for photovoltaic power generation systems.

![product](https://github.com/Yang-Nankai/Vulnerabilities/blob/main/Pasted%20image%2020240503010448.png)

# Affected Products

All F-logic DataCube3 measurement system version 1.0.

![product-version](https://github.com/Yang-Nankai/Vulnerabilities/blob/main/Pasted%20image%2020240503010620.png)

# Vulnerability Summary

Shell Code Injection

DataCube3 is affected by a command execution injection vulnerability, where file upload allows unauthenticated malicious actors to perform command injection attacks by manipulating the file name. Successful exploitation of the vulnerability could allow an attacker to upload a file with a PHP webshell leading to an RCE (Remote Code Execution) vulnerability. This issue affects all DataCube3 appliances version 1.0.

# Reproduction Steps

There is a command injection vulnerability in `/admin/transceiver_schedule.php` that does not require authentication. The uploaded file name is not filtered and the file name is concatenated during execution, so command injection can be performed through this vulnerability. In the example, we will show how to exploit the command injection in the file name and write a minimal PHP WebShell.

![burpsuite](https://github.com/Yang-Nankai/Vulnerabilities/blob/main/Pasted%20image%2020240503012751.png)

Then visit `/admin/flag.php` and you will find that the webshell has been written successfully.

![shell](https://github.com/Yang-Nankai/Vulnerabilities/blob/main/Pasted%20image%2020240503012943.png)

# Recommendation Fixes / Remediation

Escape command injection splicing and ensure that all requests sent to the backend are authenticated.

# Vulnerable Devices Found

As of 2 May 2024, there were 328 F-logic DataCube3 devices exposed to the internet and were affected by the vulnerabilities discovered.

![fofa](https://github.com/Yang-Nankai/Vulnerabilities/blob/main/Pasted%20image%2020240503013439.png)

# References

[https://www.f-logic.jp](https://www.f-logic.jp/)

[https://www.f-logic.jp/pdf/support/manual_product/manual_product_datacube3_ver1.0_sc.pdf](https://www.f-logic.jp/pdf/support/manual_product/manual_product_datacube3_ver1.0_sc.pdf)
