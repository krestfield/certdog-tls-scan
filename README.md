# Running a TLS Scan

  <br>

This script enables the discovery of TLS certificates from end points and the import into the certdog inventory for management and monitoring.  

Instructions on running this script can be obtained from here:

[https://krestfield.github.io/docs/certdog/tls_scanning.html](https://krestfield.github.io/docs/certdog/tls_scanning.html)

A signed version of the script is available for download from here:

[https://krestfield.s3.eu-west-2.amazonaws.com/certdog/scripts/tls-scan.ps1](https://krestfield.s3.eu-west-2.amazonaws.com/certdog/scripts/tls-scan.ps1)

<br>

Example:

```powershell
tls-scan.ps1 -certdogserver 127.0.0.1 -userid 673de9bcfac0d02ac6ced94d -teamid 473df9bce6c0d02ac6cedd49 -ipstart 192.168.100.1 -ipend 192.168.100.255 -ports (443,80)
Enter API Token: *******
```



