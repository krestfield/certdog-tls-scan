<#
.DESCRIPTION
    Scans the provided list of IP addresses or server names and imports all discovered certificates
    into the specified certdog server

    An instance of certdog is required. This can be obtained from the following locations:
    * https://krestfield.github.io/docs/certdog/get_certdog.html
    
    The demo version for windows can be found here: 
    * https://krestfield.github.io/docs/certdog/demo_quickstart.html

    The Docker version can be obtained from here:
    * https://hub.docker.com/r/krestfield/certdog


.NOTES
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

.LINK
    https://krestfield.github.io/docs/certdog/tls_scanning.html

.PARAMETER certdogServer
    The hostname or IP address of the certdog server

.PARAMETER userId
    The ID of the user who will be the owner of the imported certificates

.PARAMETER serverList
    A comma separated list of IP addresses or hostnames of the end points to be scanned. Can contain a single server

.PARAMETER ipStart
    If a range of IP addresses is to be scanned, this is the starting IP address
    Requires that ipEnd also be provided\

.PARAMETER ipEnd
    If a range of IP addresses is to be scanned, this is the last IP address
    Requires that ipStart also be provided

.PARAMETER ipAddress
    If the range of IP addresses is provided in CIDR format. This is the IP address
    If subnetMask is ommitted the default of /32 will be used

.PARAMETER subnetMask
    If the range of IP addresses is provided in CIDR format. This is the CIDR mask    

.PARAMETER ignoreSslErrors
    If the certdog server is running a TLS certificate that is not trusted by the server running this script, set this switch to ignore SSL errors

.PARAMETER apiToken
    The API key to authenticate to the certdog server. If not provided the user will be prompted to enter this

.PARAMETER additionalText
    Text that will be saved with the certificate. This text can be searched on once imported.

.EXAMPLE
    tls-scan.ps1 -certdogServer 127.0.0.1 -userId 673de9bcfac0d02ac6ced94d -teamId 573de6bcfac0d02ac6ced934 -serverList google.com

.EXAMPLE
    tls-scan.ps1 -certdogServer 127.0.0.1 -userId 673de9bcfac0d02ac6ced94d -teamId 573de6bcfac0d02ac6ced934 -serverList google.com,amazon.co.uk,microsoft.com

.EXAMPLE
    tls-scan.ps1 -certdogServer 127.0.0.1 -userId 673de9bcfac0d02ac6ced94d -teamId 573de6bcfac0d02ac6ced934 -ipStart 178.54.25.1 -ipEnd 178.54.25.255

.EXAMPLE
    tls-scan.ps1 -certdogServer 127.0.0.1 -userId 673de9bcfac0d02ac6ced94d -teamId 573de6bcfac0d02ac6ced934 -ipAddress 178.54.25.1 -subnetMask 24 -additionalText "SCAN from Network Segment 455"

#>    
param(
        [parameter(Mandatory=$true)]
        [String]$certdogServer,
        [parameter(Mandatory=$true)]
        [String]$userId,
        [parameter(Mandatory=$true)]
        [String]$teamId,
        
        [String]$ipStart,
        [String]$ipEnd,

        [String[]]$serverList,

        [String]$ipAddress,
        [String]$subnetMask,

        [ValidateRange(1,65535)]
        [int32[]]$ports = 443,

        [String]$apiToken,

        [Switch]$ignoreSslErrors,

        [String]$additionalText
)

function Test-TlsProtocols {
    [cmdletbinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Server,
        [ValidateRange(1,65535)]
        [int32[]]$Port = 443,
        [string[]]$ProtocolName,
        [ValidateSet("PSObject", "Csv", "Json", "OrderedDictionary", "Xml")]
        [String]$OutputFormat = "PSObject",
        [switch]$ExportRemoteCertificate,
        [switch]$IncludeErrorMessages,
        [switch]$IncludeRemoteCertificateInfo,
        [switch]$ReturnRemoteCertificateOnly,
        [ValidateSet(1, 2, 3, 4, 5)][int32]$TimeoutSeconds = 2
    )
    begin {
        # Validate input
        # TO-DO: Add client TLS configuration settings validation, i.e. check registry for supported client tls protocols and the *nix equivalent.
        # Check all Ssl/Tls protocols
        $SupportedProtocolNames = ([System.Security.Authentication.SslProtocols]).GetEnumValues().Where{ $_ -ne 'Default' -and $_ -ne 'None' }
        Write-Verbose "Supported tls protocols:"
        $SupportedProtocolNames.ForEach{ Write-Verbose $_ }
        if (-not $ProtocolName){
            Write-Verbose "No tls protocols specified. Defaulting to test all support tls protocols."
            $ProtocolName = $SupportedProtocolNames
        }
        elseif ($UnsupportedProtocolNames = $ProtocolName.Where{ $_ -notin $SupportedProtocolNames }) {
            Write-Verbose "Unsupported tls protocol(s) specified. Unable to complete request. "
            Write-Error -ErrorAction Stop (
                "Unknown protocol name(s). Please use names from the list of protocol names supported on this system ({0}). You used: {1}" -f
                ($SupportedProtocolNames -join ", "),
                ($UnsupportedProtocolNames -join ", ")
            )
        }

        # Resolve input
        if ($Server -as [IPAddress]) {
            try {
                # This is very slow to fail
                # $Fqdn = [System.Net.DNS]::GetHostByAddress($Server).HostName
                $dnsResult = Resolve-DnsName -Name $Server -DnsOnly -erroraction 'silentlycontinue'
                $Fqdn = $dnsResult.NameHost

                $Ip = $Server
                Write-Verbose "Server is an IP address with FQDN: $Fqdn"
            } 
            # TO-DO: Should skip process block, but the code gets messy when accounting for all switches to keep objects the same.
            # This is important when results are exported to a csv file.
            catch {
                Write-Verbose "Unable to resolve IP address $Server to fqdn."
            }
        }
        else {
            $Fqdn = $Server
            $Ip = [System.Net.DNS]::GetHostByName($Server).AddressList.IPAddressToString -join ", "
            Write-Verbose "Server is an FQDN with the following IP addresses: $ip"
        }
    }
    process {
        # TO-DO: Add option to enable RemoteCertificateValidationCallback (current implementation accepts all certificates)
        Write-Verbose "Scanning $($port.count) ports:"
        $Port.ForEach{ Write-Verbose $_ }

        $Port.ForEach{
            $p = $_
            $ProtocolStatus = [Ordered]@{
                Fqdn = $Fqdn
                IP   = $Ip
                Port = $p
            }
            [PSCustomObject]$ProtocolStatus.ForEach{ Write-Verbose $_ }
            if ($pscmdlet.ShouldProcess($Server, "Test the following protocols: $Name")) {
                if ($PSVersionTable.PSVersion.Major -ge 6) {
                    $OpenPort = Test-Connection $Server -TCPPort $p -TimeoutSeconds $TimeoutSeconds
                }
                else {
                    #$OpenPort = (Test-NetConnection $Server -Port $p).TcpTestSucceeded
                    $OpenPort = (New-Object System.Net.Sockets.TcpClient).ConnectAsync($Server, $p).Wait(100)
                }
                Write-Verbose "Connection to $Server`:$p is available - $OpenPort"
                if ($OpenPort) {
                    # Retrieve remote certificate information when IncludeRemoteCertificateInfo switch is enabled.
                    if ($IncludeRemoteCertificateInfo) {
                        Write-Verbose "Including remote certificate information."
                        $ProtocolStatus += [ordered]@{
                            CertificateThumbprint = 'unknown'
                            CertificateSubject    = 'unknown'
                            CertificateIssuer     = 'unknown'
                            CertificateIssued     = 'unknown'
                            CertificateExpires    = 'unknown'
                            SignatureAlgorithm    = 'unknown'
                        }
                    }
                    $ProtocolName.ForEach{
                        $Name = $_
                        Write-Verbose "Starting test on $Name"
                        $ProtocolStatus.Add($Name, 'unknown')
                        if ($IncludeErrorMessages) {
                            $ProtocolStatus.Add("$Name`ErrorMsg", $false)
                        }
                        try {
                            $Socket = [System.Net.Sockets.Socket]::new([System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
                            Write-Verbose "Attempting socket connection to $fqdn`:$p"
                            $Socket.Connect($fqdn, $p)
                            Write-Verbose "Connection succeeded."
                            $NetStream = [System.Net.Sockets.NetworkStream]::new($Socket, $true)
                            $SslStream = [System.Net.Security.SslStream]::new($NetStream, $true, { $true }) # Ignore certificate validation errors
                            Write-Verbose "Attempting to authenticate to $fqdn as a client over $Name"
                            $SslStream.AuthenticateAsClient($fqdn, $null, $Name, $false)
                            $ProtocolStatus[$Name] = $true # success
                            Write-Verbose "Successfully authenticated to $fqdn`:$p"
                            $RemoteCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SslStream.RemoteCertificate

                            if ($IncludeRemoteCertificateInfo) {
                                # Store remote certificate information if it hasn't already been collected
                                if ($ProtocolStatus.CertificateThumbprint -eq 'unknown' -and $RemoteCertificate.Thumbprint) {
                                    $ProtocolStatus["CertificateThumbprint"] = $RemoteCertificate.Thumbprint
                                    $ProtocolStatus["CertificateSubject"] = $RemoteCertificate.Subject
                                    $ProtocolStatus["CertificateIssuer"] = $RemoteCertificate.Issuer
                                    $ProtocolStatus["CertificateIssued"] = $RemoteCertificate.NotBefore
                                    $ProtocolStatus["CertificateExpires"] = $RemoteCertificate.NotAfter
                                    $ProtocolStatus["SignatureAlgorithm"] = $RemoteCertificate.SignatureAlgorithm.FriendlyName

                                    $certData = $RemoteCertificate.GetRawCertData()
                                    $certDataB64 = [System.Convert]::ToBase64String($certData)
                                    $ProtocolStatus["CertificateData"] = $certDataB64
                                }
                            }

                            if ($ExportRemoteCertificate) {
                                $CertPath = "$fqdn.cer"
                                if (-not (Test-Path $CertPath)) {
                                    #Write-Host "Exporting $fqdn.cer to $($(Get-Location).path)" -ForegroundColor Green
                                    #$RemoteCertificate.Export('Cert') | Set-Content "$fqdn.cer" -AsByteStream
                                    
                                    $certData = $RemoteCertificate.GetRawCertData()
                                    $certDataB64 = [System.Convert]::ToBase64String($certData)
                                    "----- BEGIN CERTIFICATE -----`n" + $certDataB64 + "`n----- END CERTIFICATE -----`n" | Out-File -FilePath $CertPath 
                                }
                            }

                            if ($ReturnRemoteCertificateOnly) {
                                Write-Verbose "Returning $fqdn remote certificate only."
                                $RemoteCertificate
                                break;
                            }
                        }
                        catch {
                            $ProtocolStatus[$Name] = $false # failed to establish tls connection
                            Write-Verbose "Unable to establish tls connection with $fqdn`:$p over $Name"
                            # Collect detailed error message about why the tls connection failed
                            if ($IncludeErrorMessages) {
                                $e = $error[0]
                                $NestedException = $e.Exception.InnerException.InnerException.Message
                                if ($NestedException) { $emsg = $NestedException }
                                else { $emsg = $e.Exception.InnerException.Message }
                                Write-Verbose $emsg
                                $ProtocolStatus["$Name`ErrorMsg"] = $emsg
                            }
                        }
                        finally {
                            # Free up system memory/garbage collection
                            Write-Verbose "Garbage collection."
                            if ($SslStream) { $SslStream.Dispose() }
                            if ($NetStream) { $NetStream.Dispose() }
                            if ($Socket) { $Socket.Dispose() }
                        }
                    }
                }
                else {
                    # Supported Tls protocols are unknown when a connection cannot be established.
                    Write-Verbose "Supported Tls protocols are unknown when a connection cannot be established."
                    $ProtocolName.ForEach{
                        $Name = $_
                        $ProtocolStatus.Add($Name, 'unknown')
                        if ($IncludeErrorMessages) {
                            $ProtocolStatus.Add("$Name`ErrorMsg", "Could not connect to $server on TCP port $p`.")
                        }
                    }
                }
                Export-ProtocolStatus -ProtocolStatus $ProtocolStatus -OutputFormat $OutputFormat
            }
        }
    }
} # Test-TlsProtocols

function Export-ProtocolStatus {
    [CmdletBinding()]
    param (
        $ProtocolStatus,
        $OutputFormat
    )
    
    process {
        if ([string]::IsNullOrWhiteSpace($OutputFormat)) {
            [PSCustomObject]$ProtocolStatus
        } else {
            # Various switches to generate output in desired format of choice
            switch ($OutputFormat) {
                "Csv" { [PSCustomObject]$ProtocolStatus | ConvertTo-Csv -NoTypeInformation }
                "Json" { [PSCustomObject]$ProtocolStatus | ConvertTo-Json }
                "OrderedDictionary" { $ProtocolStatus } # Ordered HashTable
                "PSObject" { [PSCustomObject]$ProtocolStatus }
                "Xml" { [PSCustomObject]$ProtocolStatus | ConvertTo-Xml -NoTypeInformation }
            }
        }
    }
}

function Find-IPRange {
    <#
    .SYNOPSIS
    Determines all the IP address in a given range or subnet.
    .DESCRIPTION
    This function can evaluate a set of addresses based of the following three options:

        Range - What IP addresses are between this and that address
        Mask - What are the IP addresses given a particular IP address and mask, i.e. 24, 25.
        Subnet - What are the IP addresses given a particular IP address and subnet address, i.e 255.255.0.0, 255.255.255.192

    You have to specify an IP address to use the subnet and mask options. For the range you have to specify two addresses.
    .PARAMETER Start
    Start address of an IP range
    .PARAMETER End
    End address of an IP range
    .PARAMETER IP
    Any valid ip address
    .PARAMETER Subnet
    A valid Subnet IP address i.e. 255.255.255.0, 255.255.0.0
    .PARAMETER Mask
    A valid net mask from 0 to 32
    .EXAMPLE
    Find-IPRange -IP 192.168.0.4 -mask 30
    .EXAMPLE
    Find-IPRange -Start 192.168.1.250 -End 192.168.2.5
    .EXAMPLE
    Find-IPRange -IP 10.100.100.10 -Subnet 255.255.255.240
    #>
    [CmdletBinding(DefaultParameterSetName = "Range")]
    Param (
        [Parameter(Mandatory = $true, ParameterSetName = "Range")]
        [System.Net.IPAddress]
        $Start,

        [Parameter(Mandatory = $true, ParameterSetName = "Range")]
        [System.Net.IPAddress]
        $End,

        [Parameter(Mandatory = $true, ParameterSetName = "Mask")]
        [Parameter(Mandatory = $true, ParameterSetName = "Subnet")]
        [System.Net.IPAddress]
        $IP,

        [Parameter(Mandatory = $true, ParameterSetName = "Subnet")]
        [System.Net.IPAddress]
        $Subnet,

        [Parameter(Mandatory = $true, ParameterSetName = "Mask")]
        [ValidateRange(0, 32)]
        [System.Int32]
        $Mask,

        [Parameter(ParameterSetName = "Mask")]
        [Parameter(ParameterSetName = "Subnet")]
        [System.Management.Automation.SwitchParameter]
        $ReturnRange
    )
    Begin {
        # If the user specifies a mask, then convert it to a subnet ip address
        if ($Mask) {
            $Binary = ("1" * $Mask) + ("0" * (32 - $Mask))
            $Decimal = [System.Convert]::ToInt64($Binary, 2)
            [System.Net.IPAddress]$Subnet = ConvertFrom-IntToIP -Decimal $Decimal
        }
    }
    Process {
        # If we're looking at a subnet, we need to establish the start address and the broadcast address for it. We're using bitwise operators to do this.
        if ($PSCmdlet.ParameterSetName -ne "Range") {
            # Compare bits where both are a match using the bitwise AND operator
            [System.Net.IPAddress]$SubnetAddr = $Subnet.Address -band $IP.Address

            # Flip the subnet mask i.e. 0.0.0.255 for 255.255.255.0 by using the bitwise XOR operator and then compare against a bitwise OR operator
            [System.Net.IPAddress]$Broadcast = ([System.Net.IPAddress]'255.255.255.255').Address -bxor $Subnet.Address -bor $SubnetAddr.Address

            # Return the start and end of a subnet only if requested
            if ($ReturnRange) { return $SubnetAddr, $Broadcast }

            # Convert the start and end of the ranges to integers
            $RangeStart = ConvertFrom-IPToInt -ip $SubnetAddr.IPAddressToString
            $RangeEnd = ConvertFrom-IPToInt -ip $Broadcast.IPAddressToString
        }
        else {
            $RangeStart = ConvertFrom-IPToInt -ip $Start.IPAddressToString
            $RangeEnd = ConvertFrom-IPToInt -ip $End.IPAddressToString
        }

        # Loop through the points between the start and end of the ranges and convert them back to IP addresses
        for ($Addr = $RangeStart; $Addr -le $RangeEnd; $Addr ++) { ConvertFrom-IntToIP -Decimal $Addr }
    }
    End {
    }
}

function ConvertFrom-IPToInt {
    <#
    .SYNOPSIS
    Converts an IP address to an Int64 value.
    .DESCRIPTION
    Converts an IP address to an Int64 value.
    .PARAMETER IP
    A valid IP address to be converted to an integer
    .EXAMPLE
    ConvertFrom-IPToInt -IP 192.168.0.1
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [System.Net.IPAddress]
        $IP
    )
    Begin {
    }
    Process {
        # Split the IP address in to octets
        $Octets = $IP -split "\."

        # Multiply the octets based on the maximum number of addresses each octet provides.
        [System.Int64]$Decimal = ([System.Int32]$Octets[0] * [System.Math]::Pow(256, 3)) +
            ([System.Int32]$Octets[1] * [System.Math]::Pow(256, 2)) +
            ([System.Int32]$Octets[2] * 256) +
            ([System.Int32]$Octets[3])
    }
    End {
        # Return the int64 value
        $Decimal
    }
}

function ConvertFrom-IntToIP {
    <#
    .SYNOPSIS
    Converts an Int64 value to an IP address.
    .DESCRIPTION
    Converts an Int64 value to an IP address.
    .PARAMETER Decimal
    A decimal value for the IP Address to be converted
    .EXAMPLE
    ConvertFrom-IntToIP -Decimal 3232235521
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [System.Int64]
        $Decimal
    )
    Begin {
        # Initialise an array for the octets
        $Octets = @()
    }
    Process {
        # Work out first octet by dividing by the total number of addresses.
        $Octets += [System.String]([System.Math]::Truncate($Decimal / [System.Math]::Pow(256, 3)))

        # Work out second octet by the modulus of the first octets total number of addresses divided by the total number of address available for a class B subnet.
        $Octets += [System.String]([System.Math]::Truncate(($Decimal % [System.Math]::Pow(256, 3)) / [System.Math]::Pow(256, 2)))

        # Work out third octet by the modulus of the second octets total number of addresses divided by the total number of address available for a class C subnet.
        $Octets += [System.String]([System.Math]::Truncate(($Decimal % [System.Math]::Pow(256, 2)) / 256))

        # Work out fourth octet by the modulus of the third octets total number of addresses.
        $Octets += [System.String]([System.Math]::Truncate($Decimal % 256))

        # Join the strings to form the IP address
        [System.Net.IPAddress]$IP = $Octets -join "."
    }
    End {
        # Return the ip address object
        $IP.IPAddressToString
    }
}

# -------------------------------------------------------------------------------------------
#
#
#
# -------------------------------------------------------------------------------------------


# -------------------------------------------------------------------------------------------
# Check Parameters
# -------------------------------------------------------------------------------------------
if (! $PSBoundParameters.ContainsKey("ipStart") -and ! $PSBoundParameters.ContainsKey("serverList") -and ! $PSBoundParameters.ContainsKey("ipAddress"))
{
    Write-Host "You must provide either ipStart and ipEnd, or serverList or ipAddress and subnetMask"
    Exit
}

if ($PSBoundParameters.ContainsKey("ipStart"))
{
    if (! $PSBoundParameters.ContainsKey("ipEnd"))
    {
        Write-Host "You must provide ipEnd with ipStart"
        Exit
    }
    $ipAddresses = Find-IPRange -Start $ipStart -End $ipEnd
}

if ($PSBoundParameters.ContainsKey("ipAddress"))
{
    if (! $PSBoundParameters.ContainsKey("subnetMask"))
    {
        Write-Host "No subnet mask provided. Defaulting to /32 (only the provided IP address will be scanned)"
        $subnetMask = 32
    }
    $ipAddresses = Find-IPRange -IP $ipAddress -Mask $subnetMask
}

if ($PSBoundParameters.ContainsKey("serverList"))
{
    $ipAddresses = $serverList
}

if (! $PSBoundParameters.ContainsKey("additionalText"))
{
    $additionalText = "Imported from scan job"
}

# -------------------------------------------------------------------------------------------
# Get the API Token in a secure way if not provided
# -------------------------------------------------------------------------------------------
if (! $PSBoundParameters.ContainsKey("apiToken"))
{
    $secureApiKey = Read-Host -assecurestring "Enter the API Token"		
    $apiToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureApiKey))
}

# -------------------------------------------------------------------------------------------
# Ignore SSL errors
# -------------------------------------------------------------------------------------------
if ($ignoreSslErrors)
{
    # NOTE: This skips the SSL certificate check
    add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy 

$allProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $allProtocols 
}

# -------------------------------------------------------------------------------------------
# Construct URL and headers
# -------------------------------------------------------------------------------------------
#$VerbosePreference="Continue"
$certdogUrl = "https://$certdogServer/certdog/api/certs/import"

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/json")
$headers.Add("Authorization", "Bearer $apiToken")

# -------------------------------------------------------------------------------------------
# Run through the provided IP addresses, obtain certs and import
# -------------------------------------------------------------------------------------------
foreach ($ip in $ipAddresses)
{
    Write-Host "Trying IP Address $ip"

    $result = Test-TlsProtocols $ip -IncludeRemoteCertificateInfo -Port $ports -OutputFormat PSObject

    if ($result)
    {
        if ($result.CertificateSubject)
        {
            $foundCert = $result.CertificateSubject
            Write-Host "Found $foundCert at $ip"
        }
    }

    $certData = $result.CertificateData
    $ipAddress = $result.IP
    $port = $result.Port

    $extraInfo = "$additionalText. Host scanned: google.com [IP: $ipAddress] port: $port"

    $body = [Ordered]@{
        'certData' = "$certData"
        'ownerUserId' = "$userId"
        'teamId' = "$teamId"
        'extraInfo' = "$extraInfo"
    } | ConvertTo-Json -Compress

    try
    {
        if ($certData)
        {
            $response = Invoke-RestMethod "$certdogUrl" -Headers $headers -Method POST -Body $body
        }
    }
    catch
    {
        $jsonResponse = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($jsonResponse)
        $responseBody = $reader.ReadToEnd();
        
        $output = $responseBody | ConvertFrom-Json
        $output.message
    } 
}

# SIG # Begin signature block
# MIIrowYJKoZIhvcNAQcCoIIrlDCCK5ACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUHEbJ6934HWH5qY5Im86dpc9q
# ls+ggiTeMIIFbzCCBFegAwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0B
# AQwFADB7MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVy
# MRAwDgYDVQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEh
# MB8GA1UEAwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTIxMDUyNTAwMDAw
# MFoXDTI4MTIzMTIzNTk1OVowVjELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3Rp
# Z28gTGltaXRlZDEtMCsGA1UEAxMkU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWduaW5n
# IFJvb3QgUjQ2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAjeeUEiIE
# JHQu/xYjApKKtq42haxH1CORKz7cfeIxoFFvrISR41KKteKW3tCHYySJiv/vEpM7
# fbu2ir29BX8nm2tl06UMabG8STma8W1uquSggyfamg0rUOlLW7O4ZDakfko9qXGr
# YbNzszwLDO/bM1flvjQ345cbXf0fEj2CA3bm+z9m0pQxafptszSswXp43JJQ8mTH
# qi0Eq8Nq6uAvp6fcbtfo/9ohq0C/ue4NnsbZnpnvxt4fqQx2sycgoda6/YDnAdLv
# 64IplXCN/7sVz/7RDzaiLk8ykHRGa0c1E3cFM09jLrgt4b9lpwRrGNhx+swI8m2J
# mRCxrds+LOSqGLDGBwF1Z95t6WNjHjZ/aYm+qkU+blpfj6Fby50whjDoA7NAxg0P
# OM1nqFOI+rgwZfpvx+cdsYN0aT6sxGg7seZnM5q2COCABUhA7vaCZEao9XOwBpXy
# bGWfv1VbHJxXGsd4RnxwqpQbghesh+m2yQ6BHEDWFhcp/FycGCvqRfXvvdVnTyhe
# Be6QTHrnxvTQ/PrNPjJGEyA2igTqt6oHRpwNkzoJZplYXCmjuQymMDg80EY2NXyc
# uu7D1fkKdvp+BRtAypI16dV60bV/AK6pkKrFfwGcELEW/MxuGNxvYv6mUKe4e7id
# FT/+IAx1yCJaE5UZkADpGtXChvHjjuxf9OUCAwEAAaOCARIwggEOMB8GA1UdIwQY
# MBaAFKARCiM+lvEH7OKvKe+CpX/QMKS0MB0GA1UdDgQWBBQy65Ka/zWWSC8oQEJw
# IDaRXBeF5jAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zATBgNVHSUE
# DDAKBggrBgEFBQcDAzAbBgNVHSAEFDASMAYGBFUdIAAwCAYGZ4EMAQQBMEMGA1Ud
# HwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0FBQUNlcnRpZmlj
# YXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBDAUAA4IBAQASv6Hvi3Sa
# mES4aUa1qyQKDKSKZ7g6gb9Fin1SB6iNH04hhTmja14tIIa/ELiueTtTzbT72ES+
# BtlcY2fUQBaHRIZyKtYyFfUSg8L54V0RQGf2QidyxSPiAjgaTCDi2wH3zUZPJqJ8
# ZsBRNraJAlTH/Fj7bADu/pimLpWhDFMpH2/YGaZPnvesCepdgsaLr4CnvYFIUoQx
# 2jLsFeSmTD1sOXPUC4U5IOCFGmjhp0g4qdE2JXfBjRkWxYhMZn0vY86Y6GnfrDyo
# XZ3JHFuu2PMvdM+4fvbXg50RlmKarkUT2n/cR/vfw1Kf5gZV6Z2M8jpiUbzsJA8p
# 1FiAhORFe1rYMIIGFDCCA/ygAwIBAgIQeiOu2lNplg+RyD5c9MfjPzANBgkqhkiG
# 9w0BAQwFADBXMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MS4wLAYDVQQDEyVTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFJvb3QgUjQ2
# MB4XDTIxMDMyMjAwMDAwMFoXDTM2MDMyMTIzNTk1OVowVTELMAkGA1UEBhMCR0Ix
# GDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJs
# aWMgVGltZSBTdGFtcGluZyBDQSBSMzYwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAw
# ggGKAoIBgQDNmNhDQatugivs9jN+JjTkiYzT7yISgFQ+7yavjA6Bg+OiIjPm/N/t
# 3nC7wYUrUlY3mFyI32t2o6Ft3EtxJXCc5MmZQZ8AxCbh5c6WzeJDB9qkQVa46xiY
# Epc81KnBkAWgsaXnLURoYZzksHIzzCNxtIXnb9njZholGw9djnjkTdAA83abEOHQ
# 4ujOGIaBhPXG2NdV8TNgFWZ9BojlAvflxNMCOwkCnzlH4oCw5+4v1nssWeN1y4+R
# laOywwRMUi54fr2vFsU5QPrgb6tSjvEUh1EC4M29YGy/SIYM8ZpHadmVjbi3Pl8h
# JiTWw9jiCKv31pcAaeijS9fc6R7DgyyLIGflmdQMwrNRxCulVq8ZpysiSYNi79tw
# 5RHWZUEhnRfs/hsp/fwkXsynu1jcsUX+HuG8FLa2BNheUPtOcgw+vHJcJ8HnJCrc
# UWhdFczf8O+pDiyGhVYX+bDDP3GhGS7TmKmGnbZ9N+MpEhWmbiAVPbgkqykSkzyY
# Vr15OApZYK8CAwEAAaOCAVwwggFYMB8GA1UdIwQYMBaAFPZ3at0//QET/xahbIIC
# L9AKPRQlMB0GA1UdDgQWBBRfWO1MMXqiYUKNUoC6s2GXGaIymzAOBgNVHQ8BAf8E
# BAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADATBgNVHSUEDDAKBggrBgEFBQcDCDAR
# BgNVHSAECjAIMAYGBFUdIAAwTAYDVR0fBEUwQzBBoD+gPYY7aHR0cDovL2NybC5z
# ZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljVGltZVN0YW1waW5nUm9vdFI0Ni5jcmww
# fAYIKwYBBQUHAQEEcDBuMEcGCCsGAQUFBzAChjtodHRwOi8vY3J0LnNlY3RpZ28u
# Y29tL1NlY3RpZ29QdWJsaWNUaW1lU3RhbXBpbmdSb290UjQ2LnA3YzAjBggrBgEF
# BQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wDQYJKoZIhvcNAQEMBQADggIB
# ABLXeyCtDjVYDJ6BHSVY/UwtZ3Svx2ImIfZVVGnGoUaGdltoX4hDskBMZx5NY5L6
# SCcwDMZhHOmbyMhyOVJDwm1yrKYqGDHWzpwVkFJ+996jKKAXyIIaUf5JVKjccev3
# w16mNIUlNTkpJEor7edVJZiRJVCAmWAaHcw9zP0hY3gj+fWp8MbOocI9Zn78xvm9
# XKGBp6rEs9sEiq/pwzvg2/KjXE2yWUQIkms6+yslCRqNXPjEnBnxuUB1fm6bPAV+
# Tsr/Qrd+mOCJemo06ldon4pJFbQd0TQVIMLv5koklInHvyaf6vATJP4DfPtKzSBP
# kKlOtyaFTAjD2Nu+di5hErEVVaMqSVbfPzd6kNXOhYm23EWm6N2s2ZHCHVhlUgHa
# C4ACMRCgXjYfQEDtYEK54dUwPJXV7icz0rgCzs9VI29DwsjVZFpO4ZIVR33LwXyP
# DbYFkLqYmgHjR3tKVkhh9qKV2WCmBuC27pIOx6TYvyqiYbntinmpOqh/QPAnhDge
# xKG9GX/n1PggkGi9HCapZp8fRwg8RftwS21Ln61euBG0yONM6noD2XQPrFwpm3Gc
# uqJMf0o8LLrFkSLRQNwxPDDkWXhW+gZswbaiie5fd/W2ygcto78XCSPfFWveUOSZ
# 5SqK95tBO8aTHmEa4lpJVD7HrTEn9jb1EGvxOb1cnn0CMIIGGjCCBAKgAwIBAgIQ
# Yh1tDFIBnjuQeRUgiSEcCjANBgkqhkiG9w0BAQwFADBWMQswCQYDVQQGEwJHQjEY
# MBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS0wKwYDVQQDEyRTZWN0aWdvIFB1Ymxp
# YyBDb2RlIFNpZ25pbmcgUm9vdCBSNDYwHhcNMjEwMzIyMDAwMDAwWhcNMzYwMzIx
# MjM1OTU5WjBUMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MSswKQYDVQQDEyJTZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgQ0EgUjM2MIIB
# ojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAmyudU/o1P45gBkNqwM/1f/bI
# U1MYyM7TbH78WAeVF3llMwsRHgBGRmxDeEDIArCS2VCoVk4Y/8j6stIkmYV5Gej4
# NgNjVQ4BYoDjGMwdjioXan1hlaGFt4Wk9vT0k2oWJMJjL9G//N523hAm4jF4UjrW
# 2pvv9+hdPX8tbbAfI3v0VdJiJPFy/7XwiunD7mBxNtecM6ytIdUlh08T2z7mJEXZ
# D9OWcJkZk5wDuf2q52PN43jc4T9OkoXZ0arWZVeffvMr/iiIROSCzKoDmWABDRzV
# /UiQ5vqsaeFaqQdzFf4ed8peNWh1OaZXnYvZQgWx/SXiJDRSAolRzZEZquE6cbcH
# 747FHncs/Kzcn0Ccv2jrOW+LPmnOyB+tAfiWu01TPhCr9VrkxsHC5qFNxaThTG5j
# 4/Kc+ODD2dX/fmBECELcvzUHf9shoFvrn35XGf2RPaNTO2uSZ6n9otv7jElspkfK
# 9qEATHZcodp+R4q2OIypxR//YEb3fkDn3UayWW9bAgMBAAGjggFkMIIBYDAfBgNV
# HSMEGDAWgBQy65Ka/zWWSC8oQEJwIDaRXBeF5jAdBgNVHQ4EFgQUDyrLIIcouOxv
# SK4rVKYpqhekzQwwDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwGwYDVR0gBBQwEjAGBgRVHSAAMAgGBmeBDAEE
# ATBLBgNVHR8ERDBCMECgPqA8hjpodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3Rp
# Z29QdWJsaWNDb2RlU2lnbmluZ1Jvb3RSNDYuY3JsMHsGCCsGAQUFBwEBBG8wbTBG
# BggrBgEFBQcwAoY6aHR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGlj
# Q29kZVNpZ25pbmdSb290UjQ2LnA3YzAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Au
# c2VjdGlnby5jb20wDQYJKoZIhvcNAQEMBQADggIBAAb/guF3YzZue6EVIJsT/wT+
# mHVEYcNWlXHRkT+FoetAQLHI1uBy/YXKZDk8+Y1LoNqHrp22AKMGxQtgCivnDHFy
# AQ9GXTmlk7MjcgQbDCx6mn7yIawsppWkvfPkKaAQsiqaT9DnMWBHVNIabGqgQSGT
# rQWo43MOfsPynhbz2Hyxf5XWKZpRvr3dMapandPfYgoZ8iDL2OR3sYztgJrbG6VZ
# 9DoTXFm1g0Rf97Aaen1l4c+w3DC+IkwFkvjFV3jS49ZSc4lShKK6BrPTJYs4NG1D
# GzmpToTnwoqZ8fAmi2XlZnuchC4NPSZaPATHvNIzt+z1PHo35D/f7j2pO1S8BCys
# QDHCbM5Mnomnq5aYcKCsdbh0czchOm8bkinLrYrKpii+Tk7pwL7TjRKLXkomm5D1
# Umds++pip8wH2cQpf93at3VDcOK4N7EwoIJB0kak6pSzEu4I64U6gZs7tS/dGNSl
# jf2OSSnRr7KWzq03zl8l75jy+hOds9TWSenLbjBQUGR96cFr6lEUfAIEHVC1L68Y
# 1GGxx4/eRI82ut83axHMViw1+sVpbPxg51Tbnio1lB93079WPFnYaOvfGAA0e0zc
# fF/M9gXr+korwQTh2Prqooq2bYNMvUoUKD85gnJ+t0smrWrb8dee2CvYZXD5laGt
# aAxOfy/VKNmwuWuAh9kcMIIGSjCCBLKgAwIBAgIQbNQZSezHYTUIi09IS8O7HTAN
# BgkqhkiG9w0BAQwFADBUMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBM
# aW1pdGVkMSswKQYDVQQDEyJTZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgQ0Eg
# UjM2MB4XDTIzMDMyMDAwMDAwMFoXDTI2MDMxOTIzNTk1OVowYTELMAkGA1UEBhMC
# R0IxGDAWBgNVBAgMD0J1Y2tpbmdoYW1zaGlyZTEbMBkGA1UECgwSS3Jlc3RmaWVs
# ZCBMaW1pdGVkMRswGQYDVQQDDBJLcmVzdGZpZWxkIExpbWl0ZWQwggIiMA0GCSqG
# SIb3DQEBAQUAA4ICDwAwggIKAoICAQC+7C6nh5jC2hKXwqHmLviGM0BoNUXRAJv2
# gq8zIv5lw5HFul5wLr0i52JgV6TvIdgOw9fXCMqPOhRIfUzvBAswXr8GZHlPqNJ/
# RCW9xgXE8MjOY3iJ5Pn99qVOp6OQjXSq7W5t6NDqhv/LfpwHihh284xRAI9wtAsN
# QD2cTqZ0hKxIvaIclRuUB1nkMXZM8jgDOzpj3nv+fJ6jt4ODMLjhexQPNjTuoYMH
# uxgkPw0vJ9kWkA+WTeExSh0nGsGPqsgLt+1blyGB8RDe/tUgSQnAsMGb47X66WtX
# ED06hIgEMkOjJI5J5KNVCbPI7F+woDlcwmRdSHWiQwiDQINGpaQFnm+ZEC0xzGYV
# 4QmKvJwy4mjpr6ztxpiOj9/VOYfivLYmlukvS7fs6zfV723c9p72t4/8yuaILxMd
# 43hPc5cyXlEgfCcN7n3RH+eHEd4gXI7C44y3aynOp97xe2L4FMQ2byPNF+9IY1SE
# u6xzoI/oTUV0ZmILxdTAnpRd/+RFMu0N/uANRjSJJuQWf6XHxUHvdVqIsTlIECsp
# wy0Q80Iu4vRp0M2cFh4m1+tJ5wYi8XtD/KKviosaBlVEXKR9OXdLXTI1ZKa/Bir4
# dh6+QhXBnLHfRP2jEHmDA0gpAOr/7UoCiecjhttmOdHQHVfbB1BYTZZiFl0BQZdk
# +NB9i4CcfQIDAQABo4IBiTCCAYUwHwYDVR0jBBgwFoAUDyrLIIcouOxvSK4rVKYp
# qhekzQwwHQYDVR0OBBYEFCV8ePD482YZEBQUp8NBczlgQqqWMA4GA1UdDwEB/wQE
# AwIHgDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMEoGA1UdIARD
# MEEwNQYMKwYBBAGyMQECAQMCMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2VjdGln
# by5jb20vQ1BTMAgGBmeBDAEEATBJBgNVHR8EQjBAMD6gPKA6hjhodHRwOi8vY3Js
# LnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2RlU2lnbmluZ0NBUjM2LmNybDB5
# BggrBgEFBQcBAQRtMGswRAYIKwYBBQUHMAKGOGh0dHA6Ly9jcnQuc2VjdGlnby5j
# b20vU2VjdGlnb1B1YmxpY0NvZGVTaWduaW5nQ0FSMzYuY3J0MCMGCCsGAQUFBzAB
# hhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTANBgkqhkiG9w0BAQwFAAOCAYEAeUU2
# Rf+FPWWj/bzphJK0xg1Q8EpS2PcK+6TTdkbDcgp01kGK9DUQ57++Pk4tsHuKUPQ6
# h6eSGsfuSPlXacBafhb6cYtU+C/GxJyjdf9N3wNlrUY8VEJT0s99bFOYL/o1dN6y
# xaVuK/5fJTmoRA7vUUnxUuw1q+IlBILWpL35qU2xEt9rfgcIqZ7u8fHcIhsXeah+
# +0qOxnELhbpIVN4lM3ilxUmvvpuSbL5XgxJyn2W77INYCob1q1KhBkqRmW3WLAFY
# r4hnuqYJ6AEBuDiC0yCM0JLjJZ8lXVAWQMyuXHl7cT3Bh0ad7hDkIU85IchL3/Ul
# 42b6PoTyO1ARAlXZuqQIBAKlRenDUVFx2dfHzbFGrP7SLQfAsR3N+dfEUfCKsI1S
# UXpIFdHBnYbxmGN81km8UYvYHlXcW6YdISrqMB5M3Q2H1W8Qf80DfewjwOlrNERf
# FWf58J5EITs1ffQ43sizgzjqw6CyvnAMMKMnoOXsGKF4peAN3L+IdEIBfpr2MIIG
# XTCCBMWgAwIBAgIQOlJqLITOVeYdZfzMEtjpiTANBgkqhkiG9w0BAQwFADBVMQsw
# CQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSwwKgYDVQQDEyNT
# ZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIENBIFIzNjAeFw0yNDAxMTUwMDAw
# MDBaFw0zNTA0MTQyMzU5NTlaMG4xCzAJBgNVBAYTAkdCMRMwEQYDVQQIEwpNYW5j
# aGVzdGVyMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxMDAuBgNVBAMTJ1NlY3Rp
# Z28gUHVibGljIFRpbWUgU3RhbXBpbmcgU2lnbmVyIFIzNTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAI3RZ/TBSJu9/ThJOk1hgZvD2NxFpWEENo0GnuOY
# loD11BlbmKCGtcY0xiMrsN7LlEgcyoshtP3P2J/vneZhuiMmspY7hk/Q3l0FPZPB
# llo9vwT6GpoNnxXLZz7HU2ITBsTNOs9fhbdAWr/Mm8MNtYov32osvjYYlDNfefnB
# ajrQqSV8Wf5ZvbaY5lZhKqQJUaXxpi4TXZKohLgxU7g9RrFd477j7jxilCU2ptz+
# d1OCzNFAsXgyPEM+NEMPUz2q+ktNlxMZXPF9WLIhOhE3E8/oNSJkNTqhcBGsbDI/
# 1qCU9fBhuSojZ0u5/1+IjMG6AINyI6XLxM8OAGQmaMB8gs2IZxUTOD7jTFR2HE1x
# oL7qvSO4+JHtvNceHu//dGeVm5Pdkay3Et+YTt9EwAXBsd0PPmC0cuqNJNcOI0Xn
# wjE+2+Zk8bauVz5ir7YHz7mlj5Bmf7W8SJ8jQwO2IDoHHFC46ePg+eoNors0QrC0
# PWnOgDeMkW6gmLBtq3CEOSDU8iNicwNsNb7ABz0W1E3qlSw7jTmNoGCKCgVkLD2F
# aMs2qAVVOjuUxvmtWMn1pIFVUvZ1yrPIVbYt1aTld2nrmh544Auh3tgggy/WluoL
# XlHtAJgvFwrVsKXj8ekFt0TmaPL0lHvQEe5jHbufhc05lvCtdwbfBl/2ARSTuy1s
# 8CgFAgMBAAGjggGOMIIBijAfBgNVHSMEGDAWgBRfWO1MMXqiYUKNUoC6s2GXGaIy
# mzAdBgNVHQ4EFgQUaO+kMklptlI4HepDOSz0FGqeDIUwDgYDVR0PAQH/BAQDAgbA
# MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwSgYDVR0gBEMw
# QTA1BgwrBgEEAbIxAQIBAwgwJTAjBggrBgEFBQcCARYXaHR0cHM6Ly9zZWN0aWdv
# LmNvbS9DUFMwCAYGZ4EMAQQCMEoGA1UdHwRDMEEwP6A9oDuGOWh0dHA6Ly9jcmwu
# c2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY1RpbWVTdGFtcGluZ0NBUjM2LmNybDB6
# BggrBgEFBQcBAQRuMGwwRQYIKwYBBQUHMAKGOWh0dHA6Ly9jcnQuc2VjdGlnby5j
# b20vU2VjdGlnb1B1YmxpY1RpbWVTdGFtcGluZ0NBUjM2LmNydDAjBggrBgEFBQcw
# AYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wDQYJKoZIhvcNAQEMBQADggGBALDc
# Lsn6TzZMii/2yU/V7xhPH58Oxr/+EnrZjpIyvYTz2u/zbL+fzB7lbrPml8ERajOV
# budan6x08J1RMXD9hByq+yEfpv1G+z2pmnln5XucfA9MfzLMrCArNNMbUjVcRcsA
# r18eeZeloN5V4jwrovDeLOdZl0tB7fOX5F6N2rmXaNTuJR8yS2F+EWaL5VVg+RH8
# FelXtRvVDLJZ5uqSNIckdGa/eUFhtDKTTz9LtOUh46v2JD5Q3nt8mDhAjTKp2fo/
# KJ6FLWdKAvApGzjpPwDqFeJKf+kJdoBKd2zQuwzk5Wgph9uA46VYK8p/BTJJahKC
# uGdyKFIFfEfakC4NXa+vwY4IRp49lzQPLo7WticqMaaqb8hE2QmCFIyLOvWIg483
# 7bd+60FcCGbHwmL/g1ObIf0rRS9ceK4DY9rfBnHFH2v1d4hRVvZXyCVlrL7ZQuVz
# jjkLMK9VJlXTVkHpuC8K5S4HHTv2AJx6mOdkMJwS4gLlJ7gXrIVpnxG+aIniGDCC
# BoIwggRqoAMCAQICEDbCsL18Gzrno7PdNsvJdWgwDQYJKoZIhvcNAQEMBQAwgYgx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5MRQwEgYDVQQHEwtKZXJz
# ZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMS4wLAYDVQQD
# EyVVU0VSVHJ1c3QgUlNBIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTIxMDMy
# MjAwMDAwMFoXDTM4MDExODIzNTk1OVowVzELMAkGA1UEBhMCR0IxGDAWBgNVBAoT
# D1NlY3RpZ28gTGltaXRlZDEuMCwGA1UEAxMlU2VjdGlnbyBQdWJsaWMgVGltZSBT
# dGFtcGluZyBSb290IFI0NjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AIid2LlFZ50d3ei5JoGaVFTAfEkFm8xaFQ/ZlBBEtEFAgXcUmanU5HYsyAhTXiDQ
# kiUvpVdYqZ1uYoZEMgtHES1l1Cc6HaqZzEbOOp6YiTx63ywTon434aXVydmhx7Dx
# 4IBrAou7hNGsKioIBPy5GMN7KmgYmuu4f92sKKjbxqohUSfjk1mJlAjthgF7Hjx4
# vvyVDQGsd5KarLW5d73E3ThobSkob2SL48LpUR/O627pDchxll+bTSv1gASn/hp6
# IuHJorEu6EopoB1CNFp/+HpTXeNARXUmdRMKbnXWflq+/g36NJXB35ZvxQw6zid6
# 1qmrlD/IbKJA6COw/8lFSPQwBP1ityZdwuCysCKZ9ZjczMqbUcLFyq6KdOpuzVDR
# 3ZUwxDKL1wCAxgL2Mpz7eZbrb/JWXiOcNzDpQsmwGQ6Stw8tTCqPumhLRPb7YkzM
# 8/6NnWH3T9ClmcGSF22LEyJYNWCHrQqYubNeKolzqUbCqhSqmr/UdUeb49zYHr7A
# LL8bAJyPDmubNqMtuaobKASBqP84uhqcRY/pjnYd+V5/dcu9ieERjiRKKsxCG1t6
# tG9oj7liwPddXEcYGOUiWLm742st50jGwTzxbMpepmOP1mLnJskvZaN5e45NuzAH
# teORlsSuDt5t4BBRCJL+5EZnnw0ezntk9R8QJyAkL6/bAgMBAAGjggEWMIIBEjAf
# BgNVHSMEGDAWgBRTeb9aqitKz1SA4dibwJ3ysgNmyzAdBgNVHQ4EFgQU9ndq3T/9
# ARP/FqFsggIv0Ao9FCUwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8w
# EwYDVR0lBAwwCgYIKwYBBQUHAwgwEQYDVR0gBAowCDAGBgRVHSAAMFAGA1UdHwRJ
# MEcwRaBDoEGGP2h0dHA6Ly9jcmwudXNlcnRydXN0LmNvbS9VU0VSVHJ1c3RSU0FD
# ZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDA1BggrBgEFBQcBAQQpMCcwJQYIKwYB
# BQUHMAGGGWh0dHA6Ly9vY3NwLnVzZXJ0cnVzdC5jb20wDQYJKoZIhvcNAQEMBQAD
# ggIBAA6+ZUHtaES45aHF1BGH5Lc7JYzrftrIF5Ht2PFDxKKFOct/awAEWgHQMVHo
# l9ZLSyd/pYMbaC0IZ+XBW9xhdkkmUV/KbUOiL7g98M/yzRyqUOZ1/IY7Ay0YbMni
# IibJrPcgFp73WDnRDKtVutShPSZQZAdtFwXnuiWl8eFARK3PmLqEm9UsVX+55DbV
# Iz33Mbhba0HUTEYv3yJ1fwKGxPBsP/MgTECimh7eXomvMm0/GPxX2uhwCcs/YLxD
# nBdVVlxvDjHjO1cuwbOpkiJGHmLXXVNbsdXUC2xBrq9fLrfe8IBsA4hopwsCj8hT
# uwKXJlSTrZcPRVSccP5i9U28gZ7OMzoJGlxZ5384OKm0r568Mo9TYrqzKeKZgFo0
# fj2/0iHbj55hc20jfxvK3mQi+H7xpbzxZOFGm/yVQkpo+ffv5gdhp+hv1GDsvJOt
# JinJmgGbBFZIThbqI+MHvAmMmkfb3fTxmSkop2mSJL1Y2x/955S29Gu0gSJIkc3z
# 30vU/iXrMpWx2tS7UVfVP+5tKuzGtgkP7d/doqDrLF1u6Ci3TpjAZdeLLlRQZm86
# 7eVeXED58LXd1Dk6UvaAhvmWYXoiLz4JA5gPBcz7J311uahxCweNxE+xxxR3kT0W
# KzASo5G/PyDez6NHdIUKBeE3jDPs2ACc6CkJ1Sji4PKWVT0/MYIGLzCCBisCAQEw
# aDBUMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSswKQYD
# VQQDEyJTZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgQ0EgUjM2AhBs1BlJ7Mdh
# NQiLT0hLw7sdMAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAA
# MBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgor
# BgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBTvDGricRXLxGbpEKuPcRqh2Slb8zAN
# BgkqhkiG9w0BAQEFAASCAgACUNt8G9meWRaaBCXheHqaBC8MW37sHEV6qEmmoGoh
# ZPAIcK8+qFeREQFpsCAwVIAcNACh3j4aKOlRkpZXCjmE7ENfMcnu38KJ4+3Wgj6/
# 0aBHik8SzuuyasPfb0A1VRdpkxrQT3BDkUSToJUvG65vO4MbrIrhzUpGvOhxWYLZ
# 9kZJiSiQsWvI58PYFwzeKDSozBY7IrF+b2MQr2E/lc840esgT9X0CjLNJuFA8vLB
# +b1QpxD1eWxLz9hGf53VG1o7sww56ffjJBUbGJwIf+Wvyyftr+BI9Id4Zqvy6LWZ
# WmTypgaetPf8RRj866KFJe+vq9jt3R0JvgG0soUK5EwaChgLRumcslClbUSRj0rW
# Qm9BOZBaJhdUr47cPte+ET91+U3AAfO45jlofJ1a6PUrjiEcxAcrlocUVyyecEPh
# DwJcl2Hy6tjnDDIdDBAtUVVgnd4L2zvWAxZaPKVvDbliu6YS/Bx5akrehb0HAaAF
# rpkAflIsL/BvgWf1U2ce1vnPX/GYAxA+QrsClF12HfnNGpGcwJ3aY8MIQYRbaLOR
# 4pXA7ms5TANJbQBKVc1w1+0J2BIAKvUTetjCAfcGcfXBskjMr4Lg3nIEsRhOBuGn
# jKIsh4UA//n8iBbyYxDPWwKl7GNOsYokoD/itUhwlPQxcIXnBkJNjxlfggc/4okF
# fKGCAyIwggMeBgkqhkiG9w0BCQYxggMPMIIDCwIBATBpMFUxCzAJBgNVBAYTAkdC
# MRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxLDAqBgNVBAMTI1NlY3RpZ28gUHVi
# bGljIFRpbWUgU3RhbXBpbmcgQ0EgUjM2AhA6UmoshM5V5h1l/MwS2OmJMA0GCWCG
# SAFlAwQCAgUAoHkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0B
# CQUxDxcNMjQxMTIyMTEyMzMwWjA/BgkqhkiG9w0BCQQxMgQwT6jSX0UKe+milU8j
# JTQyjpOiUueXWS0elQ4UAqhDVEEC0vcLC+xSGN96pwXScEk/MA0GCSqGSIb3DQEB
# AQUABIICAD9wcdPgUMr4Rq/kx8N5Kj1SoUcAuV+tSPQeogkHhYHY+visbPvq3Uoc
# T+zvDZRFjszXIPeShaMdOFWxq/mehByIcyooKTr45D0M3CSfJiMxGYifg+0nUwvc
# L5ffUdHK37p3+0TKi9t3GzaxbZtN+UEjqv5+wRsDAH82Iu99qIGe7nKh8Zmdir07
# MD2tZziQUjXyzb9obIcf2ExfdNJbVpV0SwTYE1Lub5dy/CnSkT4xOuO9sGXn6IqX
# KHNlXQKPXof+Q+hEXUeWQ5vciiIfGrFlm7fg+SDtsKj9SeTKrHvFZyv/mo62Fxxt
# Qb/DvjnEVGjL1stAUzd6z5SDUOt5ucIgD5EHfKG0snubVnqnUgN5MxurZy2wlszL
# M0dnEVaY+mWIRMCKPd7ixVa+596X0YHSVgJxlN8uchkgemldDcce6FmGegAEdKu0
# Oo2KoP/r6cpOna/TDYPmP9O++IB/NvTxFEwptlrkOOHkAjm9HYTgVGN0VtUYNtRW
# yYhBdUn6gitfI3pvyXTOTHEF/0wSxAhuYwtGHX335GNjORT/7EFAakMnmhcgLtWl
# hgCM8BeQMx7hkosG6Zaa6JsKGj5t72A9LmiL8k/Cs7MSfq35WCqjhCa4DMpgqDZS
# UehZfJyS9lv/NDbSBNz8kYQ8MyAXWezmw0H4PYfqBk60gcjAXMHz
# SIG # End signature block
