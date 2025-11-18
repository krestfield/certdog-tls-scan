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

    $extraInfo = "$additionalText. IP scanned: $ipAddress port: $port"

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
