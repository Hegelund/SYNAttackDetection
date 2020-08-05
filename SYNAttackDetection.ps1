function Get-NetStat {
    <#
	.SYNOPSIS
		This function will get the output of netstat -n and parse the output
	.DESCRIPTION
		This function will get the output of netstat -n and parse the output
	.LINK
		http://www.lazywinadmin.com/2014/08/powershell-parse-this-netstatexe.html
	.NOTES
		Francois-Xavier Cat
		www.lazywinadmin.com
		@LazyWinAdm
	#>
    PROCESS {
        # Get the output of netstat
        $data = netstat -n
			
        # Keep only the line with the data (we remove the first lines)
        $data = $data[4..$data.count]
			
        # Each line need to be splitted and get rid of unnecessary spaces
        foreach ($line in $data) {
            # Get rid of the first whitespaces, at the beginning of the line
            $line = $line -replace '^\s+', ''
				
            # Split each property on whitespaces block
            $line = $line -split '\s+'
				
            # Define the properties
            $properties = @{
                Protocole          = $line[0]
                LocalAddressIP     = ($line[1] -split ":")[0]
                LocalAddressPort   = ($line[1] -split ":")[1]
                ForeignAddressIP   = ($line[2] -split ":")[0]
                ForeignAddressPort = ($line[2] -split ":")[1]
                State              = $line[3]
            }
				
            # Output the current line
            New-Object -TypeName PSObject -Property $properties
        }
    }
}

function New-AttackerString {
    param(
        [Parameter(Mandatory = $True)]
        [array]$knownAttackers
    )
    
    foreach ($attacker in $knownAttackers) {
        $String += $attacker + ','
    }
    
    return $String
}

# Variables	
$firewallRuleName = "Block RDP Attackers"
$Unblocktime = 24
$ScriptPath = split-path -parent $MyInvocation.MyCommand.Definition

# Test for FW rule
$firewallrule = netsh advfirewall firewall show rule name=$firewallRuleName
if (!($firewallrule -like "*Enabled*" -or $firewallrule -like "*Aktiveret*")) { 	
    $knownAttackers = "1.2.3.4,2.3.4.5"
    netsh advfirewall firewall add rule name=$firewallRuleName protocol=TCP dir=in localport=3389 action=allow
    netsh advfirewall firewall set rule name=$firewallRuleName new remoteip=$knownAttackers action=block
}

# IPs that will not be blacklisted.
$whiteList = @(
    "127.0.0.1"
)

# Get the already known attackers from the firewall rule
$knownAttackers = ((New-object -comObject HNetCfg.FwPolicy2).Rules | where-object { $_.name -eq "Block RDP Attackers" }).RemoteAddresses.split(",")

if ($null -eq $knownAttackers) {
    $knownAttackers = @()
}
$knownAttackers = $knownAttackers | Sort-Object -Unique

# Check for Unblocks, removing logs and building new knownAttackerslist
$Attacklogs = Get-childitem $ScriptPath\*.txt
$Unblocks = @()
if ($Attacklogs) { 
    foreach ($Log in $Attacklogs ) {
        $totalTime = New-TimeSpan -Start $log.LastWritetime -End (Get-date) 
        if ($totalTime.TotalHours -gt $unblocktime) {
            Write-host $Log.basename "has been blocked for" $totalTime.TotalHours "hours - time to unblock"
            $Unblocks += $Log.basename + "/255.255.255.255"
            Remove-Item $Log.FullName
        }
    }
}
$NewknownAttackers = @()
foreach ($Attacker in $knownAttackers) { 
    if (!($Unblocks -Contains $Attacker)) { 
        $NewknownAttackers += $Attacker
    }
}

if ($Unblocks) {
    $AttackerString = New-AttackerString -knownAttackers $NewknownAttackers
    netsh advfirewall firewall set rule name=$firewallRuleName new remoteip=$AttackerString action=block
}

# Get Netstat attacks
$currentAttackers = (Get-NetStat | Where-Object { $_.LocalAddressPort -eq "3389" -AND $_.state -eq "SYN_RECEIVED" } | Select-Object -Property ForeignAddressIP, state | Group-Object -Property ForeignAddressIP -NoElement | Sort-Object -Property Count -Descending)

# If there is no response, there are no attacks
if ($null -eq $currentAttackers) {
    Write-Host "No current attackers"
    return
}

# Check each logged attacker and check if it is already known
foreach ($newAttacker in $currentAttackers) {
    if ($knownAttackers -Contains $newAttacker.name ) {
        #If it is known, don't do anything
        continue
    }
    elseif ($whiteList -contains $newAttacker.name) {
        #If it is whitelisted, don't do anything
        Write-Host "$newAttacker is dynamically whitelisted"
        continue
    }
    else {
        #otherwise it is a new attacker and add it to the blacklist
        $newAttacker.name | Out-File -FilePath "$scriptPath\$($newAttacker.name).txt"
        $knownAttackers += $newAttacker.name
        Write-Host "Added $($newAttacker.name)"
    }
}

# Remove dublicates
$knownAttackers = $knownAttackers | Sort-Object -Unique
Write-Host "$($knownAttackers.Count) IPs on blacklist"
$AttackerString = New-AttackerString -knownAttackers $knownAttackers

# Setting Firwall rules with all known and all new attackers
netsh advfirewall firewall set rule name=$firewallRuleName new remoteip=$AttackerString action=block
