#requires -version 2.0

Function Get-vShieldAPI ($URL) {
	$httpClient = [System.Net.WebRequest]::Create($URL)

	# Add Authorization headers
	$authbytes = [System.Text.Encoding]::ASCII.GetBytes($username + ":" + $password)
	$base64 = [System.Convert]::ToBase64String($authbytes)  
	$authorization = "Authorization: Basic " + $base64
	$httpClient.Headers.Add($authorization)

	# Set Method
	$httpClient.Method = "GET"
	$response = $httpClient.GetResponse()
	If ($response.StatusCode -eq "OK") {
		$reader = New-Object System.IO.StreamReader($response.GetResponseStream())
		[xml]$XML = $reader.ReadToEnd()
		$XML
	} Else {
		Write-Host -ForegroundColor Red "Unable to connect to $($URL), debug info:"
		$response
	}
}
Function Set-vShieldAPI ($URL) {
	$httpClient = [System.Net.WebRequest]::Create($URL)

	# Add Authorization headers
	$authbytes = [System.Text.Encoding]::ASCII.GetBytes($username + ":" + $password)
	$base64 = [System.Convert]::ToBase64String($authbytes)  
	$authorization = "Authorization: Basic " + $base64
	$httpClient.Headers.Add($authorization)

	# Set Method
	$httpClient.Method = "PUT"
	$response = $httpClient.GetResponse()
	If ($response.StatusCode -eq "OK") {
		"Update task completed successfully"
	} Else {
		Write-Host -ForegroundColor Red "Unable to connect to $($URL), debug info:"
		$response
	}
}
Function Remove-vShieldAPI ($URL) {
	$httpClient = [System.Net.WebRequest]::Create($URL)

	# Add Authorization headers
	$authbytes = [System.Text.Encoding]::ASCII.GetBytes($username + ":" + $password)
	$base64 = [System.Convert]::ToBase64String($authbytes)  
	$authorization = "Authorization: Basic " + $base64
	$httpClient.Headers.Add($authorization)

	# Set Method
	$httpClient.Method = "DELETE"
	$response = $httpClient.GetResponse()
	If ($response.StatusCode -eq "OK") {
		"Update task completed successfully"
	} Else {
		Write-Host -ForegroundColor Red "Unable to connect to $($URL), debug info:"
		$response
	}
}
function Get-VIType{
    [cmdletbinding()]
    param(
    [parameter(ValueFromPipeline=$true)]
    [VMware.Vim.ManagedObjectReference]
    $MoRef)

    process{
        $leaf = Get-View $MoRef
        if($leaf.ChildEntity){
            $leaf.ChildEntity | Get-VIType
        }
        if($leaf.HostFolder){
            $leaf.HostFolder | Get-VIType
        }
        if($leaf.VMFolder){
            $leaf.VMFolder | Get-VIType
        }
        if($leaf.NetworkFolder){
            $leaf.NetworkFolder | Get-VIType
        }
        if($leaf.DatastoreFolder){
            $leaf.DatastoreFolder | Get-VIType
        }
        if($leaf.Host -and $leaf.Host[0].GetType().Name -ne "DatastoreHostMount"){
            $leaf.Host | Get-VIType
        }

        $leaf.MoRef.Type
    }
}

Function Get-vShieldService ($VMHost) {
	$MoRef = ($VMHost.Id).trim("HostSystem-")
	$XML = Get-vShieldAPI -URL "https://$vShieldIP/api/1.0/vshield/$MoRef"
	$XML.vShieldConfiguration.InstallStatus | Select -ExpandProperty InstalledServices
}
Function Get-vShieldSecurityGroup ($Datacenter) {
	$MoRef = ($Datacenter.Id).trim("Datacenter-")
	$XML = Get-vShieldAPI -URL "https://$vShieldIP/api/2.0/services/securitygroup/scope/$MoRef"
	$XML.list.securitygroup | Foreach {
		$AllInfo = New-Object -TypeName PSObject -Property @{
			ID = $_.objectId
			Name = $_.name
			Member = $_.member | Select -ExpandProperty Name
		}
		$AllInfo
	}
}
Function Set-vShieldSecurityGroup ($Add, $Remove, $Datacenter, $SecurityGroup, $VM) {
	$VMMoRef = ($VM.Id).trim("VirtualMachine-")
	$SGId = (Get-vShieldSecurityGroup -datacenter ($Datacenter) | Where {$_.name -eq $SecurityGroup}).id
	If ($Add) {
		$SetSG = Set-vShieldAPI -URL "https://$vShieldIP/api/2.0/services/securitygroup/$SGId/members/$VMMoRef"
	} Else {
		$SetSG = Remove-vShieldAPI -URL "https://$vShieldIP/api/2.0/services/securitygroup/$SGId/members/$VMMoRef"
	}
	Get-vShieldSecurityGroup -datacenter ($Datacenter) | Where {$_.name -eq $SecurityGroup}
}

Function Get-vSDSScanStatus {
	$XML = Get-vShieldAPI -URL "https://$vShieldIP/api/2.0/dlp/scanstatus"
	$XML.DlpScanStatus	| Foreach {	
		$Status = New-Object -TypeName PSObject -Property @{
			Status = $_.currentScanState
			VMsInProgress = $_.vmsInProgress
			VMsCompleted = $_.vmsCompleted
		}
		$Status
	}
}
Function Get-vSDSPolicy {
	$XML = Get-vShieldAPI -URL "https://$vShieldIP/api/2.0/dlp/policy/saved"
	$XML.DlpPolicy
}
Function Get-vSDSRegulation {
	$XML = Get-vShieldAPI -URL "https://$vShieldIP/api/2.0/dlp/regulation"
	$XML.set | Select -ExpandProperty Regulation
}
Function Get-vSDSViolationCount ($Datacenter, $VMHost) {
	If ($Datacenter) {
		$MoRef = ($Datacenter.Id).trim("Datacenter-")
	}
	If ($VMHost) {
		$MoRef = ($VMHost.Id).trim("HostSystem-")
	}
	$XML = Get-vShieldAPI -URL "https://$vShieldIP/api/2.0/dlp/violations/$MoRef"
	$XML.list.Violations | Foreach {
		$Vio = New-Object -TypeName PSObject -Property @{
			RegulationViolated = $_.regulation.name
			Count = $_.violationCount
		}
		$Vio
	}
}
Function Get-vSDSViolationFile ($Datacenter, $VMHost) {
	If ($Datacenter) {
		$MoRef = ($Datacenter.Id).trim("Datacenter-")
	}
	If ($VMHost) {
		$MoRef = ($VMHost.Id).trim("HostSystem-")
	}
	$XML = Get-vShieldAPI -URL "https://$vShieldIP/api/2.0/dlp/violatingfiles/$($MoRef)?pagesize=5000&startindex=0"
	$XML.ViolatingFiles.dataPage.ViolatingFile | Foreach {
		$AllInfo = New-Object -TypeName PSObject -Property @{
			ID = $_.identifier
			DatacenterName = $_.dataCenter.name
			ClusterName = $_.cluster.name
			VM = $_.vm.name
			FileName = $_.fileName
			MatchedRegulations = $_.violations.ViolationInfo | Foreach { $_.regulation.name }
			LastModified = $_.fileLastModifiedTime.InnerXml
			ViolationLastDetected = $_.violations.ViolationInfo | Foreach { $_.lastViolationReportedTime.InnerXml }
		}
		$AllInfo
	}
}
Function Get-vSDSEvents {
	Get-VIEvent | Where { $_.FullFormattedMessage -like "SDD *"}
}

Function Get-vSAppStatus ($Datacenter) {
	$MoRef = ($Datacenter.Id).trim("Datacenter-")
	$XML = Get-vShieldAPI -URL "https://$vShieldIP/api/2.0/app/firewall/$($MoRef)/state"
	$XML.VshieldAppConfiguration.datacenterState | Foreach {
		$AllInfo = New-Object -TypeName PSObject -Property @{
			ID = $_.datacenterId
			Name = $Datacenter.name
			Status = $_.status
		}
		$AllInfo
	}
}
Function Get-vSAppProtocol {
	$XML = Get-vShieldAPI -URL "https://$vShieldIP/api/2.0/app/firewall/protocols"
	$XML.VshieldAppConfiguration.protocolTypes
}
Function Get-vSAppApplication {
	$XML = Get-vShieldAPI -URL "https://$vShieldIP/api/2.0/app/firewall/protocols/application"
	$XML.VshieldAppConfiguration.protocolsList.protocol
}
Function Get-vSAppProtocolEthernet {
	$XML = Get-vShieldAPI -URL "https://$vShieldIP/api/2.0/app/firewall/protocols/ethernet"
	$XML.VshieldAppConfiguration.protocolsList.protocol | Foreach {
		$Obj = New-Object -TypeName PSObject -Property @{
			Layer = "Layer2"
			Type = "ethernet"
			Protocol = $_.Name
			Value = $_.Value
		}
		$Obj
	}
}
Function Get-vSAppProtocolIPv4 {
	$XML = Get-vShieldAPI -URL "https://$vShieldIP/api/2.0/app/firewall/protocols/ipv4"
	$XML.VshieldAppConfiguration.protocolsList.protocol | Foreach {
		$Obj = New-Object -TypeName PSObject -Property @{
			Layer = "Layer3"
			Type = "ipv4"
			Protocol = $_.Name
			Value = $_.Value
		}
		$Obj
	}
}
Function Get-vSAppProtocolICMP {
	$XML = Get-vShieldAPI -URL "https://$vShieldIP/api/2.0/app/firewall/protocols/icmp"
	$XML.VshieldAppConfiguration.protocolsList.protocol | Foreach {
		$Obj = New-Object -TypeName PSObject -Property @{
			Layer = "Layer3"
			Type = "icmp"
			Protocol = $_.Name
			Value = $_.Value
		}
		$Obj
	}
}
Function Get-vSAppAllProtocol {
	$All = @()
	$XML = Get-vShieldAPI -URL "https://$vShieldIP/api/2.0/app/firewall/protocols/icmp"
	$XML.VshieldAppConfiguration.protocolsList.protocol | Foreach {
		$Obj = New-Object -TypeName PSObject -Property @{
			Layer = "Layer3"
			Type = "icmp"
			Protocol = $_.Name
			Value = $_.Value
		}
		$All += $Obj
	}
	$XML = Get-vShieldAPI -URL "https://$vShieldIP/api/2.0/app/firewall/protocols/ipv4"
	$XML.VshieldAppConfiguration.protocolsList.protocol | Foreach {
		$Obj = New-Object -TypeName PSObject -Property @{
			Layer = "Layer3"
			Type = "ipv4"
			Protocol = $_.Name
			Value = $_.Value
		}
		$All += $Obj
	}
	$XML = Get-vShieldAPI -URL "https://$vShieldIP/api/2.0/app/firewall/protocols/ethernet"
	$XML.VshieldAppConfiguration.protocolsList.protocol | Foreach {
		$Obj = New-Object -TypeName PSObject -Property @{
			Layer = "Layer2"
			Type = "ethernet"
			Protocol = $_.Name
			Value = $_.Value
		}
		$All += $Obj
	}
	$All | Sort Layer
}
Function Get-vSAppApplicationInfo ($ID) {
	$XML = Get-vShieldAPI -URL "https://$vShieldIP/api/2.0/services/application/$($ID)"
	$XML.application | Foreach {
		$Obj = New-Object -TypeName PSObject -Property @{
			ID = $_.objectID
			Name = $_.Name
			Type = $_.objectTypeName
		}
		$Obj
	}
}
Function Get-vCenterObject ($ID, $Datacenter){
	# The complete vCenter
	# $si = Get-View ServiceInstance
	# Get-VIType -MoRef $si.Content.RootFolder | Sort-Object -Unique

	# From a specific datacenter
	If (-not $Types) {	
		$Types = Get-VIType -MoRef $Datacenter.Extensiondata.MoRef | Sort-Object -Unique
	}

	$count = 0
	$Total = $Types.Count
	do {
		$Match = Get-View "$($Types[$count])-$ID" -ErrorAction SilentlyContinue
		$count++
	} until (($count -eq $Total) -or ($Match))

	$Match.Name
}
Function Get-vSAppFirewall ($Datacenter, $Cluster) {
	If ($Datacenter) {
		$MoRef = ($Datacenter.Id).trim("Datacenter-")
	}
	If ($Cluster) {
		$MoRef = ($VMHost.Id).trim("HostSystem-")
	}
	$XML = Get-vShieldAPI -URL "https://$vShieldIP/api/2.0/app/firewall/$MoRef/config?list=config"
	$XML.VshieldAppConfiguration.firewallConfiguration.layer3firewallrule | Where {$_.destination.address.containerId } | Foreach {
		if ($_.disabled -eq "false"){
			$Enabled = $true
		} Else {
			$Enabled = $false
		}
		if ($_.logged -eq "false"){
			$Logged = $false
		} Else {
			$Logged = $true
		}
		$AllInfo = New-Object -TypeName PSObject -Property @{
			ID = $_.id
			Layer = "Layer 3"
			Source = (Get-vCenterObject -ID $_.source.address.containerId -datacenter $Datacenter)
			SourceID = $_.source.address.containerId
			Destination = (Get-vCenterObject -ID $_.destination.address.containerId -datacenter $Datacenter)
			DestinationID = $_.destination.address.containerId
			ApplicationProtocolsPorts = (Get-vSAppApplicationInfo -ID $_.destination.application.applicationSetId).Name
			Action = $_.action
			Logging = $Logged
			Enabled = $Enabled
			Notes = $_.notes
		}
		$AllInfo
	}
}
Function Get-vSAppApplication ($Datacenter) {
	$MoRef = ($Datacenter.Id).trim("Datacenter-")
	$XML = Get-vShieldAPI -URL "https://$vShieldIP/api/2.0/services/application/scope/$($MoRef)"
	$XML.list.application | Foreach {
		$Obj = New-Object -TypeName PSObject -Property @{
			ID = $_.objectId
			Name = $_.Name
			Type = $_.objectTypeName
		}
		$Obj
	}
}

#$username = "admin"
#$password = "default"
#$vshieldIP = "192.168.0.88"


#Connect-VIServer 192.168.0.11 -User Administrator -Password Ra1nb0w

#$SecurityGroups = Get-vShieldSecurityGroup (Get-Datacenter London)

#Write-Host -ForegroundColor Yellow "vShield Security Groups:"
#$SecurityGroups

#Foreach ($Group in $SecurityGroups) {
#	if ($Group.Member) {
#		Write-Host -ForegroundColor Yellow "VM Objects for $($Group.Name)"
#		$Group.Member | Foreach {
#			$VMName = $_.Name
#			Get-VM $VMName | Select Name, VMHost
#		}
#	}
#}

#Write-Host -ForegroundColor Yellow "Data Security Scan Status:"
#Get-vSDSScanStatus

#Write-Host -ForegroundColor Yellow "Data Security Policys:"
#Get-vSDSPolicy

#Write-Host -ForegroundColor Yellow "Data Security Policy Regulations:"
#Get-vSDSPolicy | Select -ExpandProperty Regulations

#Write-Host -ForegroundColor Yellow "All Regulations"
#Get-vSDSRegulation

#Write-Host -ForegroundColor Yellow "Data Security Violation Count"
#Get-vSDSViolationCount -Datacenter (Get-Datacenter London)

#Add Multiple VMs to a Security Group
#$VMObjects = Get-VM "VM*"
#$Datacenter = Get-Datacenter London
#$VMObjects | Foreach {
#	Set-vShieldSecurityGroup -Add $true -Datacenter $Datacenter -SecurityGroup "PCI Uncompliant" -VM $_
#}

#Removing Multiple VMS from a Security Group
#$VMObjects = Get-VM "VM*"
#$Datacenter = Get-Datacenter London
#$VMObjects | Foreach {
#	Set-vShieldSecurityGroup -Remove $true -Datacenter $Datacenter -SecurityGroup "PCI Uncompliant" -VM $_
#}

#Get the status of vShield App
#Get-vSAppStatus (Get-Datacenter London)

#Start of Demo Script

#Write-Host -ForegroundColor Yellow "Data Security Violation File"
#$Violations = Get-vSDSViolationFile -Datacenter (Get-Datacenter London) | Sort-Object -property VM -Unique
#
#$SecurityGroups = Get-vShieldSecurityGroup (Get-Datacenter London)
#
#Foreach ($Violation in $Violations) {
#	Write "$($violation.VM) has violated the following policies:"
#	$Violation.MatchedRegulations | Foreach {
#		"...$($_.regulation.name)"
#		
#	}
#	Read-Host "Press any key to continue..."
#	$SecurityGroups | Where { $_.Member -contains $Violation.VM } | Foreach {
#		Write "$($violation.VM) is a member of vShield Security Group: $($_.Name)"
#	}
#	Read-Host "Press any key to continue..."
#	$VMObject = Get-VM $Violation.VM
#	Write "Moving $($violation.VM) into PCI Uncompliant security group..."
#	$SG = Set-vShieldSecurityGroup -Datacenter (Get-Datacenter London) -SecurityGroup "PCI Uncompliant" -VM $VMObject
#	
#	Read-Host "Press any key to continue..."
#	Write "PCI Uncompliant Group now contains:"
#	$SG | Select -ExpandProperty Member
#}
#
#$Violations = Get-vSDSViolationFile -Datacenter (Get-Datacenter London)
#
#Send-Gmail -From "ajw.renouf@gmail.com" -To "renoufa@vmware.com" -subj "Security Violated files" -body ($Violations | Out-String)

#List all App Firewall rules
#Get-vSAppFirewall -datacenter (Get-Datacenter London) 

# List all Applications
#Get-vSAppApplication -Datacenter (Get-Datacenter London)