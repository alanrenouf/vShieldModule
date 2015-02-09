Function Connect-vShieldServer {
	<#
		.SYNOPSIS
			Connects to a vShield Manager Server.

		.DESCRIPTION
			Connects to a vShield Manager Server. The cmdlet starts a new session with a vShield Manager Server using the specified parameters.

		.PARAMETER  Server
			Specify the IP address or the DNS name of the vSphere server to which you want to connect.

		.PARAMETER  Username
			Specify the user name you want to use for authenticating with the server. 

		.PARAMETER  Password
			Specifies the password you want to use for authenticating with the server.
			
		.EXAMPLE
			PS C:\> Connect-vShieldServer -server "192.168.0.88" -username "admin" -password "default"
	#>
	[CmdletBinding()]
	Param (
		[Parameter(ValueFromPipeline=$true)]
		$Server,
		$Username,
		$Password
	)
	process {
		
		if ($Global:DefaultvShieldServer) {
			return		
		}
		$httpClient = [System.Net.WebRequest]::Create("https://$server/api/2.0/global/heartbeat")
		
		$authbytes = [System.Text.Encoding]::ASCII.GetBytes($username + ":" + $password)
		$base64 = [System.Convert]::ToBase64String($authbytes)  
		$authorization = "Authorization: Basic " + $base64
		$httpClient.Headers.Add($authorization)
		
		$httpClient.Method = "GET"
		$response = $httpClient.GetResponse()
		If ($response.StatusCode -eq "OK") {
			$Global:DefaultvShieldServer = New-Object -TypeName PSObject -Property @{
				Name = $Server
				ServerUri = "https://$server/"
				Authorization = $authorization
			}
		Write-Host -ForegroundColor Yellow "Connected Successfully to $Server"
		} Else {
			Throw "Unable to connect to $Server, debug info:"
			Throw $response
		} 
	}
}
Function Invoke-RestAPI {
		<#
		.SYNOPSIS
			Invokes a restfull API.

		.DESCRIPTION
			Connects to a restfull API and returns data.

		.PARAMETER  URL
			Specify the URL to use when accessing the rest api.

		.PARAMETER  Get
			Specifies that you will be using the GET Method 

		.PARAMETER  Put
			Specifies that you will be using the PUT Method 
			
		.PARAMETER  Delete
			Specifies that you will be using the DELETE Method 
		
		.PARAMETER  Post
			Specifies that you will be using posting data 
		
		.PARAMETER  Data
			Specifies the data you will be using in a post method
		
		.EXAMPLE
			PS C:\> Invoke-RestAPI -Get -URL "https://192.168.0.88/api/2.0/app/firewall/protocols"
	#>
	Param (
		$URI,
		[System.Management.Automation.SwitchParameter]$Get,
		[System.Management.Automation.SwitchParameter]$Put,
		[System.Management.Automation.SwitchParameter]$Delete,
		[System.Management.Automation.SwitchParameter]$Post,
		$Data
	)
	process {
		if ((-not $Get) -and (-not $Put) -and (-not $Delete) -and (-not $Post)){
			Throw "No Method used, please specify either Get, Put, Delete or Post"
			return
		}
		if (-not $URI) {
			Throw "No URI Specified"
			return
		}
		if ($post) {
			If (-not $data) {
				Throw "You must use the -Data parameter when specifying the Post parameter"
				return
			}
			$wc = New-Object System.Net.WebClient

			# Add Authorization headers
			$URL = ($Global:DefaultvShieldServer.ServerUri) + $URI
			$wc.Headers.Add(($Global:DefaultvShieldServer.Authorization))
			$wc.UploadString($URI, "POST", $data)
			return
		}
		
		
		# Set Method
		if ($Get) { $Method = "GET" }
		if ($Put) { $Method = "PUT" }
		if ($Delete) { $Method = "DELETE" }
		
		$httpClient = [System.Net.WebRequest]::Create($URI)
		# Add Authorization headers
		$httpClient.Headers.Add($Global:DefaultvShieldServer.Authorization)
		$httpClient.Method = $Method
		$response = $httpClient.GetResponse()	
		If ($Get) {
			If ($response.StatusCode -eq "OK") {
				$reader = New-Object System.IO.StreamReader($response.GetResponseStream())
				[xml]$XML = $reader.ReadToEnd()
				$Global:DebugXML = $XML
				$XML
				return
			} Else {
				Throw "Unable to connect to $($URI)"
				return
			}
		}
	}
}
Function Get-vShieldCommand {
	Get-Command -Module vShield
}
Function Get-vShieldService {
	<#
		.SYNOPSIS
			Lists the status of installed vShield services.

		.DESCRIPTION
			Lists the status of installed vShield services.

		.PARAMETER  VMHost
			The VMHost object to check.

		.EXAMPLE
			Get-vShieldService

		.EXAMPLE
			Get-vShieldService -VMHost (Get-VMHost virtuesx1*)
	#>
	Param (
		$VMHost
	) 
	
	PROCESS {
		if (-not $VMHost) {
			$VMHost = Get-VMHost 
		}
		Foreach ($VMH in $VMHost) {
			$MoRef = ($VMH.Id).trim("HostSystem-")
			$XML = Invoke-RestAPI -Get -URI "$($DefaultvShieldServer.ServerURI)api/1.0/vshield/$MoRef"
			$XML.vShieldConfiguration.InstallStatus | Foreach {	
				$Status = New-Object -TypeName PSObject -Property @{
					VMHost = $VMH.Name
					Progress = $null
					ProgressInfo = $null
					vShieldAppInstalled = $false
					vShieldEndPointInstalled = $false
				}
				If ($_.ProgressState) {
					$Status.Progress = $_.ProgressState
					$Status.ProgressInfo = $_.ProgressSubState
				}
				If ($_.InstalledServices) {
					$Status.vShieldAppInstalled = $_.InstalledServices.VszInstalled
					$Status.vShieldEndPointInstalled = $_.InstalledServices.EpsecInstalled
				}
				$Status
			}
		}
	}
}
Function Get-vShieldSecurityGroup {
	<#
		.SYNOPSIS
			Lists all security groups and members.

		.DESCRIPTION
			Lists all security groups and members.

		.PARAMETER  Datacenter
			The Datacenter which contains the security groups.

		.EXAMPLE
			Get-vShieldSecurityGroup

		.EXAMPLE
			Get-vShieldSecurityGroup -Datacenter (Get-Datacenter London)
	#>
	Param (
		$Datacenter
	)
	If (-Not $Datacenter) {
		$Datacenter = Get-Datacenter 
	}
	Foreach ($DC in $Datacenter) {
		$MoRef = ($DC.Id).trim("Datacenter-")
		$XML = Invoke-RestAPI -Get -URI "$($DefaultvShieldServer.ServerURI)api/2.0/services/securitygroup/scope/$MoRef"
		If ($XML.list.length -eq 0) { return }
		$XML.list.securitygroup | Foreach {
			$AllInfo = New-Object -TypeName PSObject -Property @{
				ID = $_.objectId
				Datacenter = $DC.Name
				Name = $_.name
				Description = $_.description
				Member = $_.member | Select Name, ObjectTypeName, ObjectID
			}
			$AllInfo
		}
	}
}
Function Set-vShieldSecurityGroup {
	<#
		.SYNOPSIS
			Ammends security groups.

		.DESCRIPTION
			Ammends security groups, currently only setup to use with security groups
			at a datacenter level and only to add/remove VMs only.

		.PARAMETER  Add
			Use this paramater to add the VM to the group.
			
		.PARAMETER  Remove
			Use this paramater to Remove the VM to the group.
		
		.PARAMETER  Datacenter
			The Datacenter which contains the security group.

		.PARAMETER  SecurityGroup
			The Name of the Security Group.

		.PARAMETER  VM
			The VM to Add/Remove to the Security Group.

		.EXAMPLE
			Set-vShieldSecurityGroup -Add -Datacenter (Get-Datacenter Virtu-Al) -SecurityGroup "View Servers and Clients" -VM (Get-VM View01)

		.EXAMPLE
			Set-vShieldSecurityGroup -Remove -Datacenter (Get-Datacenter Virtu-Al) -SecurityGroup "View Servers and Clients" -VM (Get-VM View01)

	#>
	Param (
		[System.Management.Automation.SwitchParameter]$Add, 
		[System.Management.Automation.SwitchParameter]$Remove, 
		$Datacenter, 
		$SecurityGroup, 
		$VM
	)
	$VMMoRef = ($VM.Id).trim("VirtualMachine-")
	$SGId = (Get-vShieldSecurityGroup -datacenter ($Datacenter) | Where {$_.name -eq $SecurityGroup}).id
	If ($Add) {
		$SetSG = Invoke-RestAPI -Put -URI "$($DefaultvShieldServer.ServerURI)api/2.0/services/securitygroup/$SGId/members/$VMMoRef"
	} Else {
		$SetSG = Invoke-RestAPI -Delete -URI "$($DefaultvShieldServer.ServerURI)api/2.0/services/securitygroup/$SGId/members/$VMMoRef"
	}
	Get-vShieldSecurityGroup -datacenter ($Datacenter) | Where {$_.name -eq $SecurityGroup}
}

Function Get-vSDSScanStatus {
	<#
		.SYNOPSIS
			Lists the Data Security Status.

		.DESCRIPTION
			Lists the Data Security Status.

		.EXAMPLE
			Get-vSDSScanStatus

	#>
	$XML = Invoke-RestAPI -Get -URI "$($DefaultvShieldServer.ServerURI)api/2.0/dlp/scanstatus"
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
	<#
		.SYNOPSIS
			Lists the Policies currently setup.

		.DESCRIPTION
			Lists the Data Security policies.

		.EXAMPLE
			Get-vSDSPolicy

	#>
	$XML = Invoke-RestAPI -Get -URI "$($DefaultvShieldServer.ServerURI)api/2.0/dlp/policy/saved"
	$XML.DlpPolicy
}
Function Get-vSDSRegulation {
	<#
		.SYNOPSIS
			Lists the Data security Regulations available.

		.DESCRIPTION
			Lists the Data Security Regulations available.
			
		.EXAMPLE
		Get-vSDSRegulation

	#>
	$XML = Invoke-RestAPI -Get -URI "$($DefaultvShieldServer.ServerURI)api/2.0/dlp/regulation"
	$XML.set | Select -ExpandProperty Regulation
}
Function Get-vSDSViolationCount {
	<#
		.SYNOPSIS
			Lists the Data security violation counts.

		.DESCRIPTION
			Lists the Data Security violation counts.

		.EXAMPLE
			Get-vSDSViolationCount
			
		.PARAMETER  Datacenter
			The Datacenter which to gather information from.

	#>
	Param (
		$Datacenter
	)
	Process {
		If (-not $Datacenter) {
			$Datacenter = Get-Datacenter
		}
		Foreach ($DC in $Datacenter) {
			$MoRef = ($DC.Id).trim("Datacenter-")
			$XML = Invoke-RestAPI -Get -URI "$($DefaultvShieldServer.ServerURI)api/2.0/dlp/violations/$MoRef"
			$XML.list.Violations | Foreach {
				$Vio = New-Object -TypeName PSObject -Property @{
					Datacenter = $DC.Name
					RegulationViolated = $_.regulation.name
					Count = $_.violationCount
				}
				$Vio
			}
		}
	}
}
Function Get-vSDSViolationFile {
	<#
		.SYNOPSIS
			Lists the Data security violation files.

		.DESCRIPTION
			Lists the Data Security violation files.

		.PARAMETER  Datacenter
			The Datacenter which to gather information from.
			
		.EXAMPLE
			Get-vSDSViolationFile

	#>
	Param (
		$Datacenter
	)
	Process {
		If (-not $Datacenter) {
			$Datacenter = Get-Datacenter
		}
		Foreach ($DC in $Datacenter) {
			$MoRef = ($DC.Id).trim("Datacenter-")
			$XML = Invoke-RestAPI -Get -URI "$($DefaultvShieldServer.ServerURI)api/2.0/dlp/violatingfiles/$($MoRef)?pagesize=5000&startindex=0"
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
	}
}
Function Get-vSDSEvents {
	<#
		.SYNOPSIS
			Lists the Data security events in vCenter.

		.DESCRIPTION
			Lists the Data Security events in vCenter for all objects
			or for a given VM.

		.PARAMETER  VM
			The VM to find events for.
			
		.EXAMPLE
			Get-vSDSEvents

	#>
	Process {
		If ($VM) {
			$VM | Get-VIEvent | Where { $_.FullFormattedMessage -like "vShield Data Security *"}
		} Else {
			Get-VIEvent | Where { $_.FullFormattedMessage -like "vShield Data Security *"}
		}
	}
}

Function Get-vSAppStatus {
	<#
		.SYNOPSIS
			Lists the Status of vShield App for a datacenter.

		.DESCRIPTION
			Lists the Status of vShield App for a datacenter.

		.PARAMETER  Datacenter
			The Datacenter which to gather information from.
			
		.EXAMPLE
			Get-vSAppStatus
		
		.EXAMPLE
			Get-vSAppStatus -Datacenter (Get-Datacenter Virtu-Al)

	#>
	Param ($Datacenter)
	Process {
		If (-not $Datacenter) {
			$Datacenter = Get-Datacenter
		}
		Foreach ($DC in $Datacenter) {
			$MoRef = ($DC.Id).trim("Datacenter-")
			$XML = Invoke-RestAPI -Get -URI "$($DefaultvShieldServer.ServerURI)api/2.0/app/firewall/$($MoRef)/state"
			$XML.VshieldAppConfiguration.datacenterState | Foreach {
				$AllInfo = New-Object -TypeName PSObject -Property @{
					ID = $_.datacenterId
					Name = $DC.name
					Status = $_.status
				}
				$AllInfo
			}
		}
	}
}
Function Get-vSAppProtocol {
	<#
		.SYNOPSIS
			Lists the protocols available.

		.DESCRIPTION
			Lists the protocols available.
			
		.EXAMPLE
			Get-vSAppProtocol

	#>
	Process {
		$XML = Invoke-RestAPI -Get -URI "$($DefaultvShieldServer.ServerURI)api/2.0/app/firewall/protocols"
		$XML.VshieldAppConfiguration.protocolTypes
	}
}
Function Get-vSAppProtocolType {
	<#
		.SYNOPSIS
			Lists the Protocol Type available.

		.DESCRIPTION
			Lists the Protocol Type available.
			
		.EXAMPLE
			Get-vSAppProtocolType

	#>
	Process {
		$XML = Invoke-RestAPI -Get -URI "$($DefaultvShieldServer.ServerURI)api/2.0/app/firewall/protocols/application"
		$XML.VshieldAppConfiguration.protocolsList.protocol
	}
}
Function Get-vSAppProtocolEthernet {
	<#
		.SYNOPSIS
			Lists the Ethernet Protocols.

		.DESCRIPTION
			Lists the Ethernet Protocols.
			
		.EXAMPLE
			Get-vSAppProtocolEthernet

	#>
	Process {
		$XML = Invoke-RestAPI -Get -URI "$($DefaultvShieldServer.ServerURI)api/2.0/app/firewall/protocols/ethernet"
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
}
Function Get-vSAppProtocolIPv4  {
	<#
		.SYNOPSIS
			Lists the IPv4 Protocols.

		.DESCRIPTION
			Lists the IPv4 Protocols.
			
		.EXAMPLE
			Get-vSAppProtocolIPv4

	#>
	Process {
		$XML = Invoke-RestAPI -Get -URI "$($DefaultvShieldServer.ServerURI)api/2.0/app/firewall/protocols/ipv4"
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
}
Function Get-vSAppProtocolICMP {
	<#
		.SYNOPSIS
			Lists the ICMP Protocols.

		.DESCRIPTION
			Lists the ICMP Protocols.
			
		.EXAMPLE
			Get-vSAppProtocolICMP

	#>
	Process {
		$XML = Invoke-RestAPI -Get -URI "$($DefaultvShieldServer.ServerURI)api/2.0/app/firewall/protocols/icmp"
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
}