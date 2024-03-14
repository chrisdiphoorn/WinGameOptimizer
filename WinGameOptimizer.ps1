	# WinGameOptimizer.ps1

	#Requires -Version 5.1

	Set-StrictMode -Version Latest

	#Import-Module StartLayout
	[console]::CursorVisible =$False

	# Ensure TLS 1.2 is enabled for HTTPS traffic
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

	# This is usefull to ensure the script has some resiliency and does not jump to any conclusions too quickly...
	$Sleep_Milliseconds = 100 
	$BigSleep_Milliseconds = 1000
	
	#This is the LogFile that is used to undo the last run
	$LogName = "WinGameOptimizer.log"
	
	# Special Variables used to collect information
	$PreviousResults = @()
	$script:isXboxRunning = $false
	$script:isWIFIRunning = $false
	$script:isDomain = (gwmi win32_computersystem).partofdomain
	$script:isWindows10 = $false
	$script:isWindows11 = $false
	$script:isWindows12 = $false
	$script:opt = 1
	
	$script:FoundTasks = @() 
	$script:FoundApps = @() 
	$script:FoundServices = @() 
		
	#Get the Users Security Role on the PC
	[Security.Principal.WindowsPrincipal]$user = [Security.Principal.WindowsIdentity]::GetCurrent()
	$isAdmin = $user.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
	
	# Get Powershell Version - May Need to move to PS 7 to get any new features, but try to stick with 5.1 for the moment.
	$_PSVersion = $PSVersionTable.PSVersion.Major

	$crlf = [Environment]::NewLine	# "`r`n" in Windows

	if($isAdmin -eq $true) {
		$ExecPolicy = (Get-ExecutionPolicy)

		if( $ExecPolicy -eq 'Unrestricted' -OR $ExecPolicy -eq 'Bypass') {
	
			# Detect Windows 11 - = select Version,ProductType from Win32_OperatingSystem where Version LIKE "10.0.2%" and ProductType = "1"
			$osType = ''				#EG: Windows 11 Pro
			$osEdition = ''				#EG: Pro, Home
			$OsVersion = ''				#EG: 10
			$OsName = ''				#EG: Microsoft Windows Server 2022 Standard
			$OsDisplayVersion = ''		#EG: 21H2
			
			
			$_OSINFO =[System.Environment]::OSVersion.Version
			$_OSNAME = (Get-CimInstance Win32_OperatingSystem) | Select-Object Caption
			$_OSDVER = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion
			if($_OSINFO) {
				if($OsVersion -eq '') {
					$OsVersion = $_OSINFO.Major
				}
			}
			if($_OSNAME) {
				$OsName = $_OSNAME.Caption
			}
			if($_OSDVER) {
				$OsDisplayVersion = "$_OSDVER ("+$_OSINFO.Major +'.' + $_OSINFO.Minor+"." + $_OSINFO.Build+")"
			}

			if($OsName -like "*Server*") {
				$osType = 'Windows Server'
				$osEdition = 'Server'
				if($OsName -like "*2016*") {
					$osType = 'Server 2016'
					$OsVersion = '2016'
					
				}
				if($OsName -like "*2019*") {
					$osType = 'Server 2019'
					$OsVersion = '2019'
				}
				if($OsName -like "*2022*") {
					$osType = 'Server 2022'
					$OsVersion = '2022'
				}
			}
			if($OsName -like "*Home*") { 
				$osType = 'Windows ' + $OsVersion +' Home' 
				$osEdition = 'Home'
			}
			if($OsName -like "*Pro*") { 
				$osType = 'Windows '  + $OsVersion + ' Pro' 
				$osEdition = 'Pro'
			}
			if($OsName -like "*Business*") { 
				$osType = 'Windows '  	+ $OsVersion + ' Business' 
				$osEdition = 'Business'
			}
			
			if($OsName -like "Microsoft Windows 10*") {
					$script:isWindows10 = $true
			}
			if($OsName -like "Microsoft Windows 11*") {
					$script:isWindows11 = $true
			}
			if($OsName -like "Microsoft Windows 12*") {
					$script:isWindows12 = $true
			}
			
				
			$BiosCharacteristics = @{
			Name = 'BiosCharacteristics'
			Expression = {
			# property is an array, so process all values
			$result = foreach($value in $_.BiosCharacteristics)
			{
				switch([int]$value)	{
				0          {'Reserved'}
				1          {'Reserved'}
				2          {'Unknown'}
				3          {'BIOS Characteristics Not Supported'}
				4          {'ISA is supported'}
				5          {'MCA is supported'}
				6          {'EISA is supported'}
				7          {'PCI is supported'}
				8          {'PC Card (PCMCIA) is supported'}
				9          {'Plug and Play is supported'}
				10         {'APM is supported'}
				11         {'BIOS is Upgradeable (Flash)'}
				12         {'BIOS shadowing is allowed'}
				13         {'VL-VESA is supported'}
				14         {'ESCD support is available'}
				15         {'Boot from CD is supported'}
				16         {'Selectable Boot is supported'}
				17         {'BIOS ROM is socketed'}
				18         {'Boot From PC Card (PCMCIA) is supported'}
				19         {'EDD (Enhanced Disk Drive) Specification is supported'}
				20         {'Int 13h - Japanese Floppy for NEC 9800 1.2mb (3.5\", 1k Bytes/Sector, 360 RPM) is supported'}
				21         {'Int 13h - Japanese Floppy for Toshiba 1.2mb (3.5\", 360 RPM) is supported'}
				22         {'Int 13h - 5.25\" / 360 KB Floppy Services are supported'}
				23         {'Int 13h - 5.25\" /1.2MB Floppy Services are supported'}
				24         {'Int 13h - 3.5\" / 720 KB Floppy Services are supported'}
				25         {'Int 13h - 3.5\" / 2.88 MB Floppy Services are supported'}
				26         {'Int 5h, Print Screen Service is supported'}
				27         {'Int 9h, 8042 Keyboard services are supported'}
				28         {'Int 14h, Serial Services are supported'}
				29  	   {'Int 17h, printer services are supported'}
				30         {'Int 10h, CGA/Mono Video Services are supported'}
				31         {'NEC PC-98'}
				32         {'ACPI supported'}
				33         {'USB Legacy is supported'}
				34         {'AGP is supported'}
				35         {'I2O boot is supported'}
				36         {'LS-120 boot is supported'}
				37         {'ATAPI ZIP Drive boot is supported'}
				38         {'1394 boot is supported'}
				39         {'Smart Battery supported'}
				default    {"$value"}
			}
		
			}
			$result
			}	  
		}
	

	function Get-CurrentLocation
	{
		$currentPath = $PSScriptRoot                                                                                                     # AzureDevOps, Powershell
		if (!$currentPath) { $currentPath = Split-Path $pseditor.GetEditorContext().CurrentFile.Path -ErrorAction SilentlyContinue }     # VSCode
		if (!$currentPath) { $currentPath = Split-Path $psISE.CurrentFile.FullPath -ErrorAction SilentlyContinue }                       # PsISE
		return $currentPath + '\'
	}

	Function Update-RegistryValue($key, $name, $value, [Switch]$Verbose) {
		if ($Verbose) {Write-Debug "Updating value $key\$name ... "}
		$oldValue = Get-RegistryValue $key $name
		if ($oldValue -and ($oldValue -ne $value)) {
			if ($Verbose) {Write-Debug "Changing it from $oldValue to $value."}
			Set-RegistryValue $key $name $value
		} elseif ($oldvalue) {
			if ($Verbose) {Write-Debug "It already contains $value."}
		} else {
			if ($Verbose) {Write-Debug "Key and/or value does not exist."}
		}
	}


	Function Set-RegistryValue($Key, $Name, $Value, $PropertyType="String", [Switch]$Verbose) {
		if ((Get-RegistryValue $Key $Name) -ne $null) {
			if ($Verbose) {Write-Debug "Setting value $key\$name = $value"}
			Set-ItemProperty $Key -name $Name -value $Value >$null
		} else {
			if (! (Get-Item -ErrorAction SilentlyContinue $key)) {
			New-RegistryKey $Key -Verbose:$Verbose
			}
			if ($Verbose) {Write-Debug "Creating value $key\$name = $value"}
			New-ItemProperty $Key -name $Name -PropertyType $PropertyType -Value $Value >$null
		}
		return $null
	}

	Function Enum-RegistryValues($Key) {
		get-item $key | Select-Object -ExpandProperty property
	}

	Function New-RegistryKey($Key, [Switch]$Verbose) {
		$parent = Split-Path $key -Parent
		if (! (Get-Item -ErrorAction SilentlyContinue $parent)) {
			New-RegistryKey $parent -Verbose:$Verbose
		}
		if ($Verbose) {Write-Debug "Creating key $key\"}
		New-Item $key >$null
		return $null
	}

	Function Get-RegistryValue($key, $name, [Switch]$Verbose) {
		if ($Verbose) {Write-Debug "Reading value $key\$name"}
		$item = Get-ItemProperty -ErrorAction SilentlyContinue $key
		if ($item) {
			return $item.$name
		} else {
			return $null
		}
	}


	Function Format-Size()
	{
		[CmdletBinding()]
		Param (
			$Number,
			[switch]$Int
		)
	
		#Convert $Number to a Long Value
		[Long]$Size = $Number -as [Long]
	
		$return = $Null
		$fmat = "{0:0.00}"
	
		if ($Int.IsPresent) {
			$fmat = "{0:0}"
		}
	
		If     ($Size -gt 1TB) { $return = [string]::Format("$($fmat)Tb", $Size / 1TB) }
		ElseIf ($Size -gt 1GB) { $return = [string]::Format("$($fmat)Gb", $Size / 1GB) }
		ElseIf ($Size -gt 1MB) { $return = [string]::Format("$($fmat)Mb", $Size / 1MB) }
		ElseIf ($Size -gt 1KB) { $return = [string]::Format("$($fmat)Kb", $Size / 1KB) }
		ElseIf ($Size -gt 0)   { $return = [string]::Format("$($fmat)Bytes", $Size) }
		Else                   { $return = "0" }
		
		Return $return
	}

	# Return True if indexing has been sucessfully disabled
	function Disable-Indexing {
		Param($Drive)

		$result = $True   # Default is that Indexing is currently not enabled
		
		$obj = (Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='$Drive'")
		Start-Sleep -Milliseconds $Sleep_Milliseconds
				
		$indexing = $obj.IndexingEnabled
		
		if("$indexing" -eq $True){
			
			$runme= ($obj | Set-WmiInstance -Arguments @{IndexingEnabled=$False} | Out-Null)
			Start-Sleep -Seconds 2
			
			# Check again to ensure it has sucessfully disabled all Drive indexing?
			$obj = (Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='$Drive'")
			Start-Sleep -Milliseconds $Sleep_Milliseconds
					
			$indexing = $obj.IndexingEnabled
			
			if("$indexing" -eq $True){
				$result = $False
			}
		}
		
		return $result
	}

	Function Remove-UnusedPrinterDrivers
	{
		Param
		(
			#The name of the print server to clean up.
			[Parameter(Mandatory=$true)]
			[string]$PrintServerName
		)
		
		Write-Progress -Activity "Searching for Unused Drivers." -Status "..."
		$i = 0
		#Get all of the printer drivers
		$Drivers = Get-PrinterDriver -ComputerName $PrintServerName
		$Printers = Get-Printer -ComputerName $PrintServerName

		ForEach($Driver in $Drivers)
		{
			$PrintersUsingDriver = ($Printers | Where {$_.DriverName -eq $Driver.Name} | Measure).Count
			$i++
			$p = ($i / $tasks.count) * 100
			Write-Progress "Removing Unused Drivers." -Status "$([int]$p)% Complete." -percentComplete $p
			If ($PrintersUsingDriver -eq 0)
			{
				Try
				{
					Remove-PrinterDriver -Name $Driver.Name -ComputerName $PrintServerName -ErrorAction SilentlyContinue
				}
				Catch { }
				Start-Sleep -Milliseconds $Sleep_Milliseconds
			}
		}
		Write-Progress -Complete '(unused)'
		Start-Sleep -Milliseconds $BigSleep_Milliseconds
	}

	function GET-PrintSpooler {
		
		$service = Get-Service -name Spooler -ErrorAction SilentlyContinue
		$ServiceStatus = $service.Status
		$ServiceDisplayName = $service.DisplayName
	
		$result = $False
	
		if ($ServiceStatus -eq 'Running') {
			$result = $True
		}
		
		return $result
	}
	
	# Return True if Print Spooler has been secussfully stopped and disabled
	# Only modify the startup if the spooler was running in the firstplace. 
	Function Disable-PrintSpooler {
		
		Write-Progress -Activity "Disabling Print Spooler." -Status "..."
		
		$service = Get-Service -name Spooler -ErrorAction SilentlyContinue
		$ServiceStatus = $service.Status
		$ServiceDisplayName = $service.DisplayName
	
		$result = $True # Default is that spooler is currently not running
	
		if ($ServiceStatus -eq 'Running') {
        
			$ss=(Stop-Service -Name Spooler -Force -NoWait | Out-Null)
			Start-Sleep -Milliseconds $Sleep_Milliseconds
		
			$ss=(Set-Service -Name Spooler -StartupType 'Disabled' | Out-Null)
			Start-Sleep -Milliseconds $Sleep_Milliseconds
				
			$service = (Get-Service -name Spooler -ErrorAction SilentlyContinue)
			$ServiceStatus = $service.Status

			if ($ServiceStatus -ne 'Running') {
				$result = $True
			} else {
				$result = $False
			}
		}
		
		Write-Progress -Complete '(unused)'
		Start-Sleep -Milliseconds $Sleep_Milliseconds
		return $result
	}	
	
	Function Trim-HardDrives {
		
		$runtrim=(Optimize-Volume -DriveLetter C -ReTrim)
		
	}
	
	
	Function write-opt {
		write-host " $($script:opt). " -NoNewLine -ForegroundColor Green 
		$script:opt++
	}
	
	Function isServiceRunning ($Service) {
		$check = $null
		$result = $false
		try {
				$check = (Get-Service -Name $service -ErrorAction SilentlyContinue)
		} catch {}
		
		if($check -ne $null) {
			if($check.status -eq 'Running') {
				$result = $true
			}
		}
		return $result
	}
	
	function Get-FreeDiskSpace {
			$OS = (Get-WmiObject -Class Win32_OperatingSystem)
			$Disk = (Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$($os.SystemDrive)'" | Select @{Name="FreeGB";Expression={[math]::Round($_.FreeSpace / 1GB, 2)}})
			return $Disk.FreeGB
	}
		
	Function Clean-WindowsUpdate {
		
		Write-Progress -Activity "Running Windows Disk Cleanup." -Status "..."
		Start-Sleep -Milliseconds $Sleep_Milliseconds
		
		Try{
            Start-Process -FilePath Cleanmgr -ArgumentList '/sagerun:1' -Wait
        }
        Catch [System.Exception]{
			# Nothing to Report Here?
        }

		Write-Progress -Activity "Running DSM to Remove Old ServicePack Files." -Status "..."
		Start-Sleep -Milliseconds $Sleep_Milliseconds
		
		Try{
			$ErrorActionPreference = 'SilentlyContinue'
            $DISMResult = dism.exe /online /cleanup-Image /spsuperseded
        }
		Catch [System.Exception]{
            $ErrorActionPreference = 'SilentlyContinue'
            $DISMResult = $False
        }
		
		Write-Progress -Activity "Removing Old Update Files." -Status "..."
		Start-Sleep -Milliseconds $Sleep_Milliseconds
		
		$isRunning = (Get-Service -Name wuauserv -ErrorAction SilentlyContinue).Status
		
		Try{
            $ss=(Get-Service -Name wuauserv -ErrorAction SilentlyContinue| Stop-Service -NoWait -Force -ErrorAction Stop| Out-Null)
            $WUpdateError = $false
        }
        Catch [System.Exception]{
            $WUpdateError = $true
        }
        Finally{
            If($WUpdateError -eq $False){
                $rr=(Get-ChildItem "C:\Windows\SoftwareDistribution\*" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -force -recurse -ErrorAction SilentlyContinue)
                $ss=(Get-Service -Name wuauserv -ErrorAction SilentlyContinue| Start-Service -ErrorAction SilentlyContinue)
            } Else {
				if($isRunning = 'Running') {
					$ss=(Get-Service -Name wuauserv -ErrorAction SilentlyContinue| Start-Service -ErrorAction SilentlyContinue)
				}
            }
        }
		
		# Get final free disk space
		$After = Get-FreeDiskSpace

		# Calculate and display the freed disk space
		$Cleaned = $After - $Before

		Write-Progress -Complete '(unused)'
		Start-Sleep -Milliseconds $Sleep_Milliseconds
		return $Cleaned
	}
	
	Function Remove-Spotify {
	
		Write-Progress -Activity "Removing Spotify." -Status "..."
		Start-Sleep -Milliseconds $Sleep_Milliseconds
				
		$RunningApp = Get-Process -Name "spotify*"
		If ($RunningApp){
			try {
				$stopit=(Stop-Process -InputObject $RunningApp -Force | Out-Null)
			} catch {}
		}

		$UserFolders = Get-ChildItem -Directory "c:\users"
		ForEach ($Folder in $UserFolders) {
			$WorkingDir = "C:\\Users\\" + "$Folder"
			If (Test-Path $WorkingDir\appdata\roaming\spotify) {
				Start-Process -FilePath $WorkingDir\appdata\roaming\spotify\spotify.exe -ArgumentList "/uninstall /silent"
				Start-Sleep -s 10
				Remove-Item $WorkingDir\appdata\roaming\spotify -Force -Recurse
				Remove-Item $WorkingDir\appdata\local\spotify -Force -Recurse
				Remove-Item $WorkingDir\desktop\spotify.lnk -Force -Recurse
			}
		}

		# remove leftover listing in programs and features
		$UserKey = Get-ChildItem -Path Microsoft.PowerShell.Core\Registry::HKEY_USERS

		ForEach ($Key in $UserKey) {
			If (Test-Path Microsoft.PowerShell.Core\Registry::\$Key\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Spotify) {
				Remove-Item Microsoft.PowerShell.Core\Registry::\$Key\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Spotify -Force -Recurse
			}
		}
		Write-Progress -Complete '(unused)'
		Start-Sleep -Milliseconds $Sleep_Milliseconds
	}
	
	Function Remove-RegistryKeys {
    
    $Keys = @(
            
        #Remove Background Tasks
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
		#reg add HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR /f /t REG_DWORD /v "AppCaptureEnabled" /d 0
		#reg add HKEY_CURRENT_USER\System\GameConfigStore /f /t REG_DWORD /v "GameDVR_Enabled" /d 0

        #Windows File
        "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            
        #Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            
        #Scheduled Tasks to delete
        "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
            
        #Windows Protocol Keys
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
               
        #Windows Share Target
        "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    )
        
		#This writes the output of each key it is removing and also removes the keys listed above.
		ForEach ($Key in $Keys) {
			$rr=(Remove-Item $Key -Recurse| Out-Null)
		}
	}
	
	Function DisableCortana {
		
		$Cortana1 = "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"
		$Cortana2 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
		$Cortana3 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
		If (!(Test-Path $Cortana1)) {
			New-Item $Cortana1
		}
		Set-ItemProperty $Cortana1 AcceptedPrivacyPolicy -Value 0 
		If (!(Test-Path $Cortana2)) {
			New-Item $Cortana2
		}
		Set-ItemProperty $Cortana2 RestrictImplicitTextCollection -Value 1 
		Set-ItemProperty $Cortana2 RestrictImplicitInkCollection -Value 1 
		If (!(Test-Path $Cortana3)) {
			New-Item $Cortana3
		}
		Set-ItemProperty $Cortana3 HarvestContacts -Value 0
    
	}
	
	Function Update-HardDrives {
		# SSD life improvement
		# Encrypting the page file prevents malicious users from reading data that has been paged to a NTFS disk, but will also add processing overhead for file system operations.
		$_GetPagingFile = (fsutil behavior query encryptpagingfile)
		if($_GetPagingFile.NotContains('EncryptPagingFile = 0')) {
			fsutil behavior set EncryptPagingFile 0 | Out-Null
		}

		# The Last Access Time stamp displays an updated time each file and folder on a NTFS volume was last accessed.
		# Having the Last Access Time stamp enabled on an older or slower computer may cause file access to take longer.
		# 0	User Managed, Last Access Time Updates Enabled
		# 1	User Managed, Last Access Time Updates Disabled
		# 2 (default)	System Managed, Last Access Time Updates Enabled
		# 3	System Managed, Last Access Time Updates Disabled

		$_GetLastAccess = (fsutil behavior query DisableLastAccess)
		if($_GetLastAccess.NotContains('DisableLastAccess = 1')) {
			fsutil behavior set DisableLastAccess 1 | Out-Null
		}
	}
	
	Function Remove-OneDrive {
		
		Write-Progress -Activity "Removing OneDrive." -Status "Trying to Remove..."
		
		taskkill.exe /F /IM "OneDrive.exe" | Out-Null
		taskkill.exe /F /IM "explorer.exe" | Out-Null
		
		if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
			& "$env:systemroot\System32\OneDriveSetup.exe" /uninstall | Out-Null
		}
		if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
			& "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall | Out-Null
		}
	
		Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
		Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
		Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"
		# check if directory is empty before removing:
		If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
			Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
		}
	
		New-FolderForced -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive"
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1
	
		New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
		mkdir -Force "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
		Set-ItemProperty -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
		mkdir -Force "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
		Set-ItemProperty -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
		Remove-PSDrive "HKCR"
	

		reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
		reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
		reg unload "hku\Default"

		Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"
		
		Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ea SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
		
		Write-Progress -Complete '(unused)'
		Start-Sleep -Milliseconds $Sleep_Milliseconds
		
		$sp=(Start-Process "explorer.exe")
		
	}
	
	Function Remove-PinnedApps {
		
		$runme= (Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs" -Recurse  -Filter *uninstall*.lnk | ForEach-Object { Remove-Item $_.FullName })
						
		$RemoveItems = @(
			"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk"
			"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessibility\Speech Recognition.lnk"
			"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Calculator.lnk"
			"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Math Input Panel.lnk"
			"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Notepad.lnk"
			"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Paint.lnk"
			"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Remote Desktop Connection.lnk"
			"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Snipping Tool.lnk"
			"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Steps Recorder.lnk"
			"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Windows Media Player.lnk"
			"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Wordpad.lnk"
			"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\XPS Viewer.lnk"
			"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\System Tools\Character Map.lnk"
			"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\System Tools\Windows Server Backup.lnk"
		)
		foreach ($Item in $RemoveItems) {
			IF([System.IO.File]::Exists($Item) -eq $true) {
				$remove=(Remove-Item $Item | Out-Null)
			}
		}
		
	}
	
	Function Turnoff-Telementary {
		
		$DataCollection1 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
		$DataCollection2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
		$DataCollection3 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"    
		If (Test-Path $DataCollection1) {
			Set-ItemProperty $DataCollection1  AllowTelemetry -Value 0 
		}
		If (Test-Path $DataCollection2) {
			Set-ItemProperty $DataCollection2  AllowTelemetry -Value 0 
		}
		If (Test-Path $DataCollection3) {
			Set-ItemProperty $DataCollection3  AllowTelemetry -Value 0 
		}
    
		#Disabling Location Tracking

		$SensorState = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
		$LocationConfig = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"
		If (!(Test-Path $SensorState)) {
			New-Item $SensorState
		}
		Set-ItemProperty $SensorState SensorPermissionState -Value 0 
		If (!(Test-Path $LocationConfig)) {
				New-Item $LocationConfig
		}
		Set-ItemProperty $LocationConfig Status -Value 0 
			
		#Disables People icon on Taskbar

		$People = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
		If (Test-Path $People) {
			Set-ItemProperty $People -Name PeopleBand -Value 0
		}
	}
	
	Function Remove-Apps {
	
		$numApps = 0
		$i = 0
		$c = $FoundApps.count
		foreach  ($app in $script:FoundApps) {
			$i ++
			$p = ($i / $script:FoundApps.count) * 100
			Write-Progress "Removing $c Microsoft Apps." -status "$app" -percentComplete $p
			Start-Sleep -Milliseconds $Sleep_Milliseconds
			
			$isappid = $False
			$pos = $app.IndexOf(".")
			$posOK = $app.IndexOf(" .")
			IF($pos -ge 0 -AND $posOK -eq $false ) {$isappid = $true }
			
			if($app -like "*_8weky*" -OR $isappid -eq $True) {
				try {
					$remove = (winget uninstall -e --id $app --silent --accept-source-agreements)
					$numApps ++
				} catch {}
			} else {
				try {
					$remove = (winget uninstall -e --name $app --silent --accept-source-agreements)
					if ($remove -eq 'Multiple installed packages found matching input criteria. Please refine the input') {
						$remove = (winget uninstall -e --name $app --exact --silent --accept-source-agreements | Out-Null)
					}
					$numApps ++
				} catch {
					write-output -f red "Error: "$_.Exception.Message
				}
			}
		}		
		Write-Progress -Complete '(unused)'
		Start-Sleep -Milliseconds $Sleep_Milliseconds
			
	}
	
	function winget_outclean () {
		[CmdletBinding()]
		param (
			[Parameter(ValueFromPipeline)]
			[String[]]$lines
		)
		if ($input.Count -gt 0) { $lines = $PSBoundParameters['Value'] = $input }
		$bInPreamble = $true
		foreach ($line in $lines) {
			if ($bInPreamble){
				if ($line -like "Name*") {
					$bInPreamble = $false
				}
			}
			if (-not $bInPreamble) {
				Write-Output $line
			}
		}
	}

	function ConvertFrom-FixedColumnTable {
		[CmdletBinding()]
		param(
		[Parameter(ValueFromPipeline)] [string] $InputObject
		)
  
		begin {
			Set-StrictMode -Version 1
			$lineNdx = 0
		}
  
		process {
			$lines = 
			if ($InputObject.Contains("`n")) { $InputObject.TrimEnd("`r", "`n") -split '\r?\n' }
			else { $InputObject }
			foreach ($line in $lines) {
			++$lineNdx
			if ($lineNdx -eq 1) { 
				# header line
				$headerLine = $line 
			}
			elseif ($lineNdx -eq 2) { 
				# separator line
				# Get the indices where the fields start.
				$fieldStartIndices = [regex]::Matches($headerLine, '\b\S').Index
				# Calculate the field lengths.
				$fieldLengths = foreach ($i in 1..($fieldStartIndices.Count-1)) { 
				$fieldStartIndices[$i] - $fieldStartIndices[$i - 1] - 1
			}
			# Get the column names
			$colNames = foreach ($i in 0..($fieldStartIndices.Count-1)) {
			if ($i -eq $fieldStartIndices.Count-1) {
				$headerLine.Substring($fieldStartIndices[$i]).Trim()
			} else {
				$headerLine.Substring($fieldStartIndices[$i], $fieldLengths[$i]).Trim()
			}
        } 
      }
      else {
        # data line
        $oht = [ordered] @{} # ordered helper hashtable for object constructions.
        $i = 0
        foreach ($colName in $colNames) {
          $oht[$colName] = 
            if ($fieldStartIndices[$i] -lt $line.Length) {
              if ($fieldLengths[$i] -and $fieldStartIndices[$i] + $fieldLengths[$i] -le $line.Length) {
                $line.Substring($fieldStartIndices[$i], $fieldLengths[$i]).Trim()
              }
              else {
                $line.Substring($fieldStartIndices[$i]).Trim()
              }
            }
          ++$i
        }
        # Convert the helper hashable to an object and output it.
        [pscustomobject] $oht
      }
    }
	}
  
	}
	
	Function CheckApps {
		
		$apps = @(
					
			"Microsoft Clipchamp"
			"Microsoft Edge Update"
			"Microsoft Edge WebView2 Runtime"
            "Microsoft.Edge"                  
            "Cortana"
            "News"
			"MSN Weather"
            "Get Help"                      
            "Microsoft Tips"
			"HEIF Image Extensions"
            "Microsoft 365 (Office)"
            "Solitaire & Casual Games"
			"Microsoft Solitaire Collection"
            "Microsoft Sticky Notes"              
            "Paint"
			"Microsoft People"
            "Power Automate"
            "Raw Image Extension"
            "Snipping Tool"
            "Windows Security"
            "Microsoft Engagement Framework"
            "Store Experience Host"
            "Microsoft To Do"
            "Web Media Extensions"
            "Webp Image Extensions"
            "Dev Home"
            "Microsoft Photos"
            "Windows Clock"
            "Windows Calculator"
            "Windows Camera"                   
            "Feedback Hub"
            "Windows Maps"
            "Windows Notepad"
            "Windows Sound Recorder"
			"Windows Terminal"
			"Phone Link"                  		
			"Windows Media Player"
			"Films & TV"
			"Quick Assist"                      		
			"Microsoft Teams"
			"Windows Web Experience Pack"
			"Microsoft OneDrive"
			"Mail and Calendar"
			"Microsoft Update Health Tools"
			"Mixed Reality Portal"
			"Microsoft News"
			"Microsoft Pay"
			"Spotify Music"
			"Teams Machine-Wide Installer"
			"Microsoft Whiteboard"
			"Windows Voice Recorder"
			
			#Windows 10
			"Snip & Sketch"
			"Movies & TV"
			"Skype"
			"Paint 3D"
			"3D Viewer"
			"OneNote for Windows 10"
			"paint.net"
			
			# Other Tools
			"SharedAccess"
			"Windows Calculator"
			"Windows Clock"
			"Windows Alarms & Clock"
			"DevHome"
			"Windows PC Health Check"
			"HP Desktop Support Utilities"
			"HP Notifications"
			"VP9 Video Extensions"
		)
		

		if ($script:isXboxRunning -eq $false) {
			$apps += @("Xbox", "Game Bar", "Xbox Console Companion", "Xbox Game Speech Window", "Xbox Accessories", "Xbox Identity Provider", "Xbox Game Speech Window" , "Xbox TCUI", "Xbox Game Bar Plugin")
		}
		
		$c = $apps.count
		Write-Progress "Gathering $c Microsoft Store Apps." 
		Start-Sleep -Milliseconds $Sleep_Milliseconds
		$numApps = 0
		$i = 0

		$useWinget = $false
		
		try {
			$check=(winget --version) 
			$useWinGet = $true
		} catch {
			$useWinGet = $False
		}

		if ($useWinGet -eq $False) {
			Write-Progress "Downloading and installing WinGet which is used to manage aplications in Windows." 
			Start-Sleep -Milliseconds $Sleep_Milliseconds
			$progressPreference = 'silentlyContinue'
			
			$latestWingetMsixBundleUri = $(Invoke-RestMethod https://api.github.com/repos/microsoft/winget-cli/releases/latest).assets.browser_download_url | Where-Object {$_.EndsWith(".msixbundle")}
			$latestWingetMsixBundle = $latestWingetMsixBundleUri.Split("/")[-1]
			
			Invoke-WebRequest -Uri $latestWingetMsixBundleUri -OutFile "./$latestWingetMsixBundle"
			Invoke-WebRequest -Uri https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx -OutFile Microsoft.VCLibs.x64.14.00.Desktop.appx
			Add-AppxPackage Microsoft.VCLibs.x64.14.00.Desktop.appx
			Add-AppxPackage $latestWingetMsixBundle
			Start-Sleep -Seconds 2
			
			try {
				$check=(winget --version)
				$useWinGet = $True
			} catch {
				$useWinGet = $False
			}
			Write-Progress -Complete '(unused)'
			Start-Sleep -Milliseconds $Sleep_Milliseconds
		}
		
		$numApps = 0
		
		if($useWinget -eq $True) {
			
			[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new() 
			$winget= (winget list | winget_outclean |  ConvertFrom-FixedColumnTable |  Sort-Object Id  |  Select-Object Name,Id,@{N='Version';E={$_.Version.Replace("> ","")}},Available,Source )# Version fixup
			$i = 0
			
			if($winget) {
				$c = $winget.count
					foreach($app in $winget) {
						$AppID = $($app.Id)
						$AppName = $($app.Name)
						$i++
						$p = ($i / $c) * 100
						Write-Progress "Searching through $c Apps. $([int]$p)% Complete." -Status $AppName -percentComplete $p
						Start-Sleep -Milliseconds $Sleep_Milliseconds
			
						#Part of the ID is missing..... So lets try and remove the crap and add the ID part backon again
						if($appID -like "*...") {
							if($appID -like "*_8weky*") {
								$pos = $appID.IndexOf("_8weky")
								if($pos) {
									$appID = $appID.SubString(0,$pos) + "_8wekyb3d8bbwe"
								}
							}
						}
						
						if($apps -contains $AppName) {
							$script:FoundApps += $appName
							$numApps ++
						} elseif($apps -contains $AppID) {
							$script:FoundApps += $appID
							$numApps ++
						}
					}
			}
			
			Write-Progress -Complete '(unused)'
			Start-Sleep -Milliseconds $Sleep_Milliseconds
			
		}
		
		if($numApps -gt 0) {
			write-opt
			write-host " $numApps Microsoft Store Apps will be Removed." -ForegroundColor White 
		}
		
	}
	
	Function Update-Registry-Value {

		param (
			[parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()]$Path,
			[parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()]$Name,
			[parameter(Mandatory=$false)] $Type,
			[parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()]$Value )
		
		$regName = $False
		$regPath = $False
		
		try { 
			$Value =(Get-Item -Path $Path -ErrorAction SilentlyContinue)
			$regPath = $true
		} catch {}
		
		if($regPath -eq $true) {
			try {
				$Value =(Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue)
				#Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null }
				$regName = $true
			} catch {}
			if($regName -eq $true) {
					$set=(Set-Itemproperty -path $Path -Name $Name -value $Value -ErrorAction SilentlyContinue)
			}
			if($regName -eq $False) {
				if($Type) {
					try {
						$set=(New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -ErrorAction SilentlyContinue)
					} catch {}
				} else {
					try {
						$set=(New-ItemProperty -Path $Path -Name $Name -Value $Value -ErrorAction SilentlyContinue)
					} catch {}
					
				}
			}
		}
	}
	
	Function Remove-InternetExplorer {
		
		#If 21H1
		#$Runme=(Remove-WindowsCapability -Name 'Browser.InternetExplorer~~~~0.0.11.0' -Online)
		
		#$runme=(dism /online /Remove-Capability /CapabilityName:Browser.InternetExplorer~~~~0.0.11.0)
		#$runme=(Disable-WindowsOptionalFeature -FeatureName Internet-Explorer-Optional-amd64 –Online)
		
	}
	
	Function Remove-App-RegistryEntries {

		# Advertiser Id
		Update-Registry-Value -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value "0"
		
		# Chat
		Update-Registry-Value -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Value "0"
		
		# Edge Desktop Search Bar
		Update-Registry-Value -Path "HKLM\SOFTWARE\Policies\Microsoft\Edge" -Name "WebWidgetAllowed" -Value "0"
		
		# EdgeRecommendations
		Update-Registry-Value -Path "HKLM\SOFTWARE\Policies\Microsoft\Edge" -Name "ShowRecommendationsEnabled" -Value "0"
		
		# Hide File Extension
		Update-Registry-Value -Path "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value "0"
		
		# RotatingLockScreenOverlay
		Update-Registry-Value -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -Value "0"
				 
		# SubscribedContent-338387Enabled
		Update-Registry-Value -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Value "0"
		
		# PowershellUnrestricted
		# Update-Registry-Value -Path "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" -Name "ExecutionPolicy" -Value "Unrestricted"
		
		#StartupBoost
		Update-Registry-Value -Path "HKLM\SOFTWARE\Policies\Microsoft\Edge" -Name "StartupBoostEnabled" -Value "0"
		
		#StartMenuRecommendations
		Update-Registry-Value -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecommendedSection" -Value "1"
		
		# TaskBar search
		Update-Registry-Value -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value "0"
		
		# TaskView
		Update-Registry-Value -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value "0"

		# Startmenu Web search
	
		Update-Registry-Value -Path "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Value "1"
		
		# Widgets
		Update-Registry-Value -Path "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value "0"
		
		# No Customize This folder
		Update-Registry-Value -Path "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoCustomizeThisFolder" -Value "1"
		
		# Allow Dev
		Update-Registry-Value -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx" -Name "AllowDevelopmentWithoutDevLicense" -Value "1"
		
		#Remove Edge Bing Sidebar
		Update-Registry-Value -Path "HKLM\SOFTWARE\Policies\Microsoft\Edge" -Name "HubsSidebarEnabled" -Value "0"
		
		#ExplorerClassicMenu				 
		#ON# New-Item -Path "Registry::HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Value ""
		#OFF# Remove-Item -Path "Registry::HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
		
		#Explorer Give access
		# Update-Registry-Value -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{f81e9010-6ea4-11ce-a7ff-00aa003ca9f6}" -Type "String" -Value ""
				 
		#Remove OfficeCloud Files in Explorer = asking to Sign In
		Update-Registry-Value -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowCloudFilesInQuickAccess" -Value "0"
		
	}
	
	Function Remove-services {
	
		$numServices = 0
		$i = 0
		$c= $script:FoundServices.count
		Write-Progress "Disabling $c Services" 
		Start-Sleep -Milliseconds $Sleep_Milliseconds
		foreach ($service in $script:FoundServices) {
				$foundservice = $null
				$i++
				$p = ($i / $script:FoundServices.count) * 100
				Write-Progress "Disabling $c Services" -Status "$([int]$p)% Complete." -percentComplete $p
				Start-Sleep -Milliseconds $Sleep_Milliseconds	

				try {
						Stop-Service -Name "$($service)" -Force -NoWait 
						
				} catch {
						write-output -f red "Error: "$_.Exception.Message
				}
				try {
						Set-Service -Name "$($service)" -StartupType Disabled 
				} catch {
						write-output -f red "Error: "$_.Exception.Message
				}
				Start-Sleep -Milliseconds $Sleep_Milliseconds
				$numServices ++
								
			}
			Write-Progress -Complete '(unused)'
			Start-Sleep -Milliseconds $Sleep_Milliseconds
	}
	
	Function CheckServices {
		
		$services = @(
			"diagnosticshub.standardcollector.service" # Microsoft (R) Diagnostics Hub Standard Collector Service
			"DiagTrack"                                # Diagnostics Tracking Service
			"dmwappushservice"                         # WAP Push Message Routing Service (see known issues)
			"lfsvc"                                    # Geolocation Service
			"MapsBroker"                               # Downloaded Maps Manager
			"NetTcpPortSharing"                        # Net.Tcp Port Sharing Service
			"RemoteAccess"                             # Routing and Remote Access
			"RemoteRegistry"                           # Remote Registry
			"SharedAccess"                             # Internet Connection Sharing (ICS)
			"TrkWks"                                   # Distributed Link Tracking Client
			"WbioSrvc"                                 # Windows Biometric Service (required for Fingerprint reader / facial detection)
			"ALG"						               # Application Layer Gateway Service
			"WMPNetworkSvc"                            # Windows Media Player Network Sharing Service
			"AJRouter"								   # Enables you to connect to Lot Devices, Smart Lights, Smart TV's
			"AssignedAccessManager"					   # Helps Settingup Kiosk mode 
			"DPS"									   # Diagnostic Policy Service   - Waiting for Service to Stop 
			"WdiServiceHost"						   # Diagnostic Service Host
			"WdiSystemHost"							   # Diagnostic Service System
			"PrintNotify"							   # Print Notify Service
			"UmRdpService"							   # Remote Desktop Services UserMode Port Redirector
			"SessionEnv"							   # Remote Desktop Configuration
			"TermService"							   # Remote Desktop Services
			"SensrSvc"								   # Sensor Monitoring Service
			"SensorService"						       # Sensor Service
			"SCardSvr"						           # Smart Card
			"ScDeviceEnum"							   # Smart Card Device Enumeration Service
			"SCPolicySvc"							   # Smart Card Removal Policy
			"WerSvc"								   # Windows Error Reporting Service
			"workfolderssvc"						   # Windows Work Folders
			"PcaSvc"								   # Program compatability Monitor    - Waiting for Service to Stop
			"wisvc"									   # Windows Insider Service
			"WSearch"								   # Windows Search
			
			"WpcMonSvc"								   # Windows Parental Controls
			#"wscsvc"                                  # Windows Security Center Service
			#"ndu"                                     # Windows Network Data Usage Monitor - OS = Waits to Stop 
			#"WlanSvc"                                 # WLAN AutoConfig (Disabling this can cause issues with wifi connectivity)
			# Services which cannot be disabled
			#"WdNisSvc"
			
			#More Services
			"HpTouchpointAnalyticsService"
			"HPAppHelperCap"
			"HPDiagsCap"
			"HPSysInfoCap"
			"hpsvcsscan"
			"HotKeyServiceDSU"
			
		)
		
		if ($script:isXboxRunning -eq $false) {
			$services += @("XblAuthManager", "XblGameSave", "XboxNetApiSvc", "XboxGipSvc")
		}
		if ($script:isDomain -eq $false) {
			$services += @("NetLogon")
		}
		if($script:isWindows11 -eq $true) {
			$services += @("TabletInputService")				   # Touch Keyboard and Handwriting Panel Service (ONLY WIn 11)
		}
		
		$c = $services.count
		$numServices = 0
		$i = 0
		Write-Progress "Gathering $c Services." 
		Start-Sleep -Milliseconds $Sleep_Milliseconds
		$AllServices =(Get-Service | Select-Object Name, StartType, Status)
		$c = $AllServices.count
		foreach ($service in $AllServices) {
			$i++
			$p = ($i / $AllServices.count) * 100
			$sname = ($service.Name)
			Write-Progress "Searching through $c Services. $([int]$p)% Complete." -Status  "$sname" -percentComplete $p
			Start-Sleep -Milliseconds $Sleep_Milliseconds
			
			$stype = ($service.StartType)
			
			if($services -contains $sname) {
				if($stype -ne 'Disabled') {
					$numServices ++
					$script:FoundServices += $sname
				}
			}
		}
		
		Write-Progress -Complete '(unused)'
		Start-Sleep -Milliseconds $Sleep_Milliseconds
		
		if($numServices -gt 0) {
			write-opt
			write-host " $numServices Services will be Disabled." -ForegroundColor White 
		}


	}

	Function Kill-Apps {
		$killprocesses = @(
		"SearchApp"
		"SearchUI.exe"
		)
		foreach($killme in $killprocesses) {
			$killl = (taskkill /F /IM $killme | Out-Null)
		}
	}
	
	Function Remove-Tasks {
		$numTasks = 0
		$i =0
		$c = $FoundTasks.count
		Write-Progress "Removing $c Tasks" 
		Start-Sleep -Milliseconds $Sleep_Milliseconds
		foreach ($task in $script:FoundTasks) {
			$aTask = $null
			$parts = $task.split('\')
			$name = $parts[-1]
			$path = $parts[0..($parts.length-2)] -join '\'
			$path += "\"
			$i++
			$p = ($i / $script:FoundTasks.count) * 100
			Write-Progress "Removing Tasks" -Status "$([int]$p)% Complete." -percentComplete $p
			try {
				$aTask = (Get-ScheduledTask -TaskName "$($name)" -TaskPath "$($path)" -ErrorAction SilentlyContinue)
			} catch {}
			if($aTask -ne $null) {
				try {
					$disable=(Disable-ScheduledTask -TaskName "$($name)" -TaskPath "$($path)" -ErrorAction SilentlyContinue)
				} catch {
					write-output "Error: "$_.Exception.Message
				}
				try {
					$disable=(Unregister-ScheduledTask -TaskName "$($name)" -TaskPath "$($path)" -Confirm:$false -ErrorAction SilentlyContinue)
					Start-Sleep -Milliseconds $Sleep_Milliseconds
					$numTasks ++
				} catch {
					write-output "Error: "$_.Exception.Message
				}
			}
		}
		Write-Progress -Complete '(unused)'
		Start-Sleep -Milliseconds $Sleep_Milliseconds
	}
	
	Function CheckTasks {
	
		$tasks = @(
			# Windows base scheduled tasks
			"\MicrosoftEdgeUpdateTaskMachineCore"
			"\MicrosoftEdgeUpdateTaskMachineUA"
			"\Microsoft\VisualStudio\Updates\BackgroundDownload"
			"\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319"
			"\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64"
			"\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical"
			"\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical"
			"\Microsoft\Windows\AppID\SmartScreenSpecific"
			"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
			"\Microsoft\Windows\Application Experience\PcaPatchDbTask"
			"\Microsoft\Windows\Application Experience\ProgramDataUpdater"
			"\Microsoft\Windows\Application Experience\StartupAppTask"
			"\Microsoft\Windows\Autochk\Proxy"
			"\Microsoft\Windows\CloudExperienceHost\CreateObjectTask"
			"\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
			"\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
			"\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
			"\Microsoft\Windows\Defrag\ScheduledDefrag"
			"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
			"\Microsoft\Windows\Feedback\Siuf\DmClient"
			"\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser"
			#"\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance"
			#"\Microsoft\Windows\Windows Defender\Windows Defender Cleanup"
			#"\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"
			#"\Microsoft\Windows\Windows Defender\Windows Defender Verification"
			"\Microsoft\Windows\Windows Error Reporting\QueueReporting"
		)
		
		$c = $tasks.count
		$numTasks = 0
		$i =0
		Write-Progress "Gathering $c Tasks." 
		Start-Sleep -Milliseconds $Sleep_Milliseconds
		$AllTasks = (Get-ScheduledTask | Select-Object TaskName, TaskPath, State)
		$c = $AllTasks.count
		
		foreach ($task in $AllTasks) {
			#$parts = $task.split('\')
			#$name = $parts[-1]
			#$path = $parts[0..($parts.length-2)] -join '\'
			#$path += "\"
			$i++
			
			$p = ($i / $c) * 100
			
			$tname = ($task.TaskName)
			$tstate = ($task.State)
			$tpath= ($task.TaskPath)
			
			Write-Progress "Searching through $c Tasks. $([int]$p)% Complete." -Status $tname -percentComplete $p
			Start-Sleep -Milliseconds $Sleep_Milliseconds
			
			if($tasks -contains $tname) {
				if($tstate -ne 'Disabled') { 
					$numTasks ++	
					$script:FoundTasks += $tname
				}
			}
		}
		
		Write-Progress -Complete '(unused)'
		Start-Sleep -Milliseconds $Sleep_Milliseconds
		
		if($numTasks -gt 0) {
			write-opt
			write-host " $numTasks Scheduled Tasks will be Disabled." -ForegroundColor White 
		}	
	}
	
	Function CreateSystemRestore-Point {
		
		Write-Progress -Activity "Creating System Restore." -Status "..."
		Start-Sleep -Milliseconds $Sleep_Milliseconds
		
		$laststatus = (Get-ComputerRestorePoint -LastStatus)
		
		try {
			Enable-ComputerRestore -Drive "C:\" -Confirm:$False -ErrorAction SilentlyContinue | Out-Null
			Start-Sleep -Milliseconds $Sleep_Milliseconds
		} catch {}
		
		
		Checkpoint-Computer -Description "WinGameOptimizer" -RestorePointType "MODIFY_SETTINGS"
		Start-Sleep -Milliseconds $Sleep_Milliseconds
		
		Write-Progress -Complete '(unused)'
		Start-Sleep -Milliseconds $Sleep_Milliseconds
		
	}
	
	
	<#
	# 	88       888 d8b           .d8888b.                                   .d88888b.           888    d8b               d8b                            
	# 	888   o   888 Y8P          d88P  Y88b                                 d88P" "Y88b          888    Y8P               Y8P                           
	# 	888  d8b  888              888    888                                 888     888          888                                                    
	#	888 d888b 888 888 88888b.  888         8888b.  88888b.d88b.   .d88b.  888     888 88888b.  888888 888 88888b.d88b.  888 88888888  .d88b.  888d888 
	#	888d88888b888 888 888 "88b 888  88888     "88b 888 "888 "88b d8P  Y8b 888     888 888 "88b 888    888 888 "888 "88b 888    d88P  d8P  Y8b 888P"   
	# 	88888P Y88888 888 888  888 888    888 .d888888 888  888  888 88888888 888     888 888  888 888    888 888  888  888 888   d88P   88888888 888     
	# 	8888P   Y8888 888 888  888 Y88b  d88P 888  888 888  888  888 Y8b.     Y88b. .d88P 888 d88P Y88b.  888 888  888  888 888  d88P    Y8b.     888     
	# 	888P     Y888 888 888  888  "Y8888P88 "Y888888 888  888  888  "Y8888   "Y88888P"  88888P"   "Y888 888 888  888  888 888 88888888  "Y8888  888     
	#  	  	                                                                              888                                                             
	#       		                                                                      888                                                             
	#               		                                                              888                                                             
	
	#>
		Clear-Host
		write-output ""
		write-output ""
		write-output ""
		write-output ""
		write-output ""
		write-output ""
		write-output ""
		write-output "  _    _ _       _____                       _____       _   _           _              "
		write-output " | |  | (_)     |  __ \                     |  _  |     | | (_)         (_)             "
		write-output " | |  | |_ _ __ | |  \/ __ _ _ __ ___   ___ | | | |_ __ | |_ _ _ __ ___  _ _______ _ __ "
		write-output " | |/\| | | '_ \| | __ / _  | '_   _ \ / _ \| | | | '_ \| __| | '_   _ \| |_  / _ \ '__|"
		write-output " \  /\  / | | | | |_\ \ (_| | | | | | |  __/\ \_/ / |_) | |_| | | | | | | |/ /  __/ |   "
		write-output "  \/  \/|_|_| |_|\____/\__,_|_| |_| |_|\___| \___/| .__/ \__|_|_| |_| |_|_/___\___|_|   "
		write-output "                                                  | |                                   "
		write-output "                                                  |_|                                   "
		write-output ""
		
		$scriptDir = Get-CurrentLocation
		$logFile = "$($scriptDir)$($LogName)"
			
		$Host.UI.RawUI.WindowTitle ="WinGameOptimizer"
		Start-Sleep -Milliseconds $Sleep_Milliseconds
		
		write-output " Operating System : $OsName $OsDisplayVersion"
		
		$rammodules = New-Object System.Collections.ArrayList
		$harddrives = New-Object System.Collections.ArrayList
		$programs = New-Object System.Collections.ArrayList
		
		$hardware = New-Object -Type PSObject | Select-Object ProcessCount, ThreadCount, HandleCount, OperatingSystem, CPU, CPUCores, CPUThreads, CPUSpeed, CPUInfo, MemoryDescription, Memory, MemorySpeed, GPU, GPUName, GPUMemory, PCName, UserName, SerialNumber, Manufacturer, MainboadModel, BIOSversion
		
		# Gather as much Hardware Information as possible!
		
		$_ComputerInfo = (Get-ComputerInfo)
		
		Write-Progress -Activity "Gathering More Information" -Status "Searching..."
		$_SystemInfo = (Get-WmiObject -Class Win32_Processor -ComputerName. -ErrorAction SilentlyContinue| Select-Object -Property [a-z]*)
		
		$_ProcessesCount = (Get-Process).Count
		$_ThreadCount = (Get-Process|Select-Object -ExpandProperty Threads).count
		$_CurrentRunning = (Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue | Select-Object -Property Handle, CommandLine)
		$_CurrrentUserName = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue| Select-Object UserName)
		$_StartupPrograms = (Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue| Select-Object Name, command, Location, User)
		$_Handles = (Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue| Select-Object -Property Handle, HandleCount)
		
		$hardware.HandleCount = ($_Handles | Measure-Object 'HandleCount' -Sum).Sum
		
		$_Memory = (Get-CimInstance win32_physicalmemory)
		
		if($_Memory -ne $Null) {
			
			$_MemorySize = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).sum
			
			$MemoryType = $Null
			
			foreach ($Dimm in $_Memory) {
				$MemoryType = $Dimm.SMBIOSMemoryType
				
				if($MemoryType -eq 20) {
					$MemoryType = 'DDR'
				} elseif($MemoryType -eq 21) {
					$MemoryType = 'DDR2'
				} elseif($MemoryType -eq 22) {
					$MemoryType = 'DDR2 FB-DIMM'
				} elseif($MemoryType -eq 24) {
					$MemoryType = 'DDR3'
				} elseif($MemoryType -eq 26) {
					$MemoryType = 'DDR4'
				} else {
					$MemoryType = 'DDR'
				}
				
				$newDim = $MemoryType
				
				if ($Dimm.Manufacturer -ne $Null) {
					$Manufacturer = $Dimm.Manufacturer
					$newDim = $newDim + $Manufacturer
				}
				
				$Capacity = Format-Size -Int -Number $Dimm.Capacity
				
				$newDim = $MemoryType +" " + $Capacity
				
				$rammodules += $newDim
				
			}
			
			if($MemoryType -ne $Null) {
				$hardware.Memory = (Format-Size -Int -Number $_MemorySize)
				$hardware.MemoryDescription = $hardware.Memory + " " + $MemoryType
			}
		}
		
		[DateTime]$LastBoot = (Get-CimInstance CIM_OperatingSystem -ErrorAction SilentlyContinue).LastBootUpTime
		[DateTime]$Now = (Get-Date)
		$_Uptime = ($Now - $LastBoot)
		
		
		# Detetct Make, Model and Information of hardware / mainboard 
		
		$_SMBIOS = (Get-WmiObject -Namespace root\wmi -class MSSmBios_RawSMBiosTables)
		
		$_BIOSinfo = (Get-WmiObject -Class Win32_BIOS -ErrorAction SilentlyContinue | Format-List *)
		$_BIOSsimple = (Get-WmiObject -Class Win32_BIOS -ErrorAction SilentlyContinue | Select SMBIOSBIOSVersion, Manufacturer, SerialNumber, ReleaseDate)
		$_BIOSreg = (Get-ItemProperty -Path HKLM:\HARDWARE\DESCRIPTION\System\BIOS -ErrorAction SilentlyContinue)
		$_BIOScharacteristics = (Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue| Select-Object -Property Caption, $BiosCharacteristics)
		$_GPU = (Get-CimInstance -ClassName win32_videocontroller -ErrorAction SilentlyContinue)
		
		$_Product = $Null
		$_Manufacturer = $Null
		$_SerialNumber = $Null
		$_Mainboard = (Get-WmiObject Win32_BaseBoard -ErrorAction SilentlyContinue| Select-Object -Property Manufacturer,Product,SerialNumber,Version)
		if($_Mainboard -ne $null) {
			if($_Mainboard.Product -ne $Null) {$_Product = $_Mainboard.Product}
			if($_Mainboard.Manufacturer -ne $Null) {$_Manufacturer = $_Mainboard.Manufacturer}
			if($_Mainboard.SerialNumber -ne $Null) {$_SerialNumber = $_Mainboard.SerialNumber}
		}
		
		$_Fans = (Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object {$_.Name -like "*Fan*" })
		$_Cooling = (Get-WmiObject Win32_TemperatureProbe -Namespace "root\cimv2" -ErrorAction SilentlyContinue)
		$_Network = (Get-WmiObject -Query "SELECT * FROM Win32_NetworkAdapterConfiguration" -ErrorAction SilentlyContinue)
		$_Defender = (Get-WmiObject -Namespace ROOT\Microsoft\Windows\Defender -Class MSFT_MpComputerStatus -ErrorAction SilentlyContinue)
		$_Smart = (Get-WmiObject -Namespace root\wmi -class MSStorageDriver_FailurePredictStatus -ErrorAction SilentlyContinue)
		
		#Check if WMI drivers have been installed in the Operating system to interface with the Mainboard
		
		$Get_manufacturer = (Get-WmiObject Win32_Computersystem).manufacturer
		If($Get_manufacturer -like "*dell*")
		{
			$_Manufacturer = "Dell"
			$_DELL = (Get-WmiObject -NameSpace root\dellomci Dell_BootDeviceSequence -ErrorAction SilentlyContinue | sort bootorder | select BootDeviceName, BootOrder)
			# wmic bios get serialnumber, wmic csproduct get identifyingnumber # Dell ServiceTag
		}
		ElseIf($Get_manufacturer -like "*lenovo*")
		{
			$_Manufacturer = "Lenovo"
			$_LENOVO = (Get-WmiObject -class Lenovo_BiosSetting -namespace root\wmi -ErrorAction SilentlyContinue)
			# gwmi -class Lenovo_BiosSetting -namespace root\wmi  | select-object currentsetting | Where-Object {$_.CurrentSetting -ne ""} | select-object @{label = "Setting"; expression = {$_.currentsetting.split(",")[0]}} , @{label = "Value"; expression = {$_.currentsetting.split(",*;[")[1]}} 
		}
		ElseIf(($Get_manufacturer -like "*HP*") -or ($Get_manufacturer -like "*hewlet*"))
		{
			$_Manufacturer = "HP"
			$_HP = (Get-WmiObject -Namespace root/hp/instrumentedBIOS -Class hp_biosEnumeration -ErrorAction SilentlyContinue | select Name, value, possiblevalues)
		}
		ElseIf($Get_manufacturer -like "*toshiba*")
		{
			$_Manufacturer = "Toshiba"
			$_TOSHIBA = Get-WmiObject -NameSpace "root\wmi" -Query "SELECT * FROM QueryBiosSettings" -ErrorAction SilentlyContinue |  % { New-Object psobject -Property @{
				Setting = $_."CurrentSetting"
				Value = $_."Currentvalue"
				}}  | select-object Setting, Value
		}
		Else
		{
			$_Manufacturer = $Get_manufacturer
		
			if($_Manufacturer -eq 'Micro-Star International Co., Ltd.') {
				$_Manufacturer = 'MSI'
				$_MSI = (Get-CimClass -namespace root/WMI -ErrorAction SilentlyContinue | Where-Object CimClassName -Match ".*MSI_.*")
				
				<#    NameSpace: ROOT/WMI
				
				# CimClassName                        CimClassMethods      CimClassProperties
				# ------------                        ---------------      ------------------
				# Msi_Ap_Service                      {}                   {}
				# MSI_BiosPassword                    {AdminPassword, U... {Active, InstanceName}
				# MSI_BiosSetting                     {GetBiosSetting, ... {Active, InstanceName}
				# MSI_LoadDefault                     {LoadDefault}        {Active, InstanceName}
				# MSI_BootOption                      {GetBootOption, S... {Active, InstanceName}
				#>
				
				if($_MSI) {
					$MSI = (get-WmiObject -class MSI_BiosSetting -Namespace root\WMI -Impersonation Impersonate)
					<#
					# __GENUS          : 2
					# __CLASS          : MSI_BiosSetting
					# __SUPERCLASS     : Msi_Ap_Service
					# __DYNASTY        : Msi_Ap_Service
					# __RELPATH        : MSI_BiosSetting.InstanceName="ACPI\\PNP0C14\\WMIC_0"
					# __PROPERTY_COUNT : 2
					# __DERIVATION     : {Msi_Ap_Service}
					# __SERVER         : PCNAME
					# __NAMESPACE      : root\WMI
					# __PATH           : \\PCNAME\root\WMI:MSI_BiosSetting.InstanceName="ACPI\\PNP0C14\\WMIC_0"
					# Active           : True
					# InstanceName     : ACPI\PNP0C14\WMIC_0
					# PSComputerName   : PCNAME
					# 
					# __GENUS          : 2
					# __CLASS          : MSI_BiosSetting
					# __SUPERCLASS     : Msi_Ap_Service
					# __DYNASTY        : Msi_Ap_Service
					# __RELPATH        : MSI_BiosSetting.InstanceName="ACPI\\PNP0C14\\WMIC_1"
					# __PROPERTY_COUNT : 2
					# __DERIVATION     : {Msi_Ap_Service}
					# __SERVER         : PCNAME
					# __NAMESPACE      : root\WMI
					# __PATH           : \\PCNAME\root\WMI:MSI_BiosSetting.InstanceName="ACPI\\PNP0C14\\WMIC_1"
					# Active           : True
					# InstanceName     : ACPI\PNP0C14\WMIC_1
					# PSComputerName   : CHRISD-PC01
					
					$_MSI_HW = (Get-CimClass -namespace root/WMI -ClassName MSI_BiosSetting -ErrorAction SilentlyContinue | %{$_.CimClassMethods})
					
					# Name           ReturnType Parameters            Qualifiers
					# ----           ---------- ----------            ----------
					# GetBiosSetting    Boolean {Item, return}        {Description, Implemented, WmiMethodId}
					# SetBiosSetting    Boolean {Item, Value, return} {Description, Implemented, WmiMethodId}
					#>
				}
			}
		
			$_ASUS = (Get-CimClass -namespace root/WMI | Where-Object CimClassName -Match ".*ASUS.*")
			if($_ASUS) {
				$_Manufacturer = 'ASUS'
				$_ASUS_HW = (Get-CimClass -namespace root/WMI -ClassName ASUSHW -ErrorAction SilentlyContinue | %{$_.CimClassMethods})
				# $asushw = Get-CimInstance -Namespace root/wmi -ClassName ASUSHW
				# Invoke-CimMethod $asushw -MethodName sensor_get_version
			}
		
		}
		
		if($_Manufacturer) {
			$hardware.manufacturer = $_Manufacturer
		}
		
		$TPM = (Get-WmiObject -class Win32_Tpm -namespace root\CIMV2\Security\MicrosoftTpm -ErrorAction SilentlyContinue)
		
		$_GPURam = ""
		if($_GPU.AdapterRAM -ne $Null) {
			$_GPURam = Format-Size($_GPU.AdapterRAM)
			$hardware.GPUMemory = $_GPURam
		}
		
		if($_GPU.VideoProcessor -ne $Null) {
			$_GPUinfo = $_GPU.VideoProcessor +" " + $_GPURam
		} else {
			$N = $_GPU.Name | Select-Object -First 1
			$_GPUinfo = $N +" " + $_GPURam
			$hardware.GPUName = $N
		}
		
		Write-Progress -Complete '(unused)'
		
		$IsVirtual=((Get-WmiObject win32_computersystem).model -eq 'VMware Virtual Platform' -or ((Get-WmiObject win32_computersystem).model -eq 'Virtual Machine'))
		
		$hardware.GPU = $_GPUInfo
		
		$hardware.CPU = $_SystemInfo.Name
		$hardware.CPUThreads = $_SystemInfo.ThreadCount
		$hardware.CPUCores = $_SystemInfo.NumberOfCores
		$cpucount = $_SystemInfo.NumberofLogicalProcessors # ($hardware.CPUThreads * [int]$hardware.CPUCores)		# Threads x Cores = LogicalProcessors
		if($_SystemInfo.MaxClockSpeed ) {
			$_ClockSpeed = [int]$_SystemInfo.MaxClockSpeed / 1000
			$hardware.CPUSpeed = "$($_ClockSpeed)GHz"
		}
		
		
		$_CPUDetails = "$($cpucount) x $($hardware.CPU)"
		if($_CPUdetails -notlike '*Ghz') {
			$_CPUDetails += " $($_ClockSpeed)GHz"
		}
		$hardware.CPUInfo = $_CPUdetails
		
		$_MemCapacity = Format-Size -Int -Number $_MemorySize
						
		if($IsVirtual -eq $true) {
			write-output " Virtual Machine  : YES"
		}
		
		write-output " Mainboard        : $($hardware.manufacturer)"
		write-output " CPU              : $($hardware.CPUInfo)"
		write-output " Memory           : $($_MemCapacity)"
		write-output " GPU              : $($hardware.GPU)"
		write-output "                  : Currently there are $($hardware.HandleCount) Running Processes."
		write-output ""

		if (Test-Path -Path "$($logFile)") {
			try {
				$PreviousResults = [string[]](Get-Content "$($logFile)" -Raw)
			} catch {}
		}
		
		$isXboxRunning = isServiceRunning('XblAuthManager')
		$isWIFIRunning = isServiceRunning('WlanSvc')
		
		
		#$undo = ''
		#if($PreviousResults.count -gt 0) {
		#	write-output " File $($LogFile) Exists!"
		#	$undo = Read-Host -Prompt " Would you like to Undo the last process (Y/N)? "
		#}
		
		if($isXboxRunning -eq $true) {
			write-output " The Xbox Auth service is running, so I won't touch any Xbox settings."
			write-output ""
		}
		
		if(GET-PrintSpooler -eq $true) {
			write-opt
			write-host " The Print Spooler Service will be Disabled." -ForegroundColor White 
		}
		
		CheckServices
		CheckApps
		CheckTasks
		
		if($script:opt -eq 0) {
			
			write-output " No Changes can be made."
			
		} else {
			if($osEdition -eq 'Pro' -or  $osEdition -eq 'Home') {
				write-output ""
				[console]::CursorVisible = $true
				$createcheckpoint = Read-Host -Prompt " Would you like create a Windows System Restore (Y/N)?"
			}

			write-output ""
			write-output 	   " PLEASE ONLY RUN THIS SCRIPT IF THIS COMPUTER IS USED FOR GAMING ONLY"
			write-output ""
			$runok = Read-Host -Prompt " Would you like make these changes to your PC (Y/N)? "
		
			if($runok -eq 'Y' -OR $runok -eq 'y') {
			
				write-host " Running..." -ForegroundColor Green
				[console]::CursorVisible =$False
				
				if($createcheckpoint -eq 'Y' -OR $createcheckpoint -eq 'y') {
					CreateSystemRestore-Point
				}
			
				Remove-PinnedApps
				$SpoolerDisabled = Disable-PrintSpooler
							
				Remove-Services
				Remove-Apps 
			
				Remove-Tasks			
				Turnoff-Telementary
				Remove-Spotify
			    DisableCortana
				Remove-App-RegistryEntries
				
				# Do these steps last
				Trim-HardDrives
				$SavedSpace = Clean-WindowsUpdate
				
				#Finished
				#$StartMenuItems = (New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items()
				
				$NewHandles = (Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue| Select-Object -Property Handle, HandleCount)
				$newHandleCount = ($NewHandles | Measure-Object 'HandleCount' -Sum).Sum
				$handleDiff = $hardware.HandleCount - $newHandleCount
			
				write-output ""
				write-output " Removed $($script:FoundApps.count) Apps, $($script:FoundTasks.count) Tasks $($script:FoundServices.Count) Services "
				write-output " Processes dropped by $($handleDiff) Handles"
			
				<#
				
				# Sends a request to delete all uploaded diagnostic data sent to Microsoft from the current device.
				# Clear-WindowsDiagnosticData -Force
	
				# WIN 11 Disable-MMAgent–MemoryCompression
				Disable-MMAgent
		
					-ApplicationLaunchPrefetching 
					-ApplicationPreLaunch
					-MemoryCompression
					-PageCombining
			
				# Disable-MMAgent -mc

				Write-Output "Disabling Windows Defender Services"
				Takeown-Registry("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend")
				Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" "Start" 4
				Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" "AutorunsDisabled" 3
				Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisSvc" "Start" 4
				Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisSvc" "AutorunsDisabled" 3
				Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sense" "Start" 4
				Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sense" "AutorunsDisabled" 3
	
				Write-Output "Removing Windows Defender context menu item"
				Set-Item "HKLM:\SOFTWARE\Classes\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}\InprocServer32" ""
	
				Write-Output "Removing Windows Defender GUI / tray from autorun"
				Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" "WindowsDefender" -ea 0
	
				Write-Output "Set general privacy options"
				# "Let websites provide locally relevant content by accessing my language list"
				Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" "HttpAcceptLanguageOptOut" 1
	
				# Locaton aware printing (changes default based on connected network)
				New-FolderForced -Path "HKCU:\Printers\Defaults"
				Set-ItemProperty -Path "HKCU:\Printers\Defaults" "NetID" "{00000000-0000-0000-0000-000000000000}"
	
				# "Send Microsoft info about how I write to help us improve typing and writing in the future"
				New-FolderForced -Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC"
				Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC" "Enabled" 0
	
				# "Let apps use my advertising ID for experiencess across apps"
				New-FolderForced -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
				Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0
	
				# "Turn on SmartScreen Filter to check web content"
				Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" "EnableWebContentEvaluation" 0
	
				Write-Output "Disable synchronisation of settings"
				# These only apply if you log on using Microsoft account
				Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" "BackupPolicy" 0x3c
				Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" "DeviceMetadataUploaded" 0
				Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" "PriorLogons" 1
	
				$groups = @(
					"Accessibility"
					"AppSync"
					"BrowserSettings"
					"Credentials"
					"DesktopTheme"
					"Language"
					"PackageState"
					"Personalization"
					"StartLayout"
					"Windows"
				)
				foreach ($group in $groups) {
					New-FolderForced -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$group"
					Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$group" "Enabled" 0
				}
			
				Write-Output "Set privacy policy accepted state to 0"
				# Prevents sending speech, inking and typing samples to MS (so Cortana can learn to recognise you)
				New-FolderForced -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"
				Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" "AcceptedPrivacyPolicy" 0
	
				Write-Output "Do not scan contact informations"
				# Prevents sending contacts to MS (so Cortana can compare speech etc samples)
				New-FolderForced -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
				Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" "HarvestContacts" 0
	
				Write-Output "Inking and typing settings"
				# Handwriting recognition personalization
				New-FolderForced -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
				Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" 1
				Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" 1
		
				Write-Output "Microsoft Edge settings"
				New-FolderForced -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main"
				Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" "DoNotTrack" 1
				New-FolderForced -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes"
				Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes" "ShowSearchSuggestionsGlobal" 0
				New-FolderForced -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead"
				Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead" "FPEnabled" 0
				New-FolderForced -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter"
				Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" "EnabledV9" 0
	
				Write-Output "Disable background access of default apps"
				foreach ($key in (Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications")) {
					Set-ItemProperty -Path ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\" + $key.PSChildName) "Disabled" 1
				}
	
				Write-Output "Denying device access"
				# Disable sharing information with unpaired devices
				Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "Type" "LooselyCoupled"
				Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "Value" "Deny"
				Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "InitialAppValue" "Unspecified"
				foreach ($key in (Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global")) {
					if ($key.PSChildName -EQ "LooselyCoupled") {
						continue
					}
					Set-ItemProperty -Path ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\" + $key.PSChildName) "Type" "InterfaceClass"
					Set-ItemProperty -Path ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\" + $key.PSChildName) "Value" "Deny"
					Set-ItemProperty -Path ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\" + $key.PSChildName) "InitialAppValue" "Unspecified"
				}
				
				Write-Output "Disable location sensor"
				New-FolderForced -Path "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
				Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" "SensorPermissionState" 0
	
				Write-Output "Disable submission of Windows Defender findings (w/ elevated privileges)"
				Takeown-Registry("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Spynet")
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" "SpyNetReporting" 0       # write-protected even after takeown ?!
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" "SubmitSamplesConsent" 0
	
				#Write-Output "Disable automatic download and installation of Windows updates"
				#New-FolderForced -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU"
				#Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate" 1
				#Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "AUOptions" 2
				#Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallDay" 0
				#Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallTime" 3
	
				Write-Output "Disable seeding of updates to other computers via Group Policies"
				New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" 0
	
				#echo "Disabling automatic driver update"
				#sp "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" "SearchOrderConfig" 0
	
				$objSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-1-0"
				$EveryOne = $objSID.Translate( [System.Security.Principal.NTAccount]).Value
	
				# disable prelaunch. lowers ram usage slightly
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" "AllowPrelaunch" 0
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" "AllowTabPreloading" 0
			
				taskkill /F /IM SearchUI.exe
				move "%windir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy" "%windir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy.bak"
	
			
				Write-Output "Disable 'Updates are available' message"
	
			takeown /F "$env:WinDIR\System32\MusNotification.exe"
			icacls "$env:WinDIR\System32\MusNotification.exe" /deny "$($EveryOne):(X)"
			takeown /F "$env:WinDIR\System32\MusNotificationUx.exe"
			icacls "$env:WinDIR\System32\MusNotificationUx.exe" /deny "$($EveryOne):(X)"
	
			Write-Output "Uninstalling Default Apps"
	
			$appxprovisionedpackage = Get-AppxProvisionedPackage -Online
	
			foreach ($app in $apps) {
				Write-Output "Trying to remove $app"
				Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers
				($appxprovisionedpackage).Where( {$_.DisplayName -EQ $app}) |
					Remove-AppxProvisionedPackage -Online
			}
	
			# Prevents Apps from re-installing
			$cdm = @(
				"ContentDeliveryAllowed"
				"FeatureManagementEnabled"
				"OemPreInstalledAppsEnabled"
				"PreInstalledAppsEnabled"
				"PreInstalledAppsEverEnabled"
				"SilentInstalledAppsEnabled"
				"SubscribedContent-314559Enabled"
				"SubscribedContent-338387Enabled"
				"SubscribedContent-338388Enabled"
				"SubscribedContent-338389Enabled"
				"SubscribedContent-338393Enabled"
				"SubscribedContentEnabled"
				"SystemPaneSuggestionsEnabled"
			)
					
			New-FolderForced -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
			foreach ($key in $cdm) {
				Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" $key 0
			}
	
			New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "AutoDownload" 2
	
			# Prevents "Suggested Applications" returning
			New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1
	
			
	
			Write-Output "Restarting explorer"
			Start-Process "explorer.exe"
	
			Write-Output "Waiting for explorer to complete loading"
			Start-Sleep 10
		
			#>

		} # runok = Y
		
		write-output ""
		#$_SystemInfo
		pause
			
		} else {
			write-output "ExecutionPolicy: $ExecPolicy"
			write-output ""
			pause
		}
	} else {
		write-output "Please run the script using 'run as Administrator'"
		write-output ""
		pause
	}
}


