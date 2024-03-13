	# WinGameOptimizer.ps1

	#Requires -Version 5.1

	Set-StrictMode -Version Latest

	Import-Module StartLayout

	# Ensure TLS 1.2 is enabled for HTTPS traffic
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

	# This is usefull to ensure the script has some resiliency and does not jump to any conclusions too quickly...
	$Sleep_Milliseconds = 500 
    
	#This is the LogFile that is used to undo the last run
	$LogName = "WinGameOptimizer.log"
	
	# Special Variables used to collect information
	$PreviousResults = @()
	$isXboxRunning = $false
	$isWIFIRunning = $false
	$isDomain = (gwmi win32_computersystem).partofdomain
	$isWindows10 = $false
	$isWindows11 = $false
	$isWindows12 = $false
	$script:opt = 1
	
	$script:FoundTasks = @() 
	$script:FoundApps = @() 
	$script:FoundAllUsersApps = @()
	$script:FoundPrApps = @() 
	$script:FoundServices = @() 
	$script:FoundFamilyNames = @()
	
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
					$isWindows10 = $true
			}
			if($OsName -like "Microsoft Windows 11*") {
					$isWindows11 = $true
			}
			if($OsName -like "Microsoft Windows 12*") {
					$isWindows12 = $true
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
		if ($Verbose) {Put-String "Updating value $key\$name ... "}
		$oldValue = Get-RegistryValue $key $name
		if ($oldValue -and ($oldValue -ne $value)) {
			if ($Verbose) {Put-Line "Changing it from $oldValue to $value."}
			Set-RegistryValue $key $name $value
		} elseif ($oldvalue) {
			if ($Verbose) {Put-Line "It already contains $value."}
		} else {
			if ($Verbose) {Put-Line "Key and/or value does not exist."}
		}
	}


	Function Set-RegistryValue($Key, $Name, $Value, $PropertyType="String", [Switch]$Verbose) {
		if ((Get-RegistryValue $Key $Name) -ne $null) {
			if ($Verbose) {Put-Line "Setting value $key\$name = $value"}
			Set-ItemProperty $Key -name $Name -value $Value >$null
		} else {
			if (! (Get-Item -ErrorAction SilentlyContinue $key)) {
			New-RegistryKey $Key -Verbose:$Verbose
			}
			if ($Verbose) {Put-Line "Creating value $key\$name = $value"}
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
		if ($Verbose) {Put-Line "Creating key $key\"}
		New-Item $key >$null
		return $null
	}

	Function Get-RegistryValue($key, $name, [Switch]$Verbose) {
		if ($Verbose) {Put-Line "Reading value $key\$name"}
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
		
		$obj = Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='$Drive'"
		Start-Sleep -Milliseconds $Sleep_Milliseconds
				
		$indexing = $obj.IndexingEnabled
		
		if("$indexing" -eq $True){
			
			$obj | Set-WmiInstance -Arguments @{IndexingEnabled=$False} | Out-Null
			
			Start-Sleep -Milliseconds $Sleep_Milliseconds
			
			# Check again to ensure it has sucessfully disabled all Drive indexing?
			$obj = Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='$Drive'"
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
		Write-Progress -Activity "Completed" -Completed
		Start-Sleep -Milliseconds $Sleep_Milliseconds
	}

	function GET-PrintSpooler {
		
		$service = Get-Service -name Spooler 
		$ServiceStatus = $service.Status
		$ServiceDisplayName = $service.DisplayName
	
		$result = $False
	
		if ($ServiceStatus -eq 'Running') {
			$result = $true
		}
		
		return $result
	}
	
	# Return True if Print Spooler has been secussfully stopped and disabled
	# Only modify the startup if the spooler was running in the firstplace. 
	Function Disable-PrintSpooler {
		
		Write-Progress -Activity "Disabling Print Spooler." -Status "..."
		
		$service = Get-Service -name Spooler 
		$ServiceStatus = $service.Status
		$ServiceDisplayName = $service.DisplayName
	
		$result = $True # Default is that spooler is currently not running
	
		if ($ServiceStatus -eq 'Running') {
        
			Stop-Service -Name Spooler -Force | Out-Null
			Start-Sleep -Milliseconds $Sleep_Milliseconds
		
			Set-Service -Name Spooler -StartupType 'Disabled' | Out-Null
			Start-Sleep -Milliseconds $Sleep_Milliseconds
				
			$service = Get-Service -name Spooler 
			$ServiceStatus = $service.Status

			if ($ServiceStatus -ne 'Running') {
				$result = $True
			} else {
				$result = $False
			}
		}
		
		Write-Progress -Activity "Completed" -Completed
		Start-Sleep -Milliseconds $Sleep_Milliseconds
		return $result
	}	
	Function Trim-HardDrives {
		
		$trim=(Optimize-Volume -DriveLetter C -ReTrim)
		
	}
	
	
	Function write-opt {
		write-host " $($opt). " -NoNewLine -ForegroundColor Green 
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
			$OS = Get-WmiObject -Class Win32_OperatingSystem
			$Disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$($os.SystemDrive)'" |
				Select @{Name="FreeGB";Expression={[math]::Round($_.FreeSpace / 1GB, 2)}}
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

		Write-Progress -Activity "Running DSM to remove old ServicePack files." -Status "..."
		Start-Sleep -Milliseconds $Sleep_Milliseconds
		
		Try{
            $DISMResult = dism.exe /online /cleanup-Image /spsuperseded
            $ErrorActionPreference = 'SilentlyContinue'
        }
		Catch [System.Exception]{
            $ErrorActionPreference = 'SilentlyContinue'
            $DISMResult = $False
        }
		
		Write-Progress -Activity "Removing Old Windows Update Files." -Status "..."
		Start-Sleep -Milliseconds $Sleep_Milliseconds
		
		$isRunning = (Get-Service -Name wuauserv).Status
		
		Try{
            Get-Service -Name wuauserv | Stop-Service -Force -ErrorAction Stop
            $WUpdateError = $false
        }
        Catch [System.Exception]{
            $WUpdateError = $true
        }
        Finally{
            If($WUpdateError -eq $False){
                Get-ChildItem "C:\Windows\SoftwareDistribution\*" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -force -recurse -ErrorAction SilentlyContinue    
                Get-Service -Name wuauserv | Start-Service
            } Else {
				if($isRunning = 'Running') {
					Get-Service -Name wuauserv | Start-Service
				}
            }
        }
		
		# Get final free disk space
		$After = Get-FreeDiskSpace

		# Calculate and display the freed disk space
		$Cleaned = $After - $Before

		Write-Progress -Activity "Completed" -Completed
		Start-Sleep -Milliseconds $Sleep_Milliseconds
		return $Cleaned
	}
	
	Function Remove-Spotify {
	
		Write-Progress -Activity "Removing Spotify." -Status "..."
		Start-Sleep -Milliseconds $Sleep_Milliseconds
				
		$RunningApp =Get-Process -Name "spotify*"
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
		Write-Progress -Activity "Completed" -Completed
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
			Remove-Item $Key -Recurse
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
		
		Write-Progress -Activity "Completed" -Completed
		Start-Sleep -Milliseconds $Sleep_Milliseconds
	}
	
	Function Remove-PinnedApps {
		
		Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs" -Recurse  -Filter *uninstall*.lnk | ForEach-Object { Remove-Item $_.FullName }   
		
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

		Clear-Host
		write-host ""
		write-host ""
		write-host ""
		write-host ""
		write-host ""
		write-host ""
		write-host ""
		write-host "  _    _ _       _____                       _____       _   _           _              "
		write-host " | |  | (_)     |  __ \                     |  _  |     | | (_)         (_)             "
		write-host " | |  | |_ _ __ | |  \/ __ _ _ __ ___   ___ | | | |_ __ | |_ _ _ __ ___  _ _______ _ __ "
		write-host " | |/\| | | '_ \| | __ / _  | '_   _ \ / _ \| | | | '_ \| __| | '_   _ \| |_  / _ \ '__|"
		write-host " \  /\  / | | | | |_\ \ (_| | | | | | |  __/\ \_/ / |_) | |_| | | | | | | |/ /  __/ |   "
		write-host "  \/  \/|_|_| |_|\____/\__,_|_| |_| |_|\___| \___/| .__/ \__|_|_| |_| |_|_/___\___|_|   "
		write-host "                                                  | |                                   "
		write-host "                                                  |_|                                   "
                                                                                             
		write-host ""
			
		$scriptDir = Get-CurrentLocation
		$logFile = "$($scriptDir)$($LogName)"
			
		$Host.UI.RawUI.WindowTitle ="Win10 Gamer Optimizer"
		write-host " Operating System : $OsName $OsDisplayVersion"

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
		
		Write-Progress -Activity "Completed" -Completed
		
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
			write-host " Virtual Machine  : YES"
		}
		
		write-host " Mainboard        : $($hardware.manufacturer)"
		write-host " CPU              : $($hardware.CPUInfo)"
		write-host " Memory           : $($_MemCapacity)"
		write-host " GPU              : $($hardware.GPU)"
		write-host "                  : Currently there are $($hardware.HandleCount) Running Processes."
		write-host ""

		if (Test-Path -Path "$($logFile)") {
			try {
				$PreviousResults = [string[]](Get-Content "$($logFile)" -Raw)
			} catch {}
		}
		
		$isXboxRunning = isServiceRunning('XblAuthManager')
		$isWIFIRunning = isServiceRunning('WlanSvc')
		
		
		#$undo = ''
		#if($PreviousResults.count -gt 0) {
		#	Write-Host " File $($LogFile) Exists!"
		#	$undo = Read-Host -Prompt " Would you like to Undo the last process (Y/N)? "
		#}
		
		if($isXboxRunning -eq $true) {
			write-host " The Xbox Auth service is running, so I won't touch any Xbox settings."
			write-host ""
		}
		
		if(GET-PrintSpooler -eq $true) {
			write-opt
			write-host " The Print Spooler Service will be Disabled." -ForegroundColor White 
		}
		
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
			"TermService"							   # Remote Desktop Services
			"UmRdpService"							   # Remote Desktop Services UserMode Port Redirector
			"SessionEnv"							   # Remote Desktop Configuration
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
			#"WSearch"                                 # Windows Search
			#"ndu"                                     # Windows Network Data Usage Monitor - OS = Waits to Stop 
			#"WlanSvc"                                 # WLAN AutoConfig (Disabling this can cause issues with wifi connectivity)
			# Services which cannot be disabled
			#"WdNisSvc"
			
		)
		
		if ($isXboxRunning -eq $false) {
			$services += @("XblAuthManager", "XblGameSave", "XboxNetApiSvc", "XboxGipSvc")
		}
		if ($isDomain -eq $false) {
			$services += @("NetLogon")
		}
		if($isWindows11 -eq $true) {
			$services += @("TabletInputService")				   # Touch Keyboard and Handwriting Panel Service (ONLY WIn 11)
		}
		
		$c = $services.count
		$numServices = 0
		$i = 0
		Write-Progress "Searching $c Services." 
		Start-Sleep -Milliseconds $Sleep_Milliseconds
		foreach ($service in $services) {
			$i++
			$p = ($i / $services.count) * 100
			Write-Progress "Searching $c Services." -Status "$([int]$p)% Complete." -percentComplete $p
			Start-Sleep -Milliseconds $Sleep_Milliseconds
			
			try {
				$foundservice = (Get-Service -Name $service -ErrorAction SilentlyContinue| select -Property name, status, starttype)
				if($foundservice) {
					if($foundservice.StartType -ne 'Disabled') {
						$numServices ++
						$script:FoundServices += $service
					}
				}
			} catch {}
		}
		Write-Progress -Activity "Completed" -Completed
		Start-Sleep -Milliseconds $Sleep_Milliseconds
		
		if($numServices -gt 0) {
			write-opt
			write-host " $numServices Services will be Disabled." -ForegroundColor White 
		}

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
		Write-Progress "Searching $c Tasks." 
		Start-Sleep -Milliseconds $Sleep_Milliseconds
		foreach ($task in $tasks) {
			$parts = $task.split('\')
			$name = $parts[-1]
			$path = $parts[0..($parts.length-2)] -join '\'
			$path += "\"
			$i++
			$p = ($i / $tasks.count) * 100
			Write-Progress "Searching $c Tasks." -Status "$([int]$p)% Complete." -percentComplete $p
			Start-Sleep -Milliseconds $Sleep_Milliseconds
			
			try {
				$aTask = (Get-ScheduledTask -TaskName "$($name)" -TaskPath "$($path)" -ErrorAction SilentlyContinue)
			} catch {}
			if($aTask) {
				if($aTask.State -ne 'Disabled') { 
					$numTasks ++	
					$script:FoundTasks += $task
				}
			}
		}
		Write-Progress -Activity "Completed" -Completed
		Start-Sleep -Milliseconds $Sleep_Milliseconds
		
		if($numTasks -gt 0) {
			write-opt
			write-host " $numTasks Scheduled Tasks will be Disabled." -ForegroundColor White 
		}
		
		$numApps = 0
		$apps = @(
			"Microsoft.549981C3F5F10" #Cortana
			"Microsoft.3DBuilder"
			"Microsoft.Appconnector"
			"Microsoft.BingFinance"
			"Microsoft.BingNews"
			"Microsoft.BingSports"
			"Microsoft.BingTranslator"
			"Microsoft.BingWeather"
			
			"Microsoft.FreshPaint"
			"Microsoft.GetHelp"
			"Microsoft.MicrosoftOfficeHub"
			"Microsoft.MicrosoftPowerBIForWindows"
			"Microsoft.MicrosoftSolitaireCollection"
			"Microsoft.MicrosoftStickyNotes"
			"Microsoft.NetworkSpeedTest"
			"Microsoft.Office.OneNote"
			"Microsoft.People"
			"Microsoft.Print3D"
			"Microsoft.SkypeApp"
			"Microsoft.ScreenSketch"
			
			"Microsoft.WindowsAlarms"
			"microsoft.windowscommunicationsapps"
			"Microsoft.WindowsMaps"
			
			"Microsoft.WindowsSoundRecorder"
			
			"Microsoft.YourPhone"
			"Microsoft.ZuneMusic"
			"Microsoft.ZuneVideo"
			"Microsoft.Wallet"

			"Microsoft.CommsPhone"
			"Microsoft.ConnectivityStore"
			"Microsoft.Getstarted"
			"Microsoft.Messaging"
			"Microsoft.Office.Sway"
			"Microsoft.OneConnect"
			"Microsoft.WindowsFeedbackHub"

			"Microsoft.BingFoodAndDrink"
			"Microsoft.BingHealthAndFitness"
			"Microsoft.BingTravel"
			"Microsoft.WindowsReadingList"
			"Microsoft.MicrosoftSolitaireCollection"
			
			"1FC1A6C2-576E-489A-9B4A-92D21F542136"         #UpdateHealth Tool
			
			"2FE3CB00.PicsArt-PhotoStudio"
			"46928bounde.EclipseManager"
			"613EBCEA.PolarrPhotoEditorAcademicEdition"
			"6Wunderkinder.Wunderlist"
			"7EE7776C.LinkedInforWindows"
			"89006A2E.AutodeskSketchBook"
			"A278AB0D.DisneyMagicKingdoms"
			"A278AB0D.MarchofEmpires"
			"ActiproSoftwareLLC.562882FEEB491" # next one is for the Code Writer from Actipro Software LLC
			"CAF9E577.Plex"  
			"ClearChannelRadioDigital.iHeartRadio"
			"D52A8D61.FarmVille2CountryEscape"
			"D5EA27B7.Duolingo-LearnLanguagesforFree"
			"DB6EA5DB.CyberLinkMediaSuiteEssentials"
			"DolbyLaboratories.DolbyAccess"
			"DolbyLaboratories.DolbyAccess"
			"Drawboard.DrawboardPDF"
			"Fitbit.FitbitCoach"
			"Flipboard.Flipboard"
			"KeeperSecurityInc.Keeper"
			"NORDCURRENT.COOKINGFEVER"
			"PandoraMediaInc.29680B314EFC2"
			"Playtika.CaesarsSlotsFreeCasino"
			"ShazamEntertainmentLtd.Shazam"
			"SlingTVLLC.SlingTV"
			"ThumbmunkeysLtd.PhototasticCollage"
			"TuneIn.TuneInRadio"
			"XINGAG.XING"
			"flaregamesGmbH.RoyalRevolt2"
			"king.com.*"
			"king.com.BubbleWitch3Saga"
			"king.com.CandyCrushSaga"
			"king.com.CandyCrushSodaSaga"
			"A025C540.Yandex.Music"
			"*ACG*"    					# ACG Media Player
			"*CandyCrush*"    			# Candy Crush
			"*Facebook*" 				# Facebook
			"*Plex*"					# Plex server
			"Spotify*"					# Spotify
			"*Twitter*"					# Twitter
			"*Viber*"					# Viber
			"*3d*"						# View 3D
			"SpotifyAB.SpotifyMusic"
			"SpotifyMusic"
			
			"Microsoft.Todos"
			"Clipchamp.Clipchamp"
			"Microsoft.ScreenSketch"
			"Microsoft.WindowsTerminal"
			"Microsoft.PowerAutomateDesktop"
			"Microsoft.MixedReality.Portal"
			"Microsoft.MSPaint"
			"Microsoft.WindowsCalculator"
			
					
			"MicrosoftWindows.Client.WebExperience"
			
			# Microsoft Teams
			"MicrosoftTeams"
			
			# Microsoft Edge
			"Microsoft.MicrosoftEdge.Stable"
			"Microsoft.MicrosoftEdge"
			
			
			# Apps which cannot be removed using Remove-AppxPackage
			#"Microsoft.BioEnrollment"
			#"Microsoft.Windows.Cortana"
			#"Microsoft.WindowsFeedback"
			#"Windows.ContactSupport"
			#"Microsoft.Windows.CloudExperienceHost"
			#"Microsoft.Windows.StartMenuExperienceHost"
			#"Microsoft.Windows.NarratorQuickStart"
			#"Microsoft.Windows.ParentalControls"
			#"MicrosoftWindows.UndockedDevKit"
			#"Windows.CBSPreview"
			#"Microsoft.Windows.CapturePicker"
			#"Microsoft.MicrosoftEdgeDevToolsClient"
			#"Microsoft.Windows.Search"
			
			# Apps which other apps depend on
			#"Microsoft.Advertising.Xaml"
			
		)
		
		
			#Win 10 Apps 
			#Microsoft.AAD.BrokerPlugin                 
			#Microsoft.Windows.OOBENetworkConnectionFlow
			#Microsoft.Windows.OOBENetworkCaptivePortal 
			#MicrosoftWindows.Client.CBS                
			
			#Microsoft.Windows.ShellExperienceHost      
			#windows.immersivecontrolpanel              
			
			#Microsoft.Windows.ContentDeliveryManager   
			#Microsoft.UI.Xaml.2.0                      
			#Microsoft.Windows.Photos                   
			
			#Microsoft.WindowsStore                     
			#Microsoft.Windows.CallingShellApp          
			#Microsoft.Windows.XGpuEjectDialog          
			#Windows.PrintDialog                        
			
			#NcsiUwpApp                                 
			#Microsoft.Windows.SecureAssessmentBrowser  
			#Microsoft.Win32WebViewHost                 
			#Microsoft.Windows.Apprep.ChxApp            
			#Microsoft.Windows.CapturePicker            
			#Microsoft.Windows.PinningConfirmationDialog
			#Microsoft.Windows.SecHealthUI              
			#      
			#Microsoft.Windows.PeopleExperienceHost     

			#Microsoft.Windows.AssignedAccessLockApp    
			#1527c705-839a-4832-9118-54d4Bd6a0c89       
			#Microsoft.LockApp                          
			#c5e2524a-ea46-4f67-841f-6a9465d9d515       
			#E2A4F912-2574-4A75-9BB0-0D023378592B       
			#F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE       
			#Microsoft.AccountsControl                  
			#Microsoft.AsyncTextService                 
			#Microsoft.ECApp                            
			#Microsoft.CredDialogHost                   
			
			#Microsoft.Xbox.TCUI                        
			#Microsoft.XboxGameOverlay  
			#Microsoft.XboxSpeechToTextOverlay     
			
			#Microsoft.WebMediaExtensions               
			
			#Microsoft.ScreenSketch                     
			#Microsoft.People                           
			#Microsoft.Office.OneNote                   
			#Microsoft.MicrosoftOfficeHub               
			#Microsoft.MicrosoftEdge.Stable             
			#Microsoft.Microsoft3DViewer                
			#Microsoft.WindowsAppRuntime.1.2            
			#Microsoft.WindowsAppRuntime.1.2            
			#Microsoft.VCLibs.140.00                    
			#Microsoft.VCLibs.140.00                    
			
			#Microsoft.BingWeather                      
			#Microsoft.HEIFImageExtension               
			#Microsoft.UI.Xaml.2.7                      
			#Microsoft.WindowsMaps                      
     
			
			#Microsoft.MicrosoftStickyNotes             
			#Microsoft.WindowsSoundRecorder             
			#Microsoft.WindowsCamera                    
			#Microsoft.WebpImageExtension               
			#Microsoft.MicrosoftSolitaireCollection     
			#microsoft.windowscommunicationsapps        
			
			#Microsoft.SkypeApp                         
			
			#Microsoft.DesktopAppInstaller              
			
			#Microsoft.StorePurchaseApp                 
			#Microsoft.YourPhone                        
			#Microsoft.549981C3F5F10                    
			#Microsoft.VP9VideoExtensions               

			#Win 11 Apps
			
			#Microsoft.Windows.OOBENetworkConnectionFlow
			#Microsoft.Windows.OOBENetworkCaptivePortal 
			#MicrosoftWindows.UndockedDevKit            
			#Microsoft.UI.Xaml.CBS                      
			#MicrosoftWindows.Client.Core               
			#Microsoft.WindowsAppRuntime.CBS            
			#MicrosoftWindows.Client.FileExp            
			#Microsoft.Windows.CloudExperienceHost      
			#Microsoft.BioEnrollment                    
			#MicrosoftWindows.Client.CBS                
			#Microsoft.AAD.BrokerPlugin                 
			#Microsoft.Windows.ShellExperienceHost      
			#windows.immersivecontrolpanel              
			#Microsoft.NET.Native.Framework.2.2         
			#Microsoft.NET.Native.Runtime.2.2           
			#Microsoft.Windows.ContentDeliveryManager   
			#Microsoft.VCLibs.140.00                    
			
			#Microsoft.MicrosoftEdge.Stable             
			#Microsoft.LanguageExperiencePacken-GB      
			#Microsoft.Windows.Apprep.ChxApp            
			#Microsoft.NET.Native.Runtime.2.2           
			#Microsoft.NET.Native.Framework.2.2         
			#Microsoft.UI.Xaml.2.8                      
			#Microsoft.VCLibs.140.00.UWPDesktop         
			#Microsoft.VCLibs.140.00                    
			#Microsoft.Windows.PinningConfirmationDialog
			#Microsoft.Paint                            
			#Microsoft.Windows.PeopleExperienceHost     
			#Microsoft.Windows.PrintQueueActionCenter   
			#Microsoft.WindowsStore                     
			#Microsoft.Windows.AssignedAccessLockApp    
			#Microsoft.MicrosoftEdgeDevToolsClient      
			#Microsoft.ZuneMusic                        
			#Microsoft.UI.Xaml.2.7                      
			#Microsoft.UI.Xaml.2.7                      
			#Microsoft.Windows.SecureAssessmentBrowser  
			#Microsoft.ZuneVideo                        
			#Microsoft.Win32WebViewHost                 
			
			#Microsoft.Windows.CapturePicker            
			#Microsoft.Windows.ParentalControls         
			#Microsoft.Windows.XGpuEjectDialog          
			#Microsoft.Windows.CallingShellApp          
			#Microsoft.Windows.NarratorQuickStart       
			#Windows.PrintDialog                        
			#1527c705-839a-4832-9118-54d4Bd6a0c89       
			#NcsiUwpApp                                 
			#c5e2524a-ea46-4f67-841f-6a9465d9d515       
			#Microsoft.LockApp                          
			#Microsoft.ECApp                            
			#Microsoft.CredDialogHost                   
			#Microsoft.AsyncTextService                 
			#Microsoft.AccountsControl                  
			#F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE       
			#E2A4F912-2574-4A75-9BB0-0D023378592B       
			#microsoft.windowscommunicationsapps        
			#Microsoft.Windows.Photos                   
			#Microsoft.UI.Xaml.2.4                      
			#Microsoft.Windows.DevHome                  
			#Microsoft.SecHealthUI                      
			#Microsoft.BingWeather                      
                
			#Microsoft.HEVCVideoExtension               
			#Microsoft.HEIFImageExtension               
			#Microsoft.WindowsMaps                      
			#Microsoft.People                           
        
			#Microsoft.549981C3F5F10                    
			#Microsoft.MicrosoftOfficeHub               
			#Microsoft.WindowsSoundRecorder             
			#Microsoft.Services.Store.Engagement        

			#Microsoft.WindowsCamera                    

			#Microsoft.RawImageExtension                
			
			#Microsoft.WebpImageExtension               

			#MicrosoftCorporationII.QuickAssist         
			
			#Microsoft.WindowsFeedbackHub               
			#Microsoft.WindowsCalculator                

			#Microsoft.DesktopAppInstaller              
			#Microsoft.WindowsAppRuntime.1.4            
			#Microsoft.YourPhone                        
			#Microsoft.VP9VideoExtensions               
			#Microsoft.WindowsNotepad                   
           
			#Microsoft.Getstarted                       
			#Microsoft.WebMediaExtensions               
			#Microsoft.MicrosoftStickyNotes             
			#Microsoft.StorePurchaseApp 
			

		if ($isXboxRunning -eq $false) {
			# "Microsoft.XboxGameCallableUI"
			$apps += @("Microsoft.XboxApp", "Microsoft.GamingApp", "Microsoft.XboxIdentityProvider", "Microsoft.XboxGameOverlay", "Microsoft.Xbox.TCUI", "Microsoft.XboxSpeechToTextOverlay","Microsoft.XboxGamingOverlay")
		}
		
		$c = $apps.count
		Write-Progress "Searching $c Microsoft Store Apps." 
		Start-Sleep -Milliseconds $Sleep_Milliseconds
		$numApps = 0
		$i = 0

		foreach  ($app in $apps) {
			$i ++
			$p = ($i / $apps.count) * 100
			
			$getApp = $null
			Write-Progress "Searching $c Microsoft Store Apps." -percentComplete $p
			Start-Sleep -Milliseconds $Sleep_Milliseconds
			
			try {
				$getApp = (Get-AppxPackage -AllUsers | Where-Object {  $_.Name -like "$($app)" } )
			} catch {}
			
			if($getApp -ne $null) {
					$FullName = $getApp.PackageFullName
					$FamilyName = $getApp.PackageFamilyName
					#$FullName = $getApp.Name
					$numApps ++
					if($FullName) {
						if($script:FoundAllUsersApps -NotContains $Fullname ) {
							$script:FoundAllUsersApps += $FullName
						}
					}
					if ($script:FoundFamilyNames -NotContains $FamilyName) {
						$script:FoundFamilyNames  += $FamilyName
					}
			} else {
			
				$getApp = $null
				try {
					$getApp = (Get-AppxPackage | Where-Object {  $_.Name -like "$($app)" })
				} catch {}
			
				if($getApp -ne $null) {
					$FullName = $getApp.PackageFullName
					$FamilyName = $getApp.PackageFamilyName
					#$FullName = $getApp.Name
					$numApps ++
					if($FullName) {
						if($script:FoundApps -NotContains $Fullname ) {
							$script:FoundApps += $FullName
						}
					}
					if ($script:FoundFamilyNames -NotContains $FamilyName) {
						$script:FoundFamilyNames  += $FamilyName
					}
				}
				
			}
			
			$getApp = $null
			try { 
				$getApp = (Get-AppxProvisionedPackage -online | where-object {$_.displayname -like "$($app)"})
			} catch {}
			
			if($getApp -ne $null) {
					$FullName = $getApp.PackageName
					$numApps ++
					if($FullName) {
						if($script:FoundPrApps -NotContains $Fullname ) {
							$script:FoundPrApps += $FullName
						}
					}
			}
		}
		
		Write-Progress -Activity "Completed" -Completed
		Start-Sleep -Milliseconds $Sleep_Milliseconds
		
		
		if($numApps -gt 0) {
			$opt++
			write-opt $opt
			write-host " $numApps Microsoft Store Apps will be Removed." -ForegroundColor White 
		}
		if($opt -eq 0) {
		
		} else {
		if($osEdition -eq 'Pro' -or  $osEdition -eq 'Home') {
			Write-Host ""
			$createcheckpoint = Read-Host -Prompt " Would you like create a Windows System Restore (Y/N)?"
		}
		
		
		Write-Host ""
		Write-Host 	   " PLEASE ONLY RUN THIS SCRIPT IF THIS COMPUTER IS USED FOR GAMING ONLY"
		Write-Host ""
		$runok = Read-Host -Prompt " Would you like make these changes to your PC (Y/N)? "
		
		if($runok -eq 'Y' -OR $runok -eq 'y') {
			
			write-host " Running..." -ForegroundColor Green
			
			if($createcheckpoint -eq 'Y' -OR $createcheckpoint -eq 'y') {
				Write-Progress -Activity "Creating System Restore." -Status "..."
				Start-Sleep -Milliseconds $Sleep_Milliseconds
				$laststatus = (Get-ComputerRestorePoint -LastStatus)
				
				try {
					Enable-ComputerRestore -Drive "C:\" -Confirm:$False -ErrorAction SilentlyContinue | Out-Null
					Start-Sleep -Milliseconds $Sleep_Milliseconds
				} catch {}
				
								
				Checkpoint-Computer -Description "WinGameOptimizer" -RestorePointType "MODIFY_SETTINGS"
				Start-Sleep -Milliseconds $Sleep_Milliseconds
				
				Write-Progress -Activity "Completed" -Completed
				Start-Sleep -Milliseconds $Sleep_Milliseconds
				
			}
			
			Remove-PinnedApps
			$SpoolerDisabled = Disable-PrintSpooler
			Trim-HardDrives
			$SavedSpace = Clean-WindowsUpdate
			
			$numTasks = 0
			$i =0
			Write-Progress "Removing Tasks" 
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
						Disable-ScheduledTask -TaskName "$($name)" -TaskPath "$($path)" -ErrorAction SilentlyContinue
					} catch {
						Write-host -f red "Error: "$_.Exception.Message
					}
					try {
						(Unregister-ScheduledTask -TaskName "$($name)" -TaskPath "$($path)" -Confirm:$false -ErrorAction SilentlyContinue)
						Start-Sleep -Milliseconds $Sleep_Milliseconds
						$numTasks ++
					} catch {
						Write-host -f red "Error: "$_.Exception.Message
					}
				}
			}
			Write-Progress -Activity "Completed" -Completed
			Start-Sleep -Milliseconds $Sleep_Milliseconds
			
			$numServices = 0
			$i = 0
			Write-Progress "Disabling Services" 
			Start-Sleep -Milliseconds $Sleep_Milliseconds
			foreach ($service in $script:FoundServices) {
				$foundservice = $null
				$i++
				$p = ($i / $script:FoundServices.count) * 100
				Write-Progress "Disabling Services" -Status "$([int]$p)% Complete." -percentComplete $p
				Start-Sleep -Milliseconds $Sleep_Milliseconds	
				try {
					$foundservice = (Get-Service -Name "$($service)" -ErrorAction SilentlyContinue)
				} catch {}
				
				if($foundservice -ne $null) {
						
					try {
						Stop-Service -Name "$($service)" -Force | Out-Null
						Start-Sleep -Milliseconds $Sleep_Milliseconds
					} catch {
						Write-host -f red "Error: "$_.Exception.Message
					}
					try {
						Set-Service -Name "$($service)" -StartupType Disabled | Out-Null
						Start-Sleep -Milliseconds $Sleep_Milliseconds
					} catch {
						Write-host -f red "Error: "$_.Exception.Message
					}
					$numServices ++
				}				
			}
			Write-Progress -Activity "Completed" -Completed
			Start-Sleep -Milliseconds $Sleep_Milliseconds
		
			$i = 0
			foreach  ($app in $script:FoundFamilyNames) {
				$i ++
				$p = ($i / $script:FoundFamilyNames.count) * 100
				Write-Progress "Allowing the Removal Store Apps" -percentComplete $p
				Start-Sleep -Milliseconds $Sleep_Milliseconds
				
				try {
					$rem= (Set-NonRemovableAppsPolicy -Online -PackageFamilyName "$($app)" -NonRemovable 0 -ErrorAction SilentlyContinue | Out-Null)
				} catch {
					Write-host -f red "Error: "$_.Exception.Message
				}
			}
			
			$numApps = 0
			$i = 0
			foreach  ($app in $script:FoundApps) {
				$i ++
				$p = ($i / $script:FoundApps.count) * 100
				Write-Progress "Removing Microsoft Store Apps" -percentComplete $p
				Start-Sleep -Milliseconds $Sleep_Milliseconds
				
				try {
					$rem= (Remove-AppxPackage -Package "$($app)" -ErrorAction SilentlyContinue | Out-Null)
					$numApps ++
				} catch {
					Write-host -f red "Error: "$_.Exception.Message
				}
			}
			
			$i = 0
			foreach  ($app in $script:FoundAllUsersApps) {
				$i ++
				$p = ($i / $script:FoundAllUsersApps.count) * 100
				Write-Progress "Removing AllUsers Microsoft Store Apps" -percentComplete $p
				Start-Sleep -Milliseconds $Sleep_Milliseconds
				try {
					$rem= (Remove-AppxPackage -AllUsers -Package "$($app)" -ErrorAction SilentlyContinue | Out-Null)
					$numApps ++
				} catch {
					Write-host -f red "Error: "$_.Exception.Message
				}
			}
			
			$i = 0
			foreach  ($app in $script:FoundPrApps) {
				$i ++
				$p = ($i / $script:FoundPrApps.count) * 100
				Write-Progress "Removing Microsoft Online Store Apps" -percentComplete $p
				Start-Sleep -Milliseconds $Sleep_Milliseconds
				try {
					#Remove-AppxProvisionedPackage -online -packagename $app -ErrorAction SilentlyContinue | Out-Null
					$rem= (Get-AppxProvisionedPackage -Online | Where {$_.PackageName -match "$($app)"} | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null)
					$numApps ++
				} catch {
					Write-host -f red "Error: "$_.Exception.Message
				}
			}
			
			Write-Progress -Activity "Completed" -Completed
			Start-Sleep -Milliseconds $Sleep_Milliseconds
			
			Turnoff-Telementary
			Remove-Spotify
			
			$StartMenuItems = (New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items()
			
			$NewHandles = (Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue| Select-Object -Property Handle, HandleCount)
			$newHandleCount = ($NewHandles | Measure-Object 'HandleCount' -Sum).Sum
			$handleDiff =- $hardware.HandleCount - $newHandleCount
			
			Write-Host ""
			Write-Host " Removed $numApps Apps, $numTasks Tasks $numServices Services"
			Write-host " Processes dropped by $handleDiff"
			
			<#
			foreach ($task in $tasks) {
				$parts = $task.split('\')
				$name = $parts[-1]
				$path = $parts[0..($parts.length-2)] -join '\'
				Write-Output "Disabling Task '$($name)'"
				try {
					
					Disable-ScheduledTask -TaskName "$name" -TaskPath "$path" -ErrorAction SilentlyContinue
	
				} catch {}
			}
	
			foreach ($service in $services) {
				Write-Output "Disabling Service '$($service)'"
				try {
					Get-Service -Name $service | Set-Service -StartupType Disabled
				} catch {}
			}
			
			# Sends a request to delete all uploaded diagnostic data sent to Microsoft from the current device.
			# Clear-WindowsDiagnosticData -Force
	
			# WIN 11 Disable-MMAgent–MemoryCompression
	
			Disable-MMAgent
		
				-ApplicationLaunchPrefetching 
				-ApplicationPreLaunch
				-MemoryCompression
				-PageCombining
			
			# Disable-MMAgent -mc
	
		
			$_SearchSetting = Get-WindowsSearchSetting 
			
			
			# EnableMeteredWebResultsSetting. Whether Windows Search displays web results and suggestions while using a metered network.
			# EnableWebResultsSetting. Whether Windows Search displays web results and suggestions.
			# SearchExperienceSetting. The experience setting.
			#    PersonalizedAndLocation. Personalize Windows Search and other Microsoft experiences by using search history, some Microsoft account information, and specific location of the user.
			#    Personalized. Personalize Windows Search and other Microsoft experiences by using search history and some Microsoft account information, but do not use specific location of the user.
			#    NotPersonalized. Do not personalize Windows Search and other Microsoft experiences or use specific location of the user.
			# WindowsSafeSearchSetting. The value of SafeSearch that Windows Search uses for queries.
			#    Off. Windows Search does not remove adult content from results.
			#    Moderate. Windows Search excludes adult images and videos, but not text, from results.
			#    Strict. Windows Search excludes adult images, videos, and text from results.
			# Set-WindowsSearchSetting [-EnableWebResultsSetting <Boolean>] [-EnableMeteredWebResultsSetting <Boolean>] [-SearchExperienceSetting <String>] [-SafeSearchSetting <String>]
			
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
	
			Write-Output "Disable automatic download and installation of Windows updates"
			New-FolderForced -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU"
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate" 1
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "AUOptions" 2
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallDay" 0
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallTime" 3
	
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
		
		write-host ""
		#$_SystemInfo
		pause
			
		} else {
			write-host "ExecutionPolicy: $ExecPolicy"
			write-host ""
			pause
		}
	} else {
		write-host "Please run the script using 'run as Administrator'"
		write-host ""
		pause
	}
}


