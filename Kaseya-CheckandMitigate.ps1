<#
.SYNOPSIS
Script that checks for indicators of compromise related to the Kaseya, REvil ransomware attack and removes said indicators when applicable.

.DESCRIPTION
This script performs various checks for processes, files and other indicators of compromise on the system it is executed on.
The checks performed are detailed within the script and nothing but the detailed actions are performed as part of the execution.

Please ensure that the disclaimer is read and understood before execution!

.NOTES
 Author: Truesec Cyber Security Incident Response Team
 Website: https://truesec.com/
 Created: 2021-07-04

 Compatibility: The script has been tested and verified on PowerShell version 2 and 5
    # #Requirement Administrator is not used because it is not compatibile for PowerShell version 2
    # However, the script requires administrator rights

 .DISCLAIMER
 Any of use of this script should be performed by qualified professionals with the necessary knowledge and skills to make independent conclusions.
 The script does not guarantee or in any way ensure, promise or indicate that after successful execution, a system can be declared as safe.
 The script should be used as a tool to help identify indicators of compromise in prefined locations as detailed within this script.



#>
# Colors used in messages on screen starts with [Color:NAMEOFCOLOR] for both accessibility reasons and to get them in the transcript
# Otherwise default colors set on the system should be used for other PowerShell specific messages
#
# [Color:Magenta] - Used for status messages where indication of the ransomware have been executed or malicious files have been found
# [Color:Yellow] - Used for status messages for actions taken, or informational message. For example stop of service, removing files, etc.
# [Color:Green] - Used for status messages where no indication was found for a specific check - this does not mean that the system is clean or that the check is cleared, see information about name of transcript file
#

#
# Rename transcript file to match status, "[Hostname]_[Status]_[TimeStamp].txt"
# Hostname = Hostname of the machine
# Status can be:
# Transcript = The name when running
# NOT_SUCCESSFUL = The script failed to remove files or registry key
# RANSOMWARE_EXECUTED = Ransomware have been executed
# MALICIOUS_FILE = No indication that the ransomware have been executed, but there are malicious files according to specification earlier in the script - these are also removed, if remove failed the status is NOT_SUCESSFUL
# NO_INDICATION = No indication that the ransomware have been executed and no indication of malicious files, according to specification earlier in the script
#

# Function that reads input from the user
function ReadInput() {
    param
    (
        [Parameter(Position = 0, ValueFromPipeline = $true)]
        [string]$msg,
        [string]$BackgroundColor = "Black",
        [string]$ForegroundColor = "Yellow"
    )

    Write-Host -ForegroundColor $ForegroundColor -NoNewline $msg;
    return Read-Host
}

# Set WorkPath
$WorkPath = (Get-Item .).FullName

# Check if WorkPath folder exist, create if false
if (!(Test-Path -Path $WorkPath)) {
    New-Item $WorkPath -type directory
}

# Get timestamp to use in naming of file with results
$TimeStamp = Get-Date -UFormat "%Y%m%d.%H%M%S"

# Get hostname
$HostName = $env:COMPUTERNAME

# Get IP address using WMI - PowerShell compatibility reasons
$IPAddress = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.Ipaddress.length -gt 1 }  -ErrorAction SilentlyContinue

# Start transcript logging
Start-Transcript -Path "$WorkPath\$($HostName)_Transcript_$TimeStamp.txt" -NoClobber

# DISCLAIMER
Write-Host "Any of use of this script should be performed by qualified professionals with the necessary knowledge and skills to make independent conclusions.
The script does not guarantee or in any way ensure, promise or indicate that after successful execution, a system can be declared as safe or unaffected.
The script should be used as a tool to help identify indicators of compromise in prefined locations as detailed within this script."

# Validate that the user understands that files will be deleted and processes stopped
Write-Host "The script is configured to remove files and stop processes if indicators of compromise are identified"
$choice = ReadInput "Are you sure you want to run this script, it will remove files and stop processes identified as malicious - Continue? [Y/N]"

# Stop execution if user types anything other than "Y"
if ($choice -ne "Y") {
    break
}

# Print hostname and IP details for logging purpose
Write-Host ""
Write-Host "[Color:Yellow] HostName: $HostName" -ForegroundColor Yellow
        
foreach ($IP in $IPAddress) {
    Write-Host "[Color:Yellow] IP adresses found: $($IP.ipaddress)" -ForegroundColor Yellow
}

# Check registry for BlackLivesMatter key
$BLMRegistryKey = "HKLM:\SOFTWARE\Wow6432Node\BlackLivesMatter"

if (Test-Path $BLMRegistryKey) {
    Write-Host ""
    Write-Host "[Color:Magenta] Registry Key $BLMRegistryKey found - INDICATION THAT THE RANSOMWARE HAVE BEEN EXECUTED" -ForegroundColor Magenta
}
else {
    Write-Host ""
    Write-Host "[Color:Green] RegistryKey $BLMRegistryKey Not Found" -ForegroundColor Green
}

# Scanning for files with names ending in -readme.txt
# If a file is found that matches, the script will get the content of the file
# and look for the pattern "onion" or "torproject" or "your files are encrypted" to determine if it's a ransomware note
# -Depth is not used due to not working on systems with older PowerShell versions

# Printing message to make user aware that the scan might take a while
Write-Host ""
Write-Host "[Color:Yellow] Checking the C drive and 1 folder down in the structure, for *-readme.txt ransomware notes - this might take a while" -ForegroundColor Yellow
Write-Host "[Color:Yellow] If files are found that matches, that will be printed to screen and to log." -ForegroundColor Yellow
Write-Host "[Color:Yellow] If there's no match the script will NOT print any information about that to screen or to the log" -ForegroundColor Yellow

# Look for files named like "*-readme.txt" with content like "onion", "torproject" or "your files are encrypted" in C:\"
$ReadMeFilesRoot = Get-ChildItem c:\*-readme.txt -ErrorAction SilentlyContinue
foreach ($ReadMeFileRoot in $ReadMeFilesRoot) {
    if (Get-Content $ReadMeFileRoot -Encoding Unicode | Select-String -Pattern "onion", "torproject", "your files are encrypted") {
        Write-Host "[Color:Magenta]$ReadMeFileRoot is identified as a ransomware note - INDICATION THAT THE RANSOMWARE HAVE BEEN EXECUTED" -ForegroundColor Magenta
    }
}

# Look for files named like "*-readme.txt" with content like "onion", "torproject" or "your files are encrypted" on files in folders 1 depth down from C:\"
$DriveSubfolder1 = Get-ChildItem -Path c:\ | Where-Object { $_.Attributes -Like "Directory" }
foreach ($Folder in $DriveSubfolder1) {
    $ReadMeSubFolder1Files = Get-ChildItem -Path "$($Folder.FullName)\*-readme.txt" -ErrorAction SilentlyContinue
    foreach ($ReadMeSubFolder1File in $ReadMeSubFolder1Files) {
        if ($null -ne $ReadMeSubFolder1File) {
            # Fix for PowerShell v2
            if (Get-Content -Path $ReadMeSubFolder1File -Encoding Unicode | Select-String -Pattern "onion", "torproject", "your files are encrypted") {
                Write-Host "[Color:Magenta]$ReadMeSubFolder1File is identified as a ransomware note - INDICATION THAT THE RANSOMWARE HAVE BEEN EXECUTED" -ForegroundColor Magenta
            }
        }

    }
}

# Get running processes and store in a variable, when removing files this is used to check if it's running
# and stop the process if found, before deletion of file
$Processes = Get-Process

# Search for malicious files created by the threat actor that are located in any of the registered Kaseya agents TempPath
#
# Remove files agent.crt and agent.exe located in Kaseya Working-Dir / TempPath
# If there's several active Kaseya agents installed, the script will check all locations and remove the files if found

# Check registry for Kaseya Agents TempPaths (Kaseya agent working directory)
$KaseyaRegistryKey = "HKLM:\SOFTWARE\Wow6432Node\Kaseya"
$KaseyaAgents = Get-Item -Path "$KaseyaRegistryKey\Agent" # Will print an error if no key was found

# Check for "agent.exe" and "agent.crt" in Kaseya Agents TempPaths (Kaseya agent working directory)
if ($null -ne $KaseyaAgents) {
    $KaseyaTempPath = foreach ($Agent in $KaseyaAgents.GetSubKeyNames()) {
        $AgentTempPath = (Get-ItemProperty "$KaseyaRegistryKey\Agent\$Agent" -Name "TempPath").TempPath
        $FilesToCheckForKaseya = "agent.exe", "agent.crt"
    
        foreach ($FileKaseya in $FilesToCheckForKaseya) {
            if (Test-Path "$AgentTempPath\$FileKaseya") {
                Write-Host ""
                Write-Host "[Color:Magenta] The file"$AgentTempPath\$FileKaseya" was found - MALICIOUS FILE FOUND" -ForegroundColor Magenta  
                Write-Host "[Color:Yellow] Trying to stop process if running, and removing"$AgentTempPath\$FileKaseya"" -ForegroundColor Yellow
                $Processes | Where-Object Path -EQ "$AgentTempPath\$FileKaseya" | Stop-Process -Force -Verbose -ErrorAction SilentlyContinue
                Remove-Item -Path "$AgentTempPath\$FileKaseya" -Force -Verbose
            }
            else {
                Write-Host ""
                Write-Host "[Color:Green] The file"$AgentTempPath\$FileKaseya" was not found" -ForegroundColor Green
            }
        }
    }
}

# Search for malicious files created by the threat actor
#
# Remove files "c:\kworking\agent.crt", "c:\kworking\agent.exe" and "c:\kworking1\agent.crt", "c:\kworking1\agent.exe"
# The Kaseya files should have been removed from the active installation paths,
# doing a second check to make sure they are not present in non-active folders left behind from old or broken Kaseya installations
#
# Remove files "c:\Windows\cert.exe", "c:\Windows\msmpeng.exe" and "c:\Windows\mpsvc.dll"
# Even if these files are named as legitimate files, they are not expected to be located in the c:\Windows folder
# The script will attempt to remove these files.

# Hardcoded file paths to check (if registry key is invalid or otherwise incorrect)
$FilesToCheck = "c:\windows\cert.exe", "c:\windows\msmpeng.exe", "c:\windows\mpsvc.dll", "c:\kworking\agent.crt", "c:\kworking\agent.exe", "c:\kworking1\agent.crt", "c:\kworking1\agent.exe"

# Check for hardcoded files and their paths - if found, attempt at deleting and killing the process
foreach ($File in $FilesToCheck) {
    if (Test-Path -Path $File) {
        Write-Host ""
        Write-Host "[Color:Magenta] The file $File was found - MALICIOUS FILE FOUND" -ForegroundColor Magenta  
        Write-Host "[Color:Yellow] Trying stop process if running, and removing $File" -ForegroundColor Yellow
        $Processes | Where-Object Path -EQ $File | Stop-Process -Force -Verbose -ErrorAction SilentlyContinue
        Remove-Item -Path $File -Force -Verbose
    }
    else {
        Write-Host ""
        Write-Host "[Color:Green] The file$File was not found" -ForegroundColor Green
    }
}

##############################
# ReCheck that files have been deleted

# Recheck files in Kaseya TempPath
if ($null -ne $KaseyaAgents) {
    $KaseyaTempPath = foreach ($Agent in $KaseyaAgents.GetSubKeyNames()) {
        $AgentTempPath = (Get-ItemProperty "$KaseyaRegistryKey\Agent\$Agent" -Name "TempPath").TempPath
        $FilesToCheckForKaseya = "agent.exe", "agent.crt"
    
        foreach ($FileKaseya in $FilesToCheckForKaseya) {
            if (Test-Path "$AgentTempPath\$FileKaseya") {
                Write-Host ""
                Write-Host "[Color:Red] !!!WARNING!!!" -ForegroundColor Red
                Write-Host "[Color:Red] !!!WARNING!!!" -ForegroundColor Red
                Write-Host "[Color:Red] The file"$AgentTempPath\$FileKaseya" is still on the system - THE FILE SHOULD HAVE BEEN REMOVED - MALICIOUS FILE FOUND" -ForegroundColor Red  
                Write-Host "[Color:Red] !!!WARNING!!!" -ForegroundColor Red
                Write-Host "[Color:Red] !!!WARNING!!!" -ForegroundColor Red
            }
        }
    }   
}

# Recheck files
foreach ($File in $FilesToCheck) {
    if (Test-Path -Path $File) {
        Write-Host ""
        Write-Host "[Color:Red] !!!WARNING!!!" -ForegroundColor Red
        Write-Host "[Color:Red] !!!WARNING!!!" -ForegroundColor Red
        Write-Host "[Color:Red] The file$File is still on the system - THE FILE SHOULD HAVE BEEN REMOVED - MALICIOUS FILE FOUND" -ForegroundColor Red  
        Write-Host "[Color:Red] !!!WARNING!!!" -ForegroundColor Red
        Write-Host "[Color:Red] !!!WARNING!!!" -ForegroundColor Red
    }
}

# Stop transcript logging and change name of the log file
Stop-Transcript -Verbose

# Rename transcript file to match status, "[Hostname]_[Status]_[TimeStamp].txt"
# Hostname = Hostname of the machine
# Status can be:
# Transcript = The name when running
# NOT_SUCCESSFUL = The script failed to remove files
# RANSOMWARE_EXECUTED = Ransomware have been executed
# MALICIOUS_FILE = No indication that the ransomware have been executed, but there are malicious files according to specification earlier in the script - these are also removed, if remove failed the status is NOT_SUCESSFUL
# NO_INDICATION = No indication that the ransomware have been executed and no indication of malicious files, according to specifications in the script

$TransscriptFile = Get-Item -Path "$WorkPath\$($HostName)_Transcript_$TimeStamp.txt"

if ($($TransscriptFile | Select-String -Pattern "!!!WARNING!!!")) {
    Rename-Item -Path "$WorkPath\$($HostName)_Transcript_$TimeStamp.txt" -NewName "$WorkPath\$($HostName)_NOT_SUCCESSFUL_$TimeStamp.txt"
    Write-Host "[Color:Red] Transcript file renamed with status NOT_SUCCESSFUL" -ForegroundColor Red
    break
}
else {
    if ($($TransscriptFile | Select-String -Pattern "INDICATION THAT THE RANSOMWARE HAVE BEEN EXECUTED")) {
        Rename-Item -Path "$WorkPath\$($HostName)_Transcript_$TimeStamp.txt" -NewName "$WorkPath\$($HostName)_RANSOMWARE_EXECUTED_$TimeStamp.txt"
        Write-Host "[Color:Magenta] Transcript file renamed with status RANSOMWARE_EXECUTED" -ForegroundColor Magenta
        $NewTranscriptName = "$WorkPath\$($HostName)_RANSOMWARE_EXECUTED_$TimeStamp.txt"
    }
    else {
        if ($($TransscriptFile | Select-String -Pattern "MALICIOUS FILE FOUND")) {
            Rename-Item -Path "$WorkPath\$($HostName)_Transcript_$TimeStamp.txt" -NewName "$WorkPath\$($HostName)_MALICIOUS_FILE_$TimeStamp.txt"
            Write-Host "[Color:Yellow] Transcript file renamed with status MALICIOUS_FILE" -ForegroundColor Yellow
            $NewTranscriptName = "$WorkPath\$($HostName)_MALICIOUS_FILE_$TimeStamp.txt"
        }
        else {
            Rename-Item -Path "$WorkPath\$($HostName)_Transcript_$TimeStamp.txt" -NewName "$WorkPath\$($HostName)_NO_INDICATION_$TimeStamp.txt"
            Write-Host "[Color:Green] Transcript file renamed with status NO_INDICATION" -ForegroundColor Green
            $NewTranscriptName = "$WorkPath\$($HostName)_NO_INDICATION_$TimeStamp.txt"
        }   
    }
}
