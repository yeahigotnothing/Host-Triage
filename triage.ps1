# Check if the script is running as an administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script needs to be run as an administrator. Please re-run with administrative privileges." -ForegroundColor Red
    exit
}

# Prompt the user for the hostname or IP
$hostname = Read-Host -Prompt "Enter the hostname or IP of the image."

# Validate the hostname
if ([string]::IsNullOrWhiteSpace($hostname)) {
    Write-Host "You must enter a hostname or IP. Please re-run the script and provide this information." -ForegroundColor Red
    exit
}

# Get the current user's desktop path
$desktopPath = [Environment]::GetFolderPath("Desktop")

# Define the Host_Triage folder path
$triageFolderPath = Join-Path -Path $desktopPath -ChildPath "Host_Triage"

# Define the Tools folder path within Host_Triage
$toolsFolderPath = Join-Path -Path $triageFolderPath -ChildPath "Tools"

# Check if the triage folder exists, if not, create it
if (-not (Test-Path -Path $triageFolderPath)) {
    New-Item -ItemType Directory -Path $triageFolderPath | Out-Null
}

# Define paths for each tool within the Tools folder
$arsenalPath = Join-Path -Path $toolsFolderPath -ChildPath "arsenal\aim_cli.exe"
$kapePath = Join-Path -Path $toolsFolderPath -ChildPath "kape\kape.exe"
$thorPath = Join-Path -Path $toolsFolderPath -ChildPath "thor\thor.exe"
$hayabusaPath = Join-Path -Path $toolsFolderPath -ChildPath "hayabusa\hayabusa.exe"

# Check if the tools exist, if not, exit the script
foreach ($toolPath in $arsenalPath, $kapePath, $thorPath, $hayabusaPath) {
    if (-not (Test-Path -Path $toolPath)) {
        Write-Host "The tool at path $toolPath does not exist. Please ensure all tools are in the correct location and re-run the script." -ForegroundColor Red
        exit
    }
}

# Define paths for tool outputs
$kapeOutputFolder = Join-Path -Path $triageFolderPath -ChildPath "Kape_Output"
$ezParserOutputFolder = Join-Path -Path $triageFolderPath -ChildPath "EZParser_Output"
$thorOutputFolder = Join-Path -Path $triageFolderPath -ChildPath "Thor_Output"
$hayabusaOutputFolder = Join-Path -Path $triageFolderPath -ChildPath "hayabusa_Output"
$hayabusaHtmlOutputFile = Join-Path -Path $hayabusaOutputFolder -ChildPath "${hostname}_HTML_Output.html"
$hayabusaCsvOutputFile = Join-Path -Path $hayabusaOutputFolder -ChildPath "${hostname}_CSV_Output.csv"


# Ensure tool output folders exist
$outputFolders = @($kapeOutputFolder, $ezParserOutputFolder, $thorOutputFolder, $hayabusaOutputFolder)
foreach ($folder in $outputFolders) {
    if (-not (Test-Path $folder)) {
        New-Item -Path $folder -ItemType Directory
        Write-Host "Created $folder."
    }
}

# Search for .E01 files within the Host_Triage folder
$e01Files = Get-ChildItem -Path $triageFolderPath -Filter "*.E01"
if ($e01Files.Count -eq 0) {
    Write-Host "No .E01 files found in the Host_Triage folder. Exiting."
    exit
}

$imagePath = $e01Files[0].FullName

# 1. Mount the forensic image using Arsenal's CLI
Write-Host "Mounting forensic image..."
Start-Process -NoNewWindow -FilePath $arsenalPath -ArgumentList "--mount", "--filename=$imagePath", "--background", "--writable", "--writeoverlay=difference"

# Wait a bit so output is cleaner.
Start-Sleep -Seconds 3

# Prompt the user to press enter when the image has finished mounting
Read-Host "Press enter when the image finished mounting, this may take a moment."

# Prompt the user for the drive letter
$driveLetter = Read-Host -Prompt "Enter the drive letter that was just mounted (e.g., D:\, E:\, F:\)"

# Validate the drive letter
if ([string]::IsNullOrWhiteSpace($driveLetter)) {
    Write-Host "You must enter a drive letter. Please re-run the script and provide this information." -ForegroundColor Red
    exit
}

# 2. Triage the image with Kape
Write-Host "Triage with Kape..."
& $kapePath --tsource $driveLetter --tdest $kapeOutputFolder --tflush --target !SANS_Triage --msource $kapeOutputFolder --mdest $ezParserOutputFolder --mflush --module !EZParser

# After Kape finishes, navigate to the directory with the Windows event logs
$driveLetterFolder = $driveLetter[0]  # Get just the drive letter
$eventLogsPath = Join-Path -Path $kapeOutputFolder -ChildPath "$driveLetterFolder\Windows\system32\winevt\logs"

# Copy the "logs" folder to the Hayabusa directory
$hayabusaLogsPath = Join-Path -Path $toolsFolderPath -ChildPath "Hayabusa\logs"
Copy-Item -Path $eventLogsPath -Destination $hayabusaLogsPath -Recurse

# 3. Run Hayabusa
Write-Host "Running Hayabusa..."
Set-Location $toolsFolderPath\Hayabusa
& $hayabusaPath csv-timeline -d .\logs -w -H $hayabusaHtmlOutputFile --output $hayabusaCsvOutputFile -C

# Cleanup operation: delete the copied logs
Write-Host "Cleaning up logs..."
Remove-Item -Path $hayabusaLogsPath -Recurse -Force

# 4. Scan for IOCs using Thor
Write-Host "Scanning with Thor..."
Set-Location $thorOutputFolder
& $thorPath -module Filescan -p $driveLetter 

# Unmount the drive
Write-Host "Unmounting the drive"
& $arsenalPath --dismount=000000

# Delete the "difference" from Arsenal in the $triageFolderPath
$filePath = Join-Path -Path $triageFolderPath -ChildPath "difference"
Remove-Item -Path $filePath -Force


Write-Host "Forensic processing completed."
