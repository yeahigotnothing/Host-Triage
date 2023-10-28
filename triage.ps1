# Check if the script is running as an administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script needs to be run as an administrator. Please re-run with administrative privileges." -ForegroundColor Red
    exit
}

# Get the current user's desktop path
$desktopPath = [Environment]::GetFolderPath("Desktop")

# Define the Host_Triage folder path
$triageFolderPath = Join-Path -Path $desktopPath -ChildPath "Host_Triage"

# Define the Tools folder path within Host_Triage
$toolsFolderPath = Join-Path -Path $triageFolderPath -ChildPath "Tools"

# Define paths for each tool within the Tools folder
$arsenalPath = Join-Path -Path $toolsFolderPath -ChildPath "arsenal\aim_cli.exe"
$kapePath = Join-Path -Path $toolsFolderPath -ChildPath "kape\kape.exe"
$lokiPath = Join-Path -Path $toolsFolderPath -ChildPath "loki\loki.exe"
$chainsawPath = Join-Path -Path $toolsFolderPath -ChildPath "chainsaw\chainsaw.exe"

# Define paths for tool outputs
$kapeOutputFolder = Join-Path -Path $triageFolderPath -ChildPath "Kape_Output"
$ezParserOutputFolder = Join-Path -Path $triageFolderPath -ChildPath "EZParser_Output"
$lokiOutputFolder = Join-Path -Path $triageFolderPath -ChildPath "Loki_Output"
$chainsawOutputFolder = Join-Path -Path $triageFolderPath -ChildPath "Chainsaw_Output"

# Ensure tool output folders exist
$outputFolders = @($kapeOutputFolder, $ezParserOutputFolder, $lokiOutputFolder, $chainsawOutputFolder)
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

# Get all currently used drive letters
$usedDriveLetters = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' } | ForEach-Object { $_.DriveLetter }

# Find the next available drive letter, starting from C
$alphabet = 68..90 # ASCII values for D-Z
$mountPoint = $null
foreach ($ascii in $alphabet) {
    $letter = [char]$ascii + ":"
    if ($usedDriveLetters -notcontains $letter) {
        $mountPoint = $letter
        break
    }
}

if (-not $mountPoint) {
    Write-Host "No available drive letters. Exiting."
    exit
}

# 1. Mount the forensic image using Arsenal's CLI
Write-Host "Mounting forensic image..."
Start-Process -NoNewWindow -FilePath $arsenalPath -ArgumentList "--mount", "--filename=$imagePath", "--background"

# Pause and wait for image mounting.
Read-Host "Press enter when the image finished mounting, this may take a moment."

# 2. Triage the image with Kape
Write-Host "Triage with Kape..."
& $kapePath --tsource $mountPoint --tdest $kapeOutputFolder --tflush --target !SANS_Triage --msource $kapeOutputFolder --mdest $ezParserOutputFolder --mflush --module !EZParser

# After Kape finishes, navigate to the directory with the Windows event logs
$driveLetterFolder = $mountPoint.TrimEnd(":")  # Remove the colon to get just the drive letter
$eventLogsPath = Join-Path -Path $kapeOutputFolder -ChildPath "$driveLetterFolder\Windows\system32\winevt\logs"

# Copy the "logs" folder to the Chainsaw directory
$chainsawLogsPath = Join-Path -Path $toolsFolderPath -ChildPath "Chainsaw\logs"
Copy-Item -Path $eventLogsPath -Destination $chainsawLogsPath -Recurse

# 3. Run Chainsaw
Write-Host "Running Chainsaw..."
Set-Location $toolsFolderPath\Chainsaw
& $chainsawPath hunt .\logs -s .\sigma --mapping mappings/sigma-event-logs-all.yml -r .\rules --csv --output $chainsawOutputFolder

# 4. Scan for IOCs using Loki
Write-Host "Scanning with Loki..."
Set-Location $lokiOutputFolder
& $lokiPath -p $mountPoint --noprocscan --csv

# Unmount the drive
Write-Host "Unmounting the drive"
& $arsenalPath --dismount=000000

Write-Host "Forensic processing completed."
