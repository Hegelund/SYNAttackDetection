# Testing for Scripts Path
$Path = "C:\Scripts"
if (!(Test-Path $Path)) {
    New-Item -ItemType directory -Path $Path
}

# Downloading Script
(New-Object System.Net.WebClient).DownloadFile("https://github.com/Hegelund/SYNAttackDetection/blob/master/SYNAttackDetection.ps", "$Path\SYNAttackDetection.ps1")

# Getting Credentials for the scheduled task
$Username = Read-Host -Prompt 'Input the user name'
$Password = Read-Host -Prompt 'Input the Password'

# Setting up the scheduled task
SCHTASKS /create /tn RDPBlock /SC MINUTE /mo 1 /F /RU $Username /RP $Password /RL HIGHEST /TR "powershell -ExecutionPolicy Unrestricted -File $Path\SYNAttackDetection.ps1"
