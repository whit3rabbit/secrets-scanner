# secrets-scanner installation script for Windows PowerShell
#
# This script will attempt to install secrets-scanner by:
# 1. Using Cargo / cargo-binstall (if cargo is available)
# 2. Downloading the pre-compiled binary from GitHub Releases (fallback)

$Repo = "whit3rabbit/secrets-scanner"
$BinaryName = "secrets-scanner.exe"
$InstallDir = Join-Path $HOME ".secrets-scanner\bin"

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------

function Write-Info ($Message) {
    Write-Host "[info] $Message" -ForegroundColor Green
}

function Write-WarningMsg ($Message) {
    Write-Host "[warn] $Message" -ForegroundColor Yellow
}

function Write-ErrorMsg ($Message) {
    Write-Host "[error] $Message" -ForegroundColor Red
}

function Has-Command ($Name) {
    return (Get-Command $Name -ErrorAction SilentlyContinue) -ne $null
}

# -----------------------------------------------------------------------------
# Method 1: Cargo / cargo-binstall
# -----------------------------------------------------------------------------
function Try-Cargo {
    if (Has-Command "cargo") {
        Write-Info "Rust Cargo detected. Attempting Cargo installation..."
        
        if (Has-Command "cargo-binstall") {
            Write-Info "cargo-binstall detected. Installing pre-built binary..."
            & cargo binstall -y secrets_scanner
            if ($LASTEXITCODE -eq 0) {
                Write-Info "secrets-scanner successfully installed via cargo-binstall!"
                exit 0
            } else {
                Write-WarningMsg "cargo-binstall failed. Trying cargo install..."
            }
        }

        Write-Info "Installing secrets-scanner from source (this may take a few minutes)..."
        & cargo install secrets_scanner
        if ($LASTEXITCODE -eq 0) {
            Write-Info "secrets-scanner successfully installed via cargo!"
            exit 0
        } else {
            Write-WarningMsg "Cargo installation failed."
            Write-Info "Proceeding to download pre-built binary..."
        }
    }
}

# -----------------------------------------------------------------------------
# Method 2: Pre-built Binary Download
# -----------------------------------------------------------------------------
function Download-Binary {
    # We only build x86_64 binaries for Windows
    $Target = "x86_64-pc-windows-msvc"

    # Determine version to download
    $Version = $env:VERSION
    if ([string]::IsNullOrEmpty($Version)) {
        Write-Info "Fetching latest release version from GitHub..."
        try {
            $ApiUrl = "https://api.github.com/repos/$Repo/releases/latest"
            # Use TLS 1.2/1.3
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
            
            $ApiHeaders = @{
                "Accept" = "application/vnd.github.v3+json"
                "User-Agent" = "secrets-scanner-installer"
            }
            $ApiResponse = Invoke-RestMethod -Uri $ApiUrl -Headers $ApiHeaders -Method Get
            $Tag = $ApiResponse.tag_name
        } catch {
            Write-ErrorMsg "Could not retrieve the latest release version from GitHub."
            Write-ErrorMsg "This might happen if the repository is private or no releases exist yet."
            Write-ErrorMsg "To force installation of a specific version, set the VERSION environment variable before running:"
            Write-ErrorMsg "  `$env:VERSION = 'v0.1.0'"
            Write-ErrorMsg "  & .\install.ps1"
            exit 1
        }
        $Version = $Tag
    }

    # Normalize tag and raw version string
    if ($Version.StartsWith("v")) {
        $Tag = $Version
        $VerRaw = $Version.Substring(1)
    } else {
        $Tag = "v$Version"
        $VerRaw = $Version
    }

    # Construct download URL
    $AssetName = "secrets-scanner-$VerRaw-$Target.exe"
    $BaseUrl = "https://github.com/$Repo/releases/download/$Tag"
    $DownloadUrl = "$BaseUrl/$AssetName"
    $ChecksumsUrl = "$BaseUrl/SHA256SUMS"

    Write-Info "Downloading secrets-scanner version $Tag ($Target)..."

    # Ensure install directory exists
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    }

    $DestPath = Join-Path $InstallDir $BinaryName
    $TempDestPath = "$DestPath.tmp"
    $TempSumsPath = "$DestPath.SHA256SUMS.tmp"

    try {
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempDestPath -UseBasicParsing
        Invoke-WebRequest -Uri $ChecksumsUrl -OutFile $TempSumsPath -UseBasicParsing
    } catch {
        Remove-Item -Path $TempDestPath, $TempSumsPath -Force -ErrorAction SilentlyContinue
        Write-ErrorMsg "Failed to download binary from $DownloadUrl"
        Write-ErrorMsg "or checksums from $ChecksumsUrl"
        Write-ErrorMsg "Please check the version and target combination."
        exit 1
    }

    $ExpectedSha = $null
    foreach ($Line in Get-Content $TempSumsPath) {
        if ($Line -match '^([A-Fa-f0-9]{64})\s+(.+)$' -and $Matches[2] -eq $AssetName) {
            $ExpectedSha = $Matches[1].ToLowerInvariant()
            break
        }
    }
    if ([string]::IsNullOrEmpty($ExpectedSha)) {
        Remove-Item -Path $TempDestPath, $TempSumsPath -Force -ErrorAction SilentlyContinue
        Write-ErrorMsg "SHA256SUMS does not contain $AssetName"
        exit 1
    }

    $ActualSha = (Get-FileHash -Algorithm SHA256 -Path $TempDestPath).Hash.ToLowerInvariant()
    if ($ExpectedSha -ne $ActualSha) {
        Remove-Item -Path $TempDestPath, $TempSumsPath -Force -ErrorAction SilentlyContinue
        Write-ErrorMsg "Checksum mismatch for $AssetName"
        Write-ErrorMsg "Expected: $ExpectedSha"
        Write-ErrorMsg "Actual:   $ActualSha"
        exit 1
    }
    Remove-Item -Path $TempSumsPath -Force -ErrorAction SilentlyContinue

    if (Test-Path $TempDestPath) {
        Move-Item -Path $TempDestPath -Destination $DestPath -Force
    }

    Write-Info "Successfully installed secrets-scanner to $DestPath"

    # Add to PATH persistently
    try {
        $UserPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
        $PathEntries = $UserPath -split ';'
        if (-not ($PathEntries -contains $InstallDir)) {
            Write-Info "Adding $InstallDir to User PATH..."
            $NewUserPath = "$UserPath;$InstallDir"
            # Clean up double semicolons
            $NewUserPath = $NewUserPath -replace ';+', ';'
            [Environment]::SetEnvironmentVariable("Path", $NewUserPath, [EnvironmentVariableTarget]::User)
            
            # Update current session path
            $env:Path += ";$InstallDir"
            
            Write-Info "User PATH updated. You may need to restart your terminal/IDE for the changes to take effect."
        } else {
            Write-Info "secrets-scanner is ready to use!"
        }
    } catch {
        Write-WarningMsg "Could not update User PATH environment variable. Please add $InstallDir to your PATH manually."
    }
}

# -----------------------------------------------------------------------------
# Main Execution Flow
# -----------------------------------------------------------------------------

Try-Cargo
Download-Binary
