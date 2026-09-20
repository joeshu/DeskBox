Warning: truncated output (original token count: 110305)
Total output lines: 10466

[CmdletBinding()]
param(
    [ValidateSet("x64", "ARM64")]
    [string]$Platform = "x64",

    [switch]$RequireCleanAnalysis,

    [string]$DotNetPath
)

$ErrorActionPreference = "Stop"

if ($Platform -ne "x64") {
    throw "This audit currently supports only x64 as the runtime gate. Use publish-arm64-aot-static-audit.ps1 for the stage 7A ARM64 static gate."
}

$auditStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$auditProfileVersion = 58

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$project = Join-Path $repoRoot "src\DeskBox\DeskBox.csproj"
$updaterProject = Join-Path $repoRoot "src\DeskBox.Updater\DeskBox.Updater.csproj"
$msvcEnvironmentScript = Join-Path $PSScriptRoot "rust-arm64-msvc-environment.ps1"
if (-not (Test-Path -LiteralPath $msvcEnvironmentScript -PathType Leaf)) {
    throw "The explicit MSVC environment helper is missing: '$msvcEnvironmentScript'."
}
. $msvcEnvironmentScript
$msvcToolchain = Get-DeskBoxMsvcEnvironment -Platform x64
$dotnet = if (-not [string]::IsNullOrWhiteSpace($DotNetPath)) {
    $resolvedDotNet = [System.IO.Path]::GetFullPath($DotNetPath)
    if (-not (Test-Path -LiteralPath $resolvedDotNet -PathType Leaf)) {
        throw "The explicitly selected dotnet host does not exist: '$resolvedDotNet'."
    }

    $resolvedDotNet
}
else {
    (Get-Command dotnet -ErrorAction Stop).Source
}

$runtimeIdentifier = "win-x64"
$expectedMachine = 0x8664
$artifactRoot = [System.IO.Path]::GetFullPath((Join-Path $repoRoot ".artifacts\aot-audit"))
$runRoot = [System.IO.Path]::GetFullPath((Join-Path $artifactRoot $runtimeIdentifier))
$buildArtifactsDir = Join-Path $runRoot "build"
$publishDir = Join-Path $runRoot "publish"
$symbolsDir = Join-Path $runRoot "symbols"
$rustIntermediateDir = Join-Path $runRoot "rust-staging"
$rustCargoTargetDir = Join-Path $runRoot "rust-target"
$logPath = Join-Path $runRoot "publish.log"
$summaryPath = Join-Path $runRoot "summary.json"
$rustNativeEnabled = $true
$jsonSerializerIsReflectionEnabledByDefault = $false

function Assert-PathInsideRoot {
    param(
        [Parameter(Mandatory)]
        [string]$Root,

        [Parameter(Mandatory)]
        [string]$Candidate
    )

    $normalizedRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar)
    $normalizedCandidate = [System.IO.Path]::GetFullPath($Candidate)
    $requiredPrefix = $normalizedRoot + [System.IO.Path]::DirectorySeparatorChar

    if (-not $normalizedCandidate.StartsWith(
            $requiredPrefix,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to modify an AOT audit path outside '$normalizedRoot': '$normalizedCandidate'"
    }
}

function Get-PeMachine {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $stream = [System.IO.File]::OpenRead($Path)
    $reader = [System.IO.BinaryReader]::new($stream)
    try {
        if ($reader.ReadUInt16() -ne 0x5A4D) {
            throw "'$Path' is not a PE image."
        }

        $stream.Position = 0x3C
        $peOffset = $reader.ReadInt32()
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            throw "'$Path' does not contain a valid PE signature."
        }

        return $reader.ReadUInt16()
    }
    finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

function Get-TextSha256 {
    param(
        [AllowEmptyString()]
        [string]$Value
    )

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        $hash = $sha256.ComputeHash($bytes)
        return ([System.BitConverter]::ToString($hash)).Replace("-", "")
    }
    finally {
        $sha256.Dispose()
    }
}

function Get-WorkingTreeSnapshot {
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        # Windows PowerShell 5.1 can promote benign native stderr (for example
        # Git's LF/CRLF notice) to a terminating NativeCommandError when the
        # script-wide preference is Stop. Capture exit codes explicitly.
        $ErrorActionPreference = "Continue"
        $gitCommitOutput = @(& git -C $repoRoot rev-parse HEAD 2>$null)
        $gitCommitExitCode = $LASTEXITCODE
        $gitStatusEntries = @(& git -C $repoRoot -c core.quotepath=false status --porcelain=v1 --untracked-files=all 2>$null)
        $gitStatusExitCode = $LASTEXITCODE
        $trackedDiff = @(& git -C $repoRoot diff --binary --no-ext-diff HEAD -- 2>$null) -join "`n"
        $gitDiffExitCode = $LASTEXITCODE
        $untrackedFiles = @(& git -C $repoRoot -c core.quotepath=false ls-files --others --exclude-standard 2>$null | Sort-Object)
        $gitUntrackedExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }

    if ($gitStatusExitCode -ne 0 -or $gitDiffExitCode -ne 0 -or $gitUntrackedExitCode -ne 0) {
        throw "Failed to capture the Git working-tree state for the AOT audit."
    }

    $gitCommit = if ($gitCommitExitCode -eq 0) {
        ($gitCommitOutput -join "").Trim()
    }
    else {
        $null
    }

    $gitDirty = $gitStatusEntries.Count -gt 0
    $untrackedManifest = @(
        foreach ($relativePath in $untrackedFiles) {
            $fullPath = Join-Path $repoRoot $relativePath
            if (Test-Path -LiteralPath $fullPath -PathType Leaf) {
                "$relativePath`t$((Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash)"
            }
        }
    ) -join "`n"

    [PSCustomObject]@{
        GitCommit = $gitCommit
        GitDirty = $gitDirty
        GitStatusEntries = $gitStatusEntries
        WorkingTreeFingerprint = Get-TextSha256 -Value (
            $trackedDiff + "`n--UNTRACKED--`n" + $untrackedManifest)
    }
}

function Get-DumpBinPath {
    param(
        [string]$PreferredPath
    )

    if (-not [string]::IsNullOrWhiteSpace($PreferredPath) -and
        (Test-Path -LiteralPath $PreferredPath -PathType Leaf)) {
        return [System.IO.Path]::GetFullPath($PreferredPath)
    }

    $dumpBinCommand = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
    if ($null -ne $dumpBinCommand) {
        return $dumpBinCommand.Source
    }

    $programFilesX86 = ${env:ProgramFiles(x86)}
    if (-not [string]::IsNullOrWhiteSpace($programFilesX86)) {
        $vsWhere = Join-Path $programFilesX86 "Microsoft Visual Studio\Installer\vswhere.exe"
        if (Test-Path -LiteralPath $vsWhere -PathType Leaf) {
            $vsWhereArguments = @(
                "-latest",
                "-products", "*",
                "-find", "VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe"
            )
            $candidates = @(& $vsWhere @vsWhereArguments 2>$null)
            foreach ($candidate in $candidates) {
                if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                    return [System.IO.Path]::GetFullPath($candidate)
                }
            }
        }
    }

    throw "Unable to locate dumpbin.exe for the native dependency inventory."
}

function Get-PeImports {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$DumpBinPath
    )

    $dumpOutput = @(& $DumpBinPath /nologo /dependents $Path 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "dumpbin failed while reading imports from '$Path'."
    }

    $imports = @(
        foreach ($line in $dumpOutput) {
            $match = [regex]::Match(
                [string]$line,
                "^\s*([A-Za-z0-9_.-]+\.dll)\s*$",
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if ($match.Success) {
                $match.Groups[1].Value.ToLowerInvariant()
            }
        }
    ) | Sort-Object -Unique

    if ($imports.Count -eq 0) {
        throw "No PE imports were found for '$Path'."
    }

    return $imports
}

Assert-PathInsideRoot -Root $artifactRoot -Candidate $runRoot
$sourceSnapshotBefore = Get-WorkingTreeSnapshot
$dumpBinPath = Get-DumpBinPath -PreferredPath (
    Join-Path $msvcToolchain.LinkerDirectory "dumpbin.exe")

if (Test-Path -LiteralPath $runRoot) {
    Remove-Item -LiteralPath $runRoot -Recurse -Force
}

New-Item -ItemType Directory -Path $publishDir -Force | Out-Null
New-Item -ItemType Directory -Path $symbolsDir -Force | Out-Null

$publishArguments = @(
    "publish",
    $project,
    "--configuration", "Release",
    "--output", $publishDir,
    "--artifacts-path", $buildArtifactsDir,
    "--no-restore",
    "-p:Platform=$Platform",
    "-p:RuntimeIdentifier=$runtimeIdentifier",
    "-p:DeskBoxDistribution=Direct",
    "-p:DeskBoxAotAudit=true",
    "-p:DeskBoxAotSmokeHarness=true",
    "-p:JsonSerializerIsReflectionEnabledByDefault=$($jsonSerializerIsReflectionEnabledByDefault.ToString().ToLowerInvariant())",
    "-p:DeskBoxRustNative=$($rustNativeEnabled.ToString().ToLowerInvariant())",
    "-p:DeskBoxRustNativeIntermediateDir=$rustIntermediateDir",
    "-p:DeskBoxRustNativeCargoTargetDir=$rustCargoTargetDir",
    "-p:IlcUseEnvironmentalTools=true",
    "-p:SelfContained=true",
    "-p:WindowsAppSDKSelfContained=false",
    "-p:PublishSingleFile=false",
    "-v:minimal"
)

$previousCliLanguage = [Environment]::GetEnvironmentVariable("DOTNET_CLI_UI_LANGUAGE", "Process")
$previousNoLogo = [Environment]::GetEnvironmentVariable("DOTNET_NOLOGO", "Process")
$msvcEnvironmentState = Enter-DeskBoxMsvcEnvironment -Toolchain $msvcToolchain
try {
    [Environment]::SetEnvironmentVariable("DOTNET_CLI_UI_LANGUAGE", "en-US", "Process")
    [Environment]::SetEnvironmentVariable("DOTNET_NOLOGO", "1", "Process")

    foreach ($restoreProject in @($project, $updaterProject)) {
        $restoreArguments = @(
            "restore",
            $restoreProject,
            "--artifacts-path", $buildArtifactsDir,
            "-p:Platform=$Platform",
            "-p:RuntimeIdentifier=$runtimeIdentifier",
            "-p:DeskBoxAotAudit=true",
            "-p:DeskBoxAotSmokeHarness=true",
            "-p:JsonSerializerIsReflectionEnabledByDefault=$($jsonSerializerIsReflectionEnabledByDefault.ToString().ToLowerInvariant())",
            "-p:PublishAot=true",
            "-p:IlcUseEnvironmentalTools=true",
            "-p:SelfContained=true",
            "-p:WindowsAppSDKSelfContained=false",
            "-v:minimal"
        )

        & $dotnet @restoreArguments 2>&1 | Tee-Object -FilePath $logPath -Append
        if ($LASTEXITCODE -ne 0) {
            throw "Restore failed for '$restoreProject' with exit code $LASTEXITCODE. See '$logPath'."
        }
    }

    & $dotnet @publishArguments 2>&1 | Tee-Object -FilePath $logPath -Append
    $publishExitCode = $LASTEXITCODE
}
finally {
    [Environment]::SetEnvironmentVariable("DOTNET_CLI_UI_LANGUAGE", $previousCliLanguage, "Process")
    [Environment]::SetEnvironmentVariable("DOTNET_NOLOGO", $previousNoLogo, "Process")
    Exit-DeskBoxMsvcEnvironment -State $msvcEnvironmentState
}

if ($publishExitCode -ne 0) {
    throw "Native AOT publish failed with exit code $publishExitCode. See '$logPath'."
}

$rustAbiVersion = $null
$rustCapabilities = $null
$rustRequiredExports = @()
$rustStagingSha256 = $null
$rustPublishSha256 = $null
$rustPublishMatchesStaging = $null
if ($rustNativeEnabled) {
    $rustBuildScript = Join-Path $repoRoot "scripts\build-rust-native.ps1"
    $rustValidation = & $rustBuildScript `
        -Platform x64 `
        -Configuration Release `
        -OutputDirectory $publishDir `
        -ValidateOnly
    $rustAbiVersion = $rustValidation.AbiVersion
    $rustCapabilities = $rustValidation.Capabilities
    $rustRequiredExports = @($rustValidation.RequiredExports)

    $stagedRustDll = Join-Path $rustIntermediateDir "deskbox_native.dll"
    $publishedRustDll = Join-Path $publishDir "deskbox_native.dll"
    if (-not (Test-Path -LiteralPath $stagedRustDll -PathType Leaf) -or
        -not (Test-Path -LiteralPath $publishedRustDll -PathType Leaf)) {
        throw "The isolated staging or published Rust native module is missing."
    }

    $rustStagingSha256 = (Get-FileHash -LiteralPath $stagedRustDll -Algorithm SHA256).Hash
    $rustPublishSha256 = (Get-FileHash -LiteralPath $publishedRustDll -Algorithm SHA256).Hash
    $rustPublishMatchesStaging = [string]::Equals(
        $rustStagingSha256,
        $rustPublishSha256,
        [System.StringComparison]::OrdinalIgnoreCase)
    if (-not $rustPublishMatchesStaging) {
        throw "The published Rust native module does not match this audit run's isolated staging output."
    }
}

$pdbFiles = @(Get-ChildItem -LiteralPath $publishDir -Filter "*.pdb" -File -Recurse)
foreach ($pdb in $pdbFiles) {
    Assert-PathInsideRoot -Root $publishDir -Candidate $pdb.FullName
    $normalizedPublishDir = [System.IO.Path]::GetFullPath($publishDir).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar)
    $normalizedPdbPath = [System.IO.Path]::GetFullPath($pdb.FullName)
    $relativePath = $normalizedPdbPath.Substring($normalizedPublishDir.Length + 1)
    $symbolDestination = Join-Path $symbolsDir $relativePath
    $symbolParent = Split-Path -Parent $symbolDestination
    New-Item -ItemType Directory -Path $symbolParent -Force | Out-Null
    Move-Item -LiteralPath $pdb.FullName -Destination $symbolDestination -Force
}

$requiredFiles = @(
    "DeskBox.exe",
    "DeskBox.Updater.exe",
    "DeskBox.ThumbnailProxy.exe",
    "DeskBox.pri"
)
if ($rustNativeEnabled) {
    $requiredFiles += "deskbox_native.dll"
}

foreach ($requiredFile in $requiredFiles) {
    $requiredPath = Join-Path $publishDir $requiredFile
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "AOT audit output is missing '$requiredFile'."
    }
}

$publishedNativeModules = @(
    Get-ChildItem -LiteralPath $publishDir -Filter "deskbox_native.dll" -File -Recurse
)
if ($rustNativeEnabled) {
    $expectedRustDllPath = [System.IO.Path]::GetFullPath(
        (Join-Path $publishDir "deskbox_native.dll"))
    if ($publishedNativeModules.Count -ne 1 -or
        -not [string]::Equals(
            $publishedNativeModules[0].FullName,
            $expectedRustDllPath,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "The x64 AOT publish must contain exactly one root-level deskbox_native.dll."
    }
}
elseif ($publishedNativeModules.Count -ne 0) {
    throw "A non-x64 AOT publish must not contain the x64 deskbox_native.dll."
}

$publishedThumbnailProxies = @(
    Get-ChildItem -LiteralPath $publishDir -Filter "DeskBox.ThumbnailProxy.exe" -File -Recurse
)
$expectedThumbnailProxyPath = [System.IO.Path]::GetFullPath(
    (Join-Path $publishDir "DeskBox.ThumbnailProxy.exe"))
if ($publishedThumbnailProxies.Count -ne 1 -or
    -not [string]::Equals(
        $publishedThumbnailProxies[0].FullName,
        $expectedThumbnailProxyPath,
        [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "The AOT publish must contain exactly one root-level DeskBox.ThumbnailProxy.exe."
}

$forbiddenFiles = @(
    "coreclr.dll",
    "clrjit.dll",
    "hostfxr.dll",
    "hostpolicy.dll",
    "System.Private.CoreLib.dll",
    "DeskBox.dll",
    "DeskBox.deps.json",
    "DeskBox.runtimeconfig.json",
    "DeskBox.Updater.dll",
    "DeskBox.Updater.deps.json",
    "DeskBox.Updater.runtimeconfig.json"
)

$publishedFiles = @(Get-ChildItem -LiteralPath $publishDir -File -Recurse)
$forbiddenMatches = @($publishedFiles | Where-Object { $_.Name -in $forbiddenFiles })
if ($forbiddenMatches.Count -gt 0) {
    $details = $forbiddenMatches.FullName -join [Environment]::NewLine
    throw "AOT audit output still contains managed runtime or application files:`n$details"
}

$publishedPdbFiles = @($publishedFiles | Where-Object Extension -eq ".pdb")
if ($publishedPdbFiles.Count -gt 0) {
    throw "AOT publish directory still contains PDB files after symbol separation."
}

$symbolFiles = @(Get-ChildItem -LiteralPath $symbolsDir -Filter "*.pdb" -File -Recurse)
$requiredSymbolFiles = @(
    "DeskBox.pdb",
    "DeskBox.Updater.pdb",
    "DeskBox.ThumbnailProxy.pdb"
)
if ($rustNativeEnabled) {
    $requiredSymbolFiles += "deskbox_native.pdb"
}

foreach ($requiredSymbolFile in $requiredSymbolFiles) {
    if (-not ($symbolFiles | Where-Object Name -eq $requiredSymbolFile)) {
        throw "AOT audit symbols are missing '$requiredSymbolFile'."
    }
}

$peFiles = @(
    (Join-Path $publishDir "DeskBox.exe"),
    (Join-Path $publishDir "DeskBox.Updater.exe"),
    (Join-Path $publishDir "DeskBox.ThumbnailProxy.exe")
)
if ($rustNativeEnabled) {
    $peFiles += (Join-Path $publishDir "deskbox_native.dll")
}

$peResults = foreach ($peFile in $peFiles) {
    $machine = Get-PeMachine -Path $peFile
    if ($machine -ne $expectedMachine) {
        throw "Unexpected PE machine 0x$($machine.ToString('X4')) for '$peFile'; expected 0x$($expectedMachine.ToString('X4'))."
    }

    $imports = @(Get-PeImports -Path $peFile -DumpBinPath $dumpBinPath)

    [ordered]@{
        file = [System.IO.Path]::GetFileName($peFile)
        machine = "0x$($machine.ToString('X4'))"
        bytes = (Get-Item -LiteralPath $peFile).Length
        sha256 = (Get-FileHash -LiteralPath $peFile -Algorithm SHA256).Hash
        imports = @($imports)
    }
}

$logLines = @(Get-Content -LiteralPath $logPath)
$warningCodeRegex = [regex]::new(
    "\b(?:IL|CS|MSB|WMC|MVVMTK|CsWinRT|NETSDK|SYSLIB)\d+\b",
    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$warningMatches = @(
    foreach ($line in $logLines) {
        foreach ($match in $warningCodeRegex.Matches($line)) {
            $match.Value
        }
    }
)
$warningCodes = @($warningMatches | Sort-Object -Unique)
$allowedWarningCodes = @(
    "CS0108",
    "CS0169",
    "CS0414",
    "CS8601",
    "CS8602",
    "WMC1510"
)
$unexpectedWarningCodes = @(
    $warningCodes | Where-Object { $allowedWarningCodes -notcontains $_ }
)
$warningCodeCounts = [ordered]@{}
foreach ($group in @($warningMatches | Group-Object | Sort-Object Name)) {
    $warningCodeCounts[$group.Name] = $group.Count
}
$targetedWarningCounts = [ordered]@{
    MVVMTK0045 = @($warningMatches | Where-Object { $_ -ieq "MVVMTK0045" }).Count
    CsWinRT1028 = @($warningMatches | Where-Object { $_ -ieq "CsWinRT1028" }).Count
}
$stage4D1ATargetFiles = @(
    "Win32Helper.cs",
    "MarkdownDocumentView.cs",
    "SearchPopupWindow.xaml.cs"
)
$stage4D1AWarningMessages = @(
    $logLines |
        Where-Object {
            $line = $_
            $warningCodeRegex.IsMatch($line) -and
                @($stage4D1ATargetFiles | Where-Object {
                    $line -match ([regex]::Escape($_) + "\(")
                }).Count -gt 0
        } |
        ForEach-Object { $_.Trim() } |
        Sort-Object -Unique
)
$stage4D1BTargetFiles = @(
    "QuickCaptureSurfaceContent.xaml.cs",
    "Localized.cs"
)
$stage4D1BWarningMessages = @(
    $logLines |
        Where-Object {
            $line = $_
            $warningCodeRegex.IsMatch($line) -and
                @($stage4D1BTargetFiles | Where-Object {
                    $line -match ([regex]::Escape($_) + "\(")
                }).Count -gt 0
        } |
        ForEach-Object { $_.Trim() } |
        Sort-Object -Unique
)
$stage4D2RemovedSourceFiles = @(
    "src\DeskBox\Helpers\FileOperationHelper.cs"
)
$stage4D2UnexpectedExistingSourceFiles = @(
    $stage4D2RemovedSourceFiles |
        Where-Object { Test-Path -LiteralPath (Join-Path $repoRoot $_) }
)
$stage4D2FileOperationWarningMessages = @(
    $logLines |
        Where-Object {
            $line = $_
            $warningCodeRegex.IsMatch($line) -and
                ($line -match "FileOperationHelper|IFileOperation|IShellItem")
        } |
        ForEach-Object { $_.Trim() } |
        Sort-Object -Unique
)
$stage4D3ASourceFiles = @(
    "src\DeskBox\Helpers\NativeDropTarget.cs",
    "src\DeskBox\Helpers\NativeDropComDataReader.cs"
)
$stage4D3ALegacyRcwPatterns = @(
    "COMIDataObject",
    "Marshal.GetObjectForIUnknown",
    "Marshal.GetIUnknownForObject",
    "Marshal.ReleaseComObject",
    "(IStream)"
)
$stage4D3ALegacyRcwSourceMatches = @(
    foreach ($relativePath in $stage4D3ASourceFiles) {
        $fullPath = Join-Path $repoRoot $relativePath
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            "{0}:<missing>" -f $relativePath
            continue
        }

        $lineNumber = 0
        foreach ($sourceLine in Get-Content -LiteralPath $fullPath) {
            $lineNumber++
            foreach ($pattern in $stage4D3ALegacyRcwPatterns) {
                if ($sourceLine.IndexOf($pattern, [StringComparison]::Ordinal) -ge 0) {
                    "{0}:{1}:{2}" -f $relativePath, $lineNumber, $pattern
                }
            }
        }
    }
)
$stage4D3ADataReaderWarningMessages = @(
    $logLines |
        Where-Object {
            $warningCodeRegex.IsMatch($_) -and
                $_ -match ([regex]::Escape("NativeDropComDataReader.cs") + "\(")
        } |
        ForEach-Object { $_.Trim() } |
        Sort-Object -Unique
)
$stage4D3ARemainingDropTargetWarningMessages = @(
    $logLines |
        Where-Object {
            $warningCodeRegex.IsMatch($_) -and
                $_ -match ([regex]::Escape("NativeDropTarget.cs") + "\(")
        } |
        ForEach-Object { $_.Trim() } |
        Sort-Object -Unique
)
$stage4D3AUnexpectedDropTargetWarningMessages = @(
    $stage4D3ARemainingDropTargetWarningMessages |
        Where-Object {
            $_ -notmatch "IL2050" -or
                $_ -notmatch "RegisterDragDrop"
        }
)
$stage4D3BSourceFiles = @(
    "src\DeskBox\Helpers\NativeDropTarget.cs",
    "src\DeskBox\Helpers\NativeDropTargetComInterop.cs"
)
$stage4D3BLegacyRegistrationPatterns = @(
    "[ComImport",
    "[ComVisible",
    "interface IDropTarget",
    "RegisterDragDrop(IntPtr hwnd, IDropTarget dropTarget)",
    "Marshal.GetIUnknownForObject",
    "Marshal.GetComInterfaceForObject"
)
$stage4D3BLegacyRegistrationSourceMatches = @(
    foreach ($relativePath in $stage4D3BSourceFiles) {
        $fullPath = Join-Path $repoRoot $relativePath
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            "{0}:<missing>" -f $relativePath
            continue
        }

        $lineNumber = 0
        foreach ($sourceLine in Get-Content -LiteralPath $fullPath) {
            $lineNumber++
            foreach ($pattern in $stage4D3BLegacyRegistrationPatterns) {
                if ($sourceLine.IndexOf($pattern, [StringComparison]::Ordinal) -ge 0) {
                    "{0}:{1}:{2}" -f $relativePath, $lineNumber, $pattern
                }
            }
        }
    }
)
$stage4D3BRequiredGeneratedComPatterns = @(
    "[GeneratedComInterface",
    "ComInterfaceOptions.ManagedObjectWrapper",
    "partial interface INativeDropTarget",
    "[GeneratedComClass]",
    "partial class NativeDropTargetComObject : INativeDropTarget",
    "[LibraryImport(`"ole32.dll`")]",
    "RegisterDragDrop(nint hwnd, nint dropTarget)",
    "ComInterfaceMarshaller<INativeDropTarget>.ConvertToUnmanaged",
    "ComInterfaceMarshaller<INativeDropTarget>.Free"
)
$stage4D3BInteropSourcePath = Join-Path $repoRoot (
    "src\DeskBox\Helpers\NativeDropTargetComInterop.cs")
$stage4D3BInteropSource = if (
    Test-Path -LiteralPath $stage4D3BInteropSourcePath -PathType Leaf) {
    Get-Content -LiteralPath $stage4D3BInteropSourcePath -Raw
}
else {
    ""
}
$stage4D3BMissingGeneratedComPatterns = @(
    $stage4D3BRequiredGeneratedComPatterns |
        Where-Object {
            $stage4D3BInteropSource.IndexOf(
                $_,
                [StringComparison]::Ordinal) -lt 0
        }
)
$stage4D3BWarningMessages = @(
    $logLines |
        Where-Object {
            $warningCodeRegex.IsMatch($_) -and
                (
                    $_ -match "NativeDropTarget(?:ComInterop)?\.cs\(" -or
                    $_ -match "INativeDropTarget|NativeDropTargetComObject"
                )
        } |
        ForEach-Object { $_.Trim() } |
        Sort-Object -Unique
)
$stage4D3BIl2050WarningMessages = @(
    $logLines |
        Where-Object { $_ -match "\bIL2050\b" } |
        ForEach-Object { $_.Trim() } |
        Sort-Object -Unique
)
$stage4D4ASourceFiles = @(
    "src\DeskBox\Helpers\ExplorerShellLaunchService.cs",
    "src\DeskBox\Helpers\ExplorerShellLaunchNativeBackend.cs"
)
$stage4D4AWarningMessages = @(
    $logLines |
        Where-Object {
            $line = $_
            $warningCodeRegex.IsMatch($line) -and
                (
                    $line -match "ExplorerShellLaunch(?:Service|NativeBackend)\.cs\(" -or
                    $line -match "ExplorerShellLaunchService|ExplorerShellLaunchNativeBackend"
                )
        } |
        ForEach-Object { $_.Trim() } |
        Sort-Object -Unique
)
$stage4D4BSourceFiles = @(
    "src\DeskBox\Helpers\ExplorerQuickAccessHelper.cs",
    "src\DeskBox\Helpers\QuickAccessNativeBackend.cs"
)
$stage4D4BWarningMessages = @(
    $logLines |
        Where-Object {
            $line = $_
            $warningCodeRegex.IsMatch($line) -and
                (
                    $line -match "(?:ExplorerQuickAccessHelper|QuickAccessNativeBackend)\.cs\(" -or
                    $line -match "ExplorerQuickAccessHelper|QuickAccessNativeBackend"
                )
        } |
        ForEach-Object { $_.Trim() } |
        Sort-Object -Unique
)
$stage4D5SourceFiles = @(
    "src\DeskBox\App.Tray.cs"
)
$stage4D5LegacyReflectionPatterns = @(
    "System.Reflection.BindingFlags",
    "GetProperty(`"ContextMenuFlyout`"",
    "GetProperty(`"TrayIcon`"",
    "GetProperty(`"WindowHandle`"",
    "GetProperty(`"Id`""
)
$stage4D5RequiredPublicPatterns = @(
    "_trayIcon.TrayIcon",
    "trayIcon.WindowHandle",
    "trayIcon.Id",
    "SecondWindowContextMenuOpened +=",
    "VisualTreeHelper.GetParent",
    "VisualTreeHelper.GetOpenPopupsForXamlRoot"
)
$stage4D5SourcePath = Join-Path $repoRoot $stage4D5SourceFiles[0]
$stage4D5Source = Get-Content -LiteralPath $stage4D5SourcePath -Raw
$stage4D5LegacyReflectionSourceMatches = @(
    foreach ($pattern in $stage4D5LegacyReflectionPatterns) {
        if ($stage4D5Source.IndexOf($pattern, [StringComparison]::Ordinal) -ge 0) {
            "$($stage4D5SourceFiles[0])::$pattern"
        }
    }
)
$stage4D5MissingPublicPatterns = @(
    $stage4D5RequiredPublicPatterns |
        Where-Object {
            $stage4D5Source.IndexOf($_, [StringComparison]::Ordinal) -lt 0
        }
)
$stage4D5WarningMessages = @(
    $logLines |
        Where-Object {
            $line = $_
            $warningCodeRegex.IsMatch($line) -and
                (
                    $line -match "App\.Tray\.cs\(" -or
                    $line -match "DeskBox\.App\.(?:TryGetTrayIconIdentity|ApplySecondWindowTrayPresenterSettings|ConfigureOwningPopup)"
                )
        } |
        ForEach-Object { $_.Trim() } |
        Sort-Object -Unique
)
$stage4E0SourceFiles = @(
    "src\DeskBox\Controls\WidgetContents\SearchWidgetContent.xaml",
    "src\DeskBox\Controls\WidgetContents\SearchWidgetContent.xaml.cs",
    "src\DeskBox\Models\SearchModels.cs"
)
$stage4E0XamlPath = Join-Path $repoRoot $stage4E0SourceFiles[0]
$stage4E0CodeBehindPath = Join-Path $repoRoot $stage4E0SourceFiles[1]
$stage4E0ModelPath = Join-Path $repoRoot $stage4E0SourceFiles[2]
$stage4E0Xaml = Get-Content -LiteralPath $stage4E0XamlPath -Raw
$stage4E0CodeBehind = Get-Content -LiteralPath $stage4E0CodeBehindPath -Raw
$stage4E0Model = Get-Content -LiteralPath $stage4E0ModelPath -Raw
$stage4E0LegacyOneWayPatterns = @(
    "{x:Bind Query, Mode=OneWay}",
    "{x:Bind DeleteLabel, Mode=OneWay}"
)
$stage4E0LegacyOneWaySourceMatches = @(
    foreach ($pattern in $stage4E0LegacyOneWayPatterns) {
        if ($stage4E0Xaml.IndexOf($pattern, [StringComparison]::Ordinal) -ge 0) {
            "$($stage4E0SourceFiles[0])::$pattern"
        }
    }
)
$stage4E0RequiredOneTimeBindings = @(
    [PSCustomObject]@{
        pattern = "{x:Bind Query, Mode=OneTime}"
        expectedCount = 4
    },
    [PSCustomObject]@{
        pattern = "{x:Bind DeleteLabel, Mode=OneTime}"
        expectedCount = 2
    }
)
$stage4E0MissingOneTimeBindings = @(
    foreach ($binding in $stage4E0RequiredOneTimeBindings) {
        $actualCount = [regex]::Matches(
            $stage4E0Xaml,
            [regex]::Escape($binding.pattern)).Count
        if ($actualCount -ne $binding.expectedCount) {
            "$($binding.pattern) expected=$($binding.expectedCount) actual=$actualCount"
        }
    }
)
$stage4E0RequiredBehaviorPatterns = @(
    [PSCustomObject]@{
        sourceFile = $stage4E0SourceFiles[2]
        source = $stage4E0Model
        pattern = "public required string Query { get; init; }"
    },
    [PSCustomObject]@{
        sourceFile = $stage4E0SourceFiles[2]
        source = $stage4E0Model
        pattern = "public required string DeleteLabel { get; init; }"
    },
    [PSCustomObject]@{
        sourceFile = $stage4E0SourceFiles[1]
        source = $stage4E0CodeBehind
        pattern = "_recentQueries.Clear();"
    },
    [PSCustomObject]@{
        sourceFile = $stage4E0SourceFiles[1]
        source = $stage4E0CodeBehind
        pattern = "_recentQueries.Add(new SearchHistoryEntry"
    }
)
$stage4E0MissingBehaviorPatterns = @(
    foreach ($contract in $stage4E0RequiredBehaviorPatterns) {
        if ($contract.source.IndexOf($contract.pattern, [StringComparison]::Ordinal) -lt 0) {
            "$($contract.sourceFile)::$($contract.pattern)"
        }
    }
)
$stage4E0Wmc1506WarningMessages = @(
    $logLines |
        Where-Object { $_ -match "\bWMC1506\b" } |
        ForEach-Object { $_.Trim() } |
        Sort-Object -Unique
)
$stage4E0SourceWarningMessages = @(
    $logLines |
        Where-Object {
            $line = $_
            $warningCodeRegex.IsMatch($line) -and
                $line -match "SearchWidgetContent\.xaml(?:\.cs)?\("
        } |
        ForEach-Object { $_.Trim() } |
        Sort-Object -Unique
)
$stage4E1SourceFiles = @(
    "src\DeskBox\Controls\PinStateIcon.xaml",
    "src\DeskBox\Controls\PinStateIcon.xaml.cs",
    "src\DeskBox\Controls\MarkdownSourceEditor.xaml",
    "src\DeskBox\Controls\MarkdownSourceEditor.xaml.cs",
    "src\DeskBox\Controls\DesktopOrganizationTaskView.xaml",
    "src\DeskBox\Controls\DesktopOrganizationTaskView.xaml.cs",
    "src\DeskBox\Views\SettingsSections\DesktopOrganizationSettingsSection.xaml",
    "src\DeskBox\Views\SettingsSections\DesktopOrganizationSettingsSection.xaml.cs"
)
$stage4E1Sources = [ordered]@{}
foreach ($sourceFile in $stage4E1SourceFiles) {
    $stage4E1Sources[$sourceFile] = Get-Content -LiteralPath (Join-Path $repoRoot $sourceFile) -Raw
}
$stage4E1LegacyBindingContracts = @(
    [PSCustomObject]@{
        sourceFile = $stage4E1SourceFiles[0]
        pattern = "{Binding Foreground, ElementName=Root}"
    },
    [PSCustomObject]@{
        sourceFile = $stage4E1SourceFiles[2]
        pattern = "{Binding EditorFontSize, ElementName=Root}"
    },
    [PSCustomObject]@{
        sourceFile = $stage4E1SourceFiles[2]
        pattern = "{Binding IsReadOnly, ElementName=Root}"
    },
    [PSCustomObject]@{
        sourceFile = $stage4E1SourceFiles[2]
        pattern = "{Binding PlaceholderText, ElementName=Root}"
    },
    [PSCustomObject]@{
        sourceFile = $stage4E1SourceFiles[4]
        pattern = 'ToolTipService.ToolTip="{Binding Text, RelativeSource={RelativeSource Self}}"'
    },
    [PSCustomObject]@{
        sourceFile = $stage4E1SourceFiles[6]
        pattern = 'ToolTipService.ToolTip="{Binding Text, RelativeSource={RelativeSource Self}}"'
    }
)
$stage4E1LegacyBindingSourceMatches = @(
    foreach ($contract in $stage4E1LegacyBindingContracts) {
        if ($stage4E1Sources[$contract.sourceFile].IndexOf(
                $contract.pattern,
                [StringComparison]::Ordinal) -ge 0) {
            "$($contract.sourceFile)::$($contract.pattern)"
        }
    }
)
$stage4E1RequiredCompiledBindings = @(
    [PSCustomObject]@{
        sourceFile = $stage4E1SourceFiles[0]
        pattern = "{x:Bind Foreground, Mode=OneWay}"
        expectedCount = 2
    },
    [PSCustomObject]@{
        sourceFile = $stage4E1SourceFiles[2]
        pattern = "{x:Bind EditorFontSize, Mode=OneWay}"
        expectedCount = 1
    },
    [PSCustomObject]@{
        sourceFile = $stage4E1SourceFiles[2]
        pattern = "{x:Bind IsReadOnly, Mode=OneWay}"
        expectedCount = 1
    },
    [PSCustomObject]@{
        sourceFile = $stage4E1SourceFiles[2]
        pattern = "{x:Bind PlaceholderText, Mode=OneWay}"
        expectedCount = 1
    },
    [PSCustomObject]@{
        sourceFile = $stage4E1SourceFiles[4]
        pattern = 'ToolTipService.ToolTip="{x:Bind StoragePathText.Text, Mode=OneWay}"'
        expectedCount = 1
    },
    [PSCustomObject]@{
        sourceFile = $stage4E1SourceFiles[6]
        pattern = 'ToolTipService.ToolTip="{x:Bind RuleDetailPath.Text, Mode=OneWay}"'
        expectedCount = 1
    }
)
$stage4E1MissingCompiledBindings = @(
    foreach ($binding in $stage4E1RequiredCompiledBindings) {
        $actualCount = [regex]::Matches(
            $stage4E1Sources[$binding.sourceFile],
            [regex]::Escape($binding.pattern)).Count
        if ($actualCount -ne $binding.expectedCount) {
            "$($binding.sourceFile)::$($binding.pattern) expected=$($binding.expectedCount) actual=$actualCount"
        }
    }
)
$stage4E1RequiredBehaviorPatterns = @(
    [PSCustomObject]@{
        sourceFile = $stage4E1SourceFiles[1]
        pattern = "IsPinnedProperty"
    },
    [PSCustomObject]@{
        sourceFile = $stage4E1SourceFiles[3]
        pattern = "EditorFontSizeProperty"
    },
    [PSCustomObject]@{
        sourceFile = $stage4E1SourceFiles[3]
        pattern = "IsReadOnlyProperty"
    },
    [PSCustomObject]@{
        sourceFile = $stage4E1SourceFiles[3]
        pattern = "PlaceholderTextProperty"
    },
    [PSCustomObject]@{
        sourceFile = $stage4E1SourceFiles[5]
        pattern = "StoragePathText.Text ="
    },
    [PSCustomObject]@{
        sourceFile = $stage4E1SourceFiles[7]
        pattern = "RuleDetailPath.Text ="
    }
)
$stage4E1MissingBehaviorPatterns = @(
    foreach ($contract in $stage4E1RequiredBehaviorPatterns) {
        if ($stage4E1Sources[$contract.sourceFile].IndexOf(
                $contract.pattern,
                [StringComparison]::Ordinal) -lt 0) {
            "$($contract.sourceFile)::$($contract.pattern)"
        }
    }
)
$stage4E1DeferredBindingContracts = @(
    [PSCustomObject]@{
        sourceFile = "src\DeskBox\App.xaml"
        pattern = 'Value="{Binding SegmentHeight}"'
    },
    [PSCustomObject]@{
        sourceFile = "src\DeskBox\App.xaml"
        pattern = 'Value="{Binding SegmentTextSize}"'
    },
    [PSCustomObject]@{
        sourceFile = "src\DeskBox\Views\ContentWidgetWindow.xaml"
        pattern = 'OverlayTitle="{Binding DisplayName}"'
    }
)
$stage4E1MissingDeferredBindings = @(
    foreach ($contract in $stage4E1DeferredBindingContracts) {
        $source = Get-Content -LiteralPath (Join-Path $repoRoot $contract.sourceFile) -Raw
        if ($source.IndexOf($contract.pattern, [StringComparison]::Ordinal) -lt 0) {
            "$($contract.sourceFile)::$($contract.pattern)"
        }
    }
)
$stage4E1SourceWarningMessages = @(
    $logLines |
        Where-Object {
            $line = $_
            $warningCodeRegex.IsMatch($line) -and
                $line -match "(?:PinStateIcon|MarkdownSourceEditor|DesktopOrganizationTaskView|DesktopOrganizationSettingsSection)\.xaml\("
        } |
        ForEach-Object { $_.Trim() } |
        Sort-Object -Unique
)
$stage4E1MaximumWmc1510Count = 1258
$stage4E1ActualWmc1510Count = @(
    $warningMatches | Where-Object { $_ -ieq "WMC1510" }
).Count
$stage4E2SourceFiles = @(
    "src\DeskBox\Controls\WidgetContents\MusicTransportIcon.xaml",
    "src\DeskBox\Controls\WidgetContents\MusicTransportIcon.xaml.cs",
    "src\DeskBox\Controls\WidgetInlineEditor.xaml",
    "src\DeskBox\Controls\WidgetInlineEditor.xaml.cs"
)
$stage4E2Sources = [ordered]@{}
foreach ($sourceFile in $stage4E2SourceFiles) {
    $stage4E2Sources[$sourceFile] = Get-Content -LiteralPath (Join-Path $repoRoot $sourceFile) -Raw
}
$stage4E2LegacyBindingContracts = @(
    [PSCustomObject]@{
        sourceFile = $stage4E2SourceFiles[0]
        pattern = "{Binding Foreground, ElementName=Root}"
    },
    [PSCustomObject]@{
        sourceFile = $stage4E2SourceFiles[2]
        pattern = "{Binding TitleFontSize, ElementName=InlineEditorRoot}"
    },
    [PSCustomObject]@{
        sourceFile = $stage4E2SourceFiles[2]
        pattern = "{Binding Title, ElementName=InlineEditorRoot}"
    },
    [PSCustomObject]@{
        sourceFile = $stage4E2SourceFiles[2]
        pattern = "{Binding EditorFontSize, ElementName=InlineEditorRoot}"
    },
    [PSCustomObject]@{
        sourceFile = $stage4E2SourceFiles[2]
        pattern = "{Binding Text, ElementName=InlineEditorRoot, Mode=TwoWay, UpdateSourceTrigger=PropertyChanged}"
    },
    [PSCustomObject]@{
        sourceFile = $stage4E2SourceFiles[2]
        pattern = "{Binding CancelText, ElementName=InlineEditorRoot}"
    },
    [PSCustomObject]@{
        sourceFile = $stage4E2SourceFiles[2]
        pattern = "{Binding CommandFontSize, ElementName=InlineEditorRoot}"
    },
    [PSCustomObject]@{
        sourceFile = $stage4E2SourceFiles[2]
        pattern = "{Binding SaveText, ElementName=InlineEditorRoot}"
    }
)
$stage4E2LegacyBindingSourceMatches = @(
    foreach ($contract in $stage4E2LegacyBindingContracts) {
        if ($stage4E2Sources[$contract.sourceFile].IndexOf(
                $contract.pattern,
                [StringComparison]::Ordinal) -ge 0) {
            "$($contract.sourceFile)::$($contract.pattern)"
        }
    }
)
$stage4E2RequiredCompiledBindings = @(
    [PSCustomObject]@{
        sourceFile = $stage4E2SourceFiles[0]
        pattern = "{x:Bind Foreground, Mode=OneWay}"
        expectedCount = 7
    },
    [PSCustomObject]@{
        sourceFile = $stage4E2SourceFiles[2]
        pattern = "{x:Bind TitleFontSize, Mode=OneWay}"
        expectedCount = 1
    },
    [PSCustomObject]@{
        sourceFile = $stage4E2SourceFiles[2]
        pattern = "{x:Bind Title, Mode=OneWay}"
        expectedCount = 1
    },
    [PSCustomObject]@{
        sourceFile = $stage4E2SourceFiles[2]
        pattern = "{x:Bind EditorFontSize, Mode=OneWay}"
        expectedCount = 1
    },
    [PSCustomObject]@{
        sourceFile = $stage4E2SourceFiles[2]
        pattern = "{x:Bind Text, Mode=TwoWay, UpdateSourceTrigger=PropertyChanged}"
        expectedCount = 1
    },
    [PSCustomObject]@{
        sourceFile = $stage4E2SourceFiles[2]
        pattern = "{x:Bind CancelTe…90305 tokens truncated…C AOT session-volume runner contracts are missing: $($stage5B3CMissingRunnerPatterns -join ', '). See '$summaryPath'."
}

if ($stage5B3CMissingLaunchPatterns.Count -gt 0 -or -not $stage5B3CLaunchOrderValid) {
    throw "Stage 5B-3C AOT session-volume smoke is not scheduled after the system-volume smoke. See '$summaryPath'."
}

if ($stage5B3CMissingProductPatterns.Count -gt 0) {
    throw "Stage 5B-3C product session getter/setter boundary is incomplete: $($stage5B3CMissingProductPatterns -join ', '). See '$summaryPath'."
}

if ($stage5B3CMissingFixturePatterns.Count -gt 0) {
    throw "Stage 5B-3C controlled silent Rust fixture is incomplete: $($stage5B3CMissingFixturePatterns -join ', '). See '$summaryPath'."
}

if ($stage5B3CMissingSmokeScriptPatterns.Count -gt 0) {
    throw "Stage 5B-3C session-volume mutation script gates are missing: $($stage5B3CMissingSmokeScriptPatterns -join ', '). See '$summaryPath'."
}

if ($stage5B3CUnsafeMutationPatterns.Count -gt 0) {
    throw "Stage 5B-3C runner bypasses the product session setter or reaches system mutation: $($stage5B3CUnsafeMutationPatterns -join ', '). See '$summaryPath'."
}

if ($stage5B3CUnsafeRunnerPatterns.Count -gt 0) {
    throw "Stage 5B-3C session-volume runner contains unsafe non-preview behavior: $($stage5B3CUnsafeRunnerPatterns -join ', '). See '$summaryPath'."
}

if ($stage5B3CUnsafeFixtureScriptPatterns.Count -gt 0) {
    throw "Stage 5B-3C fixture/script process isolation is unsafe: $($stage5B3CUnsafeFixtureScriptPatterns -join ', '). See '$summaryPath'."
}

if (-not $stage5B3CRecoveryOrderValid) {
    throw "Stage 5B-3C recovery ordering changed: identity/original intent must precede session mutation and verified matched recovery must precede intent deletion. See '$summaryPath'."
}

if ($stage5B3CSourceWarningMessages.Count -gt 0) {
    throw "Stage 5B-3C session-volume sources produced AOT warnings. See '$summaryPath'."
}

if ($stage5B3CActualWmc1510Count -ne $stage5B3CExpectedWmc1510Count) {
    throw "Stage 5B-3C WMC1510 count changed: expected=$stage5B3CExpectedWmc1510Count actual=$stage5B3CActualWmc1510Count. See '$summaryPath'."
}

if ($stage5B4AMissingRunnerPatterns.Count -gt 0) {
    throw "Stage 5B-4A managed UI runner contracts are missing: $($stage5B4AMissingRunnerPatterns -join ', '). See '$summaryPath'."
}

if ($stage5B4AMissingLaunchPatterns.Count -gt 0 -or -not $stage5B4ALaunchOrderValid) {
    throw "Stage 5B-4A managed UI smoke is not scheduled after all native boundary smokes. See '$summaryPath'."
}

if ($stage5B4AMissingSettingsPatterns.Count -gt 0) {
    throw "Stage 5B-4A settings-window diagnostic contracts are missing: $($stage5B4AMissingSettingsPatterns -join ', '). See '$summaryPath'."
}

if ($stage5B4AMissingSettingsNavigationPatterns.Count -gt 0 -or
    $stage5B4AUnsafeSettingsNavigationPatterns.Count -gt 0) {
    throw "Stage 5B-4A settings search empty-state AOT projection guard is incomplete. See '$summaryPath'."
}

if ($stage5B4AMissingSearchPatterns.Count -gt 0 -or
    $stage5B4ASortHandlerCountViolations.Count -gt 0) {
    throw "Stage 5B-4A search control routing contracts are incomplete. See '$summaryPath'."
}

if ($stage5B4AMissingLocalePatterns.Count -gt 0) {
    throw "Stage 5B-4A locale resource diagnostic contracts are missing: $($stage5B4AMissingLocalePatterns -join ', '). See '$summaryPath'."
}

if ($stage5B4AMissingSmokeScriptPatterns.Count -gt 0) {
    throw "Stage 5B-4A managed UI outer-runner gates are missing: $($stage5B4AMissingSmokeScriptPatterns -join ', '). See '$summaryPath'."
}

if ($stage5B4AMissingSmokeOptInIsolation.Count -gt 0) {
    throw "Stage 5B-4A smoke opt-in isolation is incomplete: $($stage5B4AMissingSmokeOptInIsolation -join ', '). See '$summaryPath'."
}

if ($stage5B4AUnsafeRunnerPatterns.Count -gt 0 -or
    $stage5B4AUnsafeSmokeScriptPatterns.Count -gt 0) {
    throw "Stage 5B-4A managed UI matrix contains a forbidden mutation or broad process operation. See '$summaryPath'."
}

if ($stage5B4AJsonSerializeCallCount -ne 1) {
    throw "Stage 5B-4A managed UI evidence must use exactly one source-generated JSON call. See '$summaryPath'."
}

if ($stage5B4ASourceWarningMessages.Count -gt 0) {
    throw "Stage 5B-4A managed UI sources produced AOT warnings. See '$summaryPath'."
}

if ($stage5B4AActualWmc1510Count -ne $stage5B4AExpectedWmc1510Count) {
    throw "Stage 5B-4A WMC1510 count changed: expected=$stage5B4AExpectedWmc1510Count actual=$stage5B4AActualWmc1510Count. See '$summaryPath'."
}

if ($stage5B4B1MissingRunnerPatterns.Count -gt 0) {
    throw "Stage 5B-4B1 deep-settings runner contracts are missing: $($stage5B4B1MissingRunnerPatterns -join ', '). See '$summaryPath'."
}

if ($stage5B4B1MissingSettingsPatterns.Count -gt 0 -or
    $stage5B4B1MissingNavigationPatterns.Count -gt 0 -or
    $stage5B4B1MissingProjectionPatterns.Count -gt 0 -or
    $stage5B4B1MissingInventoryPatterns.Count -gt 0 -or
    $stage5B4B1MissingBindableTypePatterns.Count -gt 0 -or
    $stage5B4B1MissingFileStackXamlPatterns.Count -gt 0 -or
    $stage5B4B1MissingFileWidgetProjectionPatterns.Count -gt 0 -or
    $stage5B4B1MissingWeatherProjectionPatterns.Count -gt 0 -or
    $stage5B4B1MissingCommandXamlPatterns.Count -gt 0 -or
    $stage5B4B1MissingCapsuleCommandXamlPatterns.Count -gt 0 -or
    $stage5B4B1MissingCapsuleCodeBehindPatterns.Count -gt 0 -or
    $stage5B4B1MissingRoutePatterns.Count -gt 0) {
    throw "Stage 5B-4B1 deep-settings search, navigation, breadcrumb, or route contracts are incomplete. See '$summaryPath'."
}

if ($stage5B4B1ActualBindableViewModelPropertyCount -ne
        $stage5B4B1ExpectedBindableViewModelPropertyCount -or
    $stage5B4B1UnsafeBindableViewModelPatterns.Count -gt 0) {
    throw "Stage 5B-4B1 SettingsViewModel generated binding scope is incomplete or includes unsupported generated commands. See '$summaryPath'."
}

if ($stage5B4B1MissingSmokeScriptPatterns.Count -gt 0) {
    throw "Stage 5B-4B1 managed UI outer-runner gates are missing: $($stage5B4B1MissingSmokeScriptPatterns -join ', '). See '$summaryPath'."
}

if ($stage5B4B1UnsafeMutationPatterns.Count -gt 0) {
    throw "Stage 5B-4B1 deep-settings matrix contains a forbidden mutation or broad process operation. See '$summaryPath'."
}

if ($stage5B4B1JsonSerializeCallCount -ne 1) {
    throw "Stage 5B-4B1 deep-settings evidence must reuse the single source-generated JSON call. See '$summaryPath'."
}

if ($stage5B4B1SourceWarningMessages.Count -gt 0) {
    throw "Stage 5B-4B1 deep-settings sources produced AOT warnings. See '$summaryPath'."
}

if ($stage5B4B1ActualWmc1510Count -ne $stage5B4B1ExpectedWmc1510Count) {
    throw "Stage 5B-4B1 WMC1510 count changed: expected=$stage5B4B1ExpectedWmc1510Count actual=$stage5B4B1ActualWmc1510Count. See '$summaryPath'."
}

if ($stage5B4B2AMissingRunnerPatterns.Count -gt 0 -or
    $stage5B4B2AMissingManagerPatterns.Count -gt 0 -or
    $stage5B4B2AMissingBoundsPatterns.Count -gt 0) {
    throw "Stage 5B-4B2A managed persistence runner, widget, or HWND bounds contracts are incomplete. See '$summaryPath'."
}

if ($stage5B4B2AMissingSmokeScriptPatterns.Count -gt 0 -or
    $stage5B4B2AMissingLauncherPatterns.Count -gt 0) {
    throw "Stage 5B-4B2A three-process outer-runner or natural-exit launcher gates are missing. See '$summaryPath'."
}

if ($stage5B4B2AForbiddenScopePatterns.Count -gt 0) {
    throw "Stage 5B-4B2A persistence matrix entered deferred content stores, OS interaction, or broad process scope. See '$summaryPath'."
}

if ($stage5B4B2AJsonSerializeCallCount -ne 1) {
    throw "Stage 5B-4B2A evidence must reuse the single source-generated JSON call. See '$summaryPath'."
}

if ($stage5B4B2ASourceWarningMessages.Count -gt 0) {
    throw "Stage 5B-4B2A persistence sources produced AOT warnings. See '$summaryPath'."
}

if ($stage5B4B2AActualWmc1510Count -ne $stage5B4B2AExpectedWmc1510Count) {
    throw "Stage 5B-4B2A WMC1510 count changed: expected=$stage5B4B2AExpectedWmc1510Count actual=$stage5B4B2AActualWmc1510Count. See '$summaryPath'."
}

if ($stage5B4B2B1MissingRunnerPatterns.Count -gt 0 -or
    $stage5B4B2B1MissingSurfacePatterns.Count -gt 0 -or
    $stage5B4B2B1MissingProductSurfacePatterns.Count -gt 0 -or
    $stage5B4B2B1MissingManagerPatterns.Count -gt 0) {
    throw "Stage 5B-4B2B1 Quick Capture runner, real UI timer, store, attachment, or host contracts are incomplete. See '$summaryPath'."
}

if ($stage5B4B2B1MissingSmokeScriptPatterns.Count -gt 0) {
    throw "Stage 5B-4B2B1 three-process outer-runner, cleanup, or natural-exit gates are missing. See '$summaryPath'."
}

if ($stage5B4B2B1ForbiddenScopePatterns.Count -gt 0) {
    throw "Stage 5B-4B2B1 entered a deferred store, OS interaction, direct file mutation, or broad widget scope. See '$summaryPath'."
}

if ($stage5B4B2B1JsonSerializeCallCount -ne 1) {
    throw "Stage 5B-4B2B1 evidence must reuse the single source-generated JSON call. See '$summaryPath'."
}

if ($stage5B4B2B1SourceWarningMessages.Count -gt 0) {
    throw "Stage 5B-4B2B1 Quick Capture sources produced AOT warnings. See '$summaryPath'."
}

if ($stage5B4B2B1ActualWmc1510Count -ne $stage5B4B2B1ExpectedWmc1510Count) {
    throw "Stage 5B-4B2B1 WMC1510 count changed: expected=$stage5B4B2B1ExpectedWmc1510Count actual=$stage5B4B2B1ActualWmc1510Count. See '$summaryPath'."
}

if ($stage5B4B2B2AMissingRunnerPatterns.Count -gt 0 -or
    $stage5B4B2B2AMissingSurfacePatterns.Count -gt 0 -or
    $stage5B4B2B2AMissingProductPatterns.Count -gt 0 -or
    $stage5B4B2B2AMissingManagerPatterns.Count -gt 0) {
    throw "Stage 5B-4B2B2A Todo runner, real UI timer/save paths, store, or host contracts are incomplete. See '$summaryPath'."
}

if ($stage5B4B2B2AMissingSmokeScriptPatterns.Count -gt 0) {
    throw "Stage 5B-4B2B2A three-process outer-runner, cleanup, or natural-exit gates are missing. See '$summaryPath'."
}

if ($stage5B4B2B2AForbiddenScopePatterns.Count -gt 0) {
    throw "Stage 5B-4B2B2A entered deferred Todo steps/attachments/reminders/recurrence, direct mutation, OS interaction, or broad widget scope. See '$summaryPath'."
}

if ($stage5B4B2B2AJsonSerializeCallCount -ne 1) {
    throw "Stage 5B-4B2B2A evidence must reuse the single source-generated JSON call. See '$summaryPath'."
}

if ($stage5B4B2B2ASourceWarningMessages.Count -gt 0) {
    throw "Stage 5B-4B2B2A Todo sources produced AOT warnings. See '$summaryPath'."
}

if ($stage5B4B2B2AActualWmc1510Count -ne $stage5B4B2B2AExpectedWmc1510Count) {
    throw "Stage 5B-4B2B2A WMC1510 count changed: expected=$stage5B4B2B2AExpectedWmc1510Count actual=$stage5B4B2B2AActualWmc1510Count. See '$summaryPath'."
}

if ($stage5B4B2B2B1MissingRunnerPatterns.Count -gt 0 -or
    $stage5B4B2B2B1MissingSurfacePatterns.Count -gt 0 -or
    $stage5B4B2B2B1MissingProductPatterns.Count -gt 0 -or
    $stage5B4B2B2B1MissingManagerPatterns.Count -gt 0) {
    throw "Stage 5B-4B2B2B1 Todo steps runner, real row UI, product paths, projection, store, or host contracts are incomplete. See '$summaryPath'."
}

if ($stage5B4B2B2B1MissingSmokeScriptPatterns.Count -gt 0) {
    throw "Stage 5B-4B2B2B1 three-process outer-runner, cleanup, process, or natural-exit gates are missing. See '$summaryPath'."
}

if ($stage5B4B2B2B1ForbiddenScopePatterns.Count -gt 0) {
    throw "Stage 5B-4B2B2B1 entered deferred Todo attachments/reminders/recurrence, direct store mutation, OS interaction, or broad widget scope. See '$summaryPath'."
}

if ($stage5B4B2B2B1GeneratedBindableCount -ne 3) {
    throw "Stage 5B-4B2B2B1 must expose exactly the three exercised Todo AOT DataContext types. See '$summaryPath'."
}

if ($stage5B4B2B2B1JsonSerializeCallCount -ne 1) {
    throw "Stage 5B-4B2B2B1 evidence must reuse the single source-generated JSON call. See '$summaryPath'."
}

if ($stage5B4B2B2B1SourceWarningMessages.Count -gt 0) {
    throw "Stage 5B-4B2B2B1 Todo steps sources produced AOT warnings. See '$summaryPath'."
}

if ($stage5B4B2B2B1ActualWmc1510Count -ne $stage5B4B2B2B1ExpectedWmc1510Count) {
    throw "Stage 5B-4B2B2B1 WMC1510 count changed: expected=$stage5B4B2B2B1ExpectedWmc1510Count actual=$stage5B4B2B2B1ActualWmc1510Count. See '$summaryPath'."
}

if ($stage5B4B2B2B2MissingRunnerPatterns.Count -gt 0 -or
    $stage5B4B2B2B2MissingSurfacePatterns.Count -gt 0 -or
    $stage5B4B2B2B2MissingTilePatterns.Count -gt 0 -or
    $stage5B4B2B2B2MissingProductPatterns.Count -gt 0 -or
    $stage5B4B2B2B2MissingManagerPatterns.Count -gt 0) {
    throw "Stage 5B-4B2B2B2 Todo managed attachment runner, real tile UI, product paths, storage, projection, or host contracts are incomplete. See '$summaryPath'."
}

if ($stage5B4B2B2B2MissingSmokeScriptPatterns.Count -gt 0) {
    throw "Stage 5B-4B2B2B2 three-process outer-runner, hash, physical-delete, cleanup, process, or natural-exit gates are missing. See '$summaryPath'."
}

if ($stage5B4B2B2B2ForbiddenScopePatterns.Count -gt 0) {
    throw "Stage 5B-4B2B2B2 entered deferred Todo reminders/recurrence, direct store mutation, OS picker/shell interaction, Rust ABI expansion, or broad widget scope. See '$summaryPath'."
}

if ($stage5B4B2B2B2GeneratedBindableCount -ne 3) {
    throw "Stage 5B-4B2B2B2 must retain exactly the three exercised Todo AOT DataContext bridge types. See '$summaryPath'."
}

if ($stage5B4B2B2B2JsonSerializeCallCount -ne 1) {
    throw "Stage 5B-4B2B2B2 evidence must reuse the single source-generated JSON call. See '$summaryPath'."
}

if ($stage5B4B2B2B2SourceWarningMessages.Count -gt 0) {
    throw "Stage 5B-4B2B2B2 Todo managed attachment sources produced AOT warnings. See '$summaryPath'."
}

if ($stage5B4B2B2B2ActualWmc1510Count -ne $stage5B4B2B2B2ExpectedWmc1510Count) {
    throw "Stage 5B-4B2B2B2 WMC1510 count changed: expected=$stage5B4B2B2B2ExpectedWmc1510Count actual=$stage5B4B2B2B2ActualWmc1510Count. See '$summaryPath'."
}

if ($stage5B4B2C1MissingRunnerPatterns.Count -gt 0 -or
    $stage5B4B2C1MissingSurfacePatterns.Count -gt 0 -or
    $stage5B4B2C1MissingProductPatterns.Count -gt 0 -or
    $stage5B4B2C1MissingManagerPatterns.Count -gt 0) {
    throw "Stage 5B-4B2C1 Glance runner, product policy, ViewModel, decoded image surface, or host contracts are incomplete. See '$summaryPath'."
}

if ($stage5B4B2C1MissingSmokeScriptPatterns.Count -gt 0) {
    throw "Stage 5B-4B2C1 three-process outer-runner, image hash, process, cleanup, or postflight gates are missing. See '$summaryPath'."
}

if ($stage5B4B2C1ForbiddenScopePatterns.Count -gt 0) {
    throw "Stage 5B-4B2C1 entered online images, network, picker/folder interaction, direct file mutation, Rust ABI expansion, or broad widget scope. See '$summaryPath'."
}

if ($stage5B4B2C1GeneratedBindableCount -ne 1 -or
    $stage5B4B2C1BindablePropertyCount -ne 33) {
    throw "Stage 5B-4B2C1 must expose exactly one narrow Glance AOT DataContext bridge with 33 XAML properties. See '$summaryPath'."
}

if ($stage5B4B2C1JsonSerializeCallCount -ne 1) {
    throw "Stage 5B-4B2C1 evidence must reuse the single source-generated JSON call. See '$summaryPath'."
}

if ($stage5B4B2C1SourceWarningMessages.Count -gt 0) {
    throw "Stage 5B-4B2C1 Glance persistence sources produced AOT warnings. See '$summaryPath'."
}

if ($stage5B4B2C1ActualWmc1510Count -ne $stage5B4B2C1ExpectedWmc1510Count) {
    throw "Stage 5B-4B2C1 WMC1510 count changed: expected=$stage5B4B2C1ExpectedWmc1510Count actual=$stage5B4B2C1ActualWmc1510Count. See '$summaryPath'."
}

if ($stage5B4B2C2AMissingRunnerPatterns.Count -gt 0 -or
    $stage5B4B2C2AMissingPolicyPatterns.Count -gt 0 -or
    $stage5B4B2C2AMissingManagerPatterns.Count -gt 0) {
    throw "Stage 5B-4B2C2A Weather settings runner, product policy, metadata, or suppressed-host contracts are incomplete. See '$summaryPath'."
}

if ($stage5B4B2C2AMissingSmokeScriptPatterns.Count -gt 0) {
    throw "Stage 5B-4B2C2A three-process outer-runner, equality, process, offline-log, cleanup, or postflight gates are missing. See '$summaryPath'."
}

if ($stage5B4B2C2AForbiddenScopePatterns.Count -gt 0) {
    throw "Stage 5B-4B2C2A entered deferred Weather surface/data/network/location/picker or Rust paths. See '$summaryPath'."
}

if ($stage5B4B2C2AJsonSerializeCallCount -ne 1) {
    throw "Stage 5B-4B2C2A evidence must reuse the single source-generated JSON call. See '$summaryPath'."
}

if ($stage5B4B2C2ASourceWarningMessages.Count -gt 0) {
    throw "Stage 5B-4B2C2A Weather settings persistence sources produced AOT warnings. See '$summaryPath'."
}

if ($stage5B4B2C2AActualWmc1510Count -ne $stage5B4B2C2AExpectedWmc1510Count) {
    throw "Stage 5B-4B2C2A WMC1510 count changed: expected=$stage5B4B2C2AExpectedWmc1510Count actual=$stage5B4B2C2AActualWmc1510Count. See '$summaryPath'."
}

if ($stage5B4B2C2BMissingRunnerPatterns.Count -gt 0 -or
    $stage5B4B2C2BMissingFixturePatterns.Count -gt 0 -or
    $stage5B4B2C2BMissingSurfacePatterns.Count -gt 0 -or
    $stage5B4B2C2BMissingManagerPatterns.Count -gt 0) {
    throw "Stage 5B-4B2C2B WeatherData fixture, real surface, generated binding, host, or runner contracts are incomplete. See '$summaryPath'."
}

if ($stage5B4B2C2BBindableAttributeCount -ne 3) {
    throw "Stage 5B-4B2C2B must expose exactly three generated Weather bindable providers. See '$summaryPath'."
}

if ($stage5B4B2C2BMissingSmokeScriptPatterns.Count -gt 0) {
    throw "Stage 5B-4B2C2B three-process outer-runner, equality, fixture-log, offline, cleanup, or postflight gates are missing. See '$summaryPath'."
}

if ($stage5B4B2C2BForbiddenScopePatterns.Count -gt 0) {
    throw "Stage 5B-4B2C2B fixture or real-surface probe entered production network, location, picker, file-write, or Rust paths. See '$summaryPath'."
}

if ($stage5B4B2C2BJsonSerializeCallCount -ne 1) {
    throw "Stage 5B-4B2C2B evidence must reuse the single source-generated JSON call. See '$summaryPath'."
}

if ($stage5B4B2C2BSourceWarningMessages.Count -gt 0) {
    throw "Stage 5B-4B2C2B Weather surface persistence sources produced AOT warnings. See '$summaryPath'."
}

if ($stage5B4B2C2BActualWmc1510Count -ne $stage5B4B2C2BExpectedWmc1510Count) {
    throw "Stage 5B-4B2C2B WMC1510 count changed: expected=$stage5B4B2C2BExpectedWmc1510Count actual=$stage5B4B2C2BActualWmc1510Count. See '$summaryPath'."
}

if ($stage5B4C1AMissingRunnerPatterns.Count -gt 0 -or
    $stage5B4C1AMissingFixturePatterns.Count -gt 0 -or
    $stage5B4C1AMissingSurfacePatterns.Count -gt 0 -or
    $stage5B4C1AMissingBindablePatterns.Count -gt 0) {
    throw "Stage 5B-4C1A owned local-file fixture, real surface, operation, or generated binding contracts are incomplete. See '$summaryPath'."
}

if ($stage5B4C1ABindableAttributeCount -ne 3) {
    throw "Stage 5B-4C1A must expose exactly three narrow generated File Widget bindable providers. See '$summaryPath'."
}

if ($stage5B4C1AMissingSmokeScriptPatterns.Count -gt 0) {
    throw "Stage 5B-4C1A three-process outer-runner, independent disk, equality, cleanup, or postflight gates are missing. See '$summaryPath'."
}

if ($stage5B4C1AForbiddenScopePatterns.Count -gt 0) {
    throw "Stage 5B-4C1A entered deferred Shell, picker, drag/drop, recycle, hotkey, media, network, or Rust paths. See '$summaryPath'."
}

if ($stage5B4C1AJsonSerializeCallCount -ne 1) {
    throw "Stage 5B-4C1A evidence must reuse the single source-generated JSON call. See '$summaryPath'."
}

if ($stage5B4C1ASourceWarningMessages.Count -gt 0) {
    throw "Stage 5B-4C1A local-file surface sources produced AOT warnings. See '$summaryPath'."
}

if ($stage5B4C1AActualWmc1510Count -ne $stage5B4C1AExpectedWmc1510Count) {
    throw "Stage 5B-4C1A WMC1510 count changed: expected=$stage5B4C1AExpectedWmc1510Count actual=$stage5B4C1AActualWmc1510Count. See '$summaryPath'."
}

if ($stage5B4C1B1MissingRunnerPatterns.Count -gt 0 -or
    $stage5B4C1B1MissingFixturePatterns.Count -gt 0 -or
    $stage5B4C1B1MissingProductPatterns.Count -gt 0 -or
    $stage5B4C1B1MissingMenuPatterns.Count -gt 0 -or
    $stage5B4C1B1MissingScenarioPatterns.Count -gt 0) {
    throw "Stage 5B-4C1B1 scenario, owned identity, product menu, operation, or evidence contracts are incomplete. See '$summaryPath'."
}

if ($stage5B4C1B1MissingNativePatterns.Count -gt 0 -or
    -not $stage5B4C1B1RestoreInvokeAfterEnumeration) {
    throw "Stage 5B-4C1B1 exact native Recycle Bin ABI, full enumeration, or unique-restore contracts are incomplete. See '$summaryPath'."
}

if ($stage5B4C1B1MissingSmokeScriptPatterns.Count -gt 0) {
    throw "Stage 5B-4C1B1 three-process runner, exact hash, compensation, isolation, or cleanup gates are missing. See '$summaryPath'."
}

if ($stage5B4C1B1ForbiddenScopePatterns.Count -gt 0) {
    throw "Stage 5B-4C1B1 entered deferred Shell progress, Properties, picker, physical drag/drop, or broad Recycle Bin paths. See '$summaryPath'."
}

if ($stage5B4C1B1JsonSerializeCallCount -ne 1) {
    throw "Stage 5B-4C1B1 evidence must reuse the single source-generated JSON call. See '$summaryPath'."
}

if ($stage5B4C1B1SourceWarningMessages.Count -gt 0) {
    throw "Stage 5B-4C1B1 Recycle Bin sources produced AOT warnings. See '$summaryPath'."
}

if ($stage5B4C1B1ActualWmc1510Count -ne $stage5B4C1B1ExpectedWmc1510Count) {
    throw "Stage 5B-4C1B1 WMC1510 count changed: expected=$stage5B4C1B1ExpectedWmc1510Count actual=$stage5B4C1B1ActualWmc1510Count. See '$summaryPath'."
}

if ($stage5B4C1B2AMissingRunnerPatterns.Count -gt 0 -or
    $stage5B4C1B2AMissingFixturePatterns.Count -gt 0 -or
    $stage5B4C1B2AMissingProductPatterns.Count -gt 0 -or
    $stage5B4C1B2AMissingMenuPatterns.Count -gt 0 -or
    $stage5B4C1B2AMissingScenarioPatterns.Count -gt 0) {
    throw "Stage 5B-4C1B2A scenario, owned fixture, real owner, product menu, or Shell move branch contracts are incomplete. See '$summaryPath'."
}

if ($stage5B4C1B2AMissingSmokeScriptPatterns.Count -gt 0) {
    throw "Stage 5B-4C1B2A three-process runner, exact hash, compensation, isolation, runtime-log, or cleanup gates are missing. See '$summaryPath'."
}

if ($stage5B4C1B2AForbiddenScopePatterns.Count -gt 0) {
    throw "Stage 5B-4C1B2A entered deferred Properties, picker, physical drag/drop, IFileOperation, or new Rust ABI scope. See '$summaryPath'."
}

if (-not $stage5B4C1B2ARustAbiUnchanged) {
    throw "Stage 5B-4C1B2A changed the frozen Rust ABI 2 / capability 511 / ten-export surface. See '$summaryPath'."
}

if ($stage5B4C1B2AJsonSerializeCallCount -ne 1) {
    throw "Stage 5B-4C1B2A evidence must reuse the single source-generated JSON call. See '$summaryPath'."
}

if ($stage5B4C1B2ASourceWarningMessages.Count -gt 0) {
    throw "Stage 5B-4C1B2A Shell move sources produced AOT warnings. See '$summaryPath'."
}

if ($stage5B4C1B2AActualWmc1510Count -ne $stage5B4C1B2AExpectedWmc1510Count) {
    throw "Stage 5B-4C1B2A WMC1510 count changed: expected=$stage5B4C1B2AExpectedWmc1510Count actual=$stage5B4C1B2AActualWmc1510Count. See '$summaryPath'."
}

if ($stage5B4C1B2BMissingRunnerPatterns.Count -gt 0 -or
    $stage5B4C1B2BMissingFixturePatterns.Count -gt 0 -or
    $stage5B4C1B2BMissingProductPatterns.Count -gt 0 -or
    $stage5B4C1B2BMissingMenuPatterns.Count -gt 0 -or
    $stage5B4C1B2BMissingScenarioPatterns.Count -gt 0) {
    throw "Stage 5B-4C1B2B scenario, owned target, product menu, real owner, dialog, or close contracts are incomplete. See '$summaryPath'."
}

if ($stage5B4C1B2BMissingSmokeScriptPatterns.Count -gt 0) {
    throw "Stage 5B-4C1B2B real-dialog runner, hash, isolation, natural-exit, runtime-log, or cleanup gates are missing. See '$summaryPath'."
}

if ($stage5B4C1B2BForbiddenScopePatterns.Count -gt 0) {
    throw "Stage 5B-4C1B2B entered deferred picker, physical drag/drop, IFileOperation, Recycle Bin, Shell move, or new Rust ABI scope. See '$summaryPath'."
}

if (-not $stage5B4C1B2BRustAbiUnchanged) {
    throw "Stage 5B-4C1B2B changed the frozen Rust ABI 2 / capability 511 / ten-export surface. See '$summaryPath'."
}

if ($stage5B4C1B2BJsonSerializeCallCount -ne 1) {
    throw "Stage 5B-4C1B2B evidence must reuse the single source-generated JSON call. See '$summaryPath'."
}

if ($stage5B4C1B2BSourceWarningMessages.Count -gt 0) {
    throw "Stage 5B-4C1B2B file Properties sources produced AOT warnings. See '$summaryPath'."
}

if ($stage5B4C1B2BActualWmc1510Count -ne $stage5B4C1B2BExpectedWmc1510Count) {
    throw "Stage 5B-4C1B2B WMC1510 count changed: expected=$stage5B4C1B2BExpectedWmc1510Count actual=$stage5B4C1B2BActualWmc1510Count. See '$summaryPath'."
}

if ($stage5B4C1C1MissingRunnerPatterns.Count -gt 0 -or
    $stage5B4C1C1MissingProductPatterns.Count -gt 0 -or
    $stage5B4C1C1MissingFixturePatterns.Count -gt 0 -or
    $stage5B4C1C1MissingProbePatterns.Count -gt 0 -or
    $stage5B4C1C1MissingScenarioPatterns.Count -gt 0) {
    throw "Stage 5B-4C1C1 modern picker, owner, cancel/select, StorageItems, import, or restart contracts are incomplete. See '$summaryPath'."
}

if ($stage5B4C1C1MissingSmokeScriptPatterns.Count -gt 0) {
    throw "Stage 5B-4C1C1 real picker UI Automation, isolation, natural-exit, fingerprint, or cleanup gates are missing. See '$summaryPath'."
}

if ($stage5B4C1C1ForbiddenScopePatterns.Count -gt 0) {
    throw "Stage 5B-4C1C1 entered deferred OLE/native drop, IFileOperation, global clipboard mutation, or new Rust ABI scope. See '$summaryPath'."
}

if (-not $stage5B4C1C1RustAbiUnchanged) {
    throw "Stage 5B-4C1C1 changed the frozen Rust ABI 2 / capability 511 / ten-export surface. See '$summaryPath'."
}

if ($stage5B4C1C1JsonSerializeCallCount -ne 1) {
    throw "Stage 5B-4C1C1 evidence must reuse the single source-generated JSON call. See '$summaryPath'."
}

if ($stage5B4C1C1SourceWarningMessages.Count -gt 0) {
    throw "Stage 5B-4C1C1 picker/StorageItems sources produced AOT warnings. See '$summaryPath'."
}

if ($stage5B4C1C1ActualWmc1510Count -ne $stage5B4C1C1ExpectedWmc1510Count) {
    throw "Stage 5B-4C1C1 WMC1510 count changed: expected=$stage5B4C1C1ExpectedWmc1510Count actual=$stage5B4C1C1ActualWmc1510Count. See '$summaryPath'."
}

if ($stage5B4C1C2AMissingRunnerPatterns.Count -gt 0 -or
    $stage5B4C1C2AMissingProductPatterns.Count -gt 0 -or
    $stage5B4C1C2AMissingFixturePatterns.Count -gt 0 -or
    $stage5B4C1C2AMissingProbePatterns.Count -gt 0 -or
    $stage5B4C1C2AMissingScenarioPatterns.Count -gt 0 -or
    $stage5B4C1C2AMissingVisualPatterns.Count -gt 0) {
    throw "Stage 5B-4C1C2A native OLE callback, stale-highlight, copy/move, progress, or visual contracts are incomplete. See '$summaryPath'."
}

if ($stage5B4C1C2AMissingSmokeScriptPatterns.Count -gt 0) {
    throw "Stage 5B-4C1C2A three-process runner, large-file, hash, isolation, natural-exit, or cleanup gates are missing. See '$summaryPath'."
}

if ($stage5B4C1C2AForbiddenScopePatterns.Count -gt 0) {
    throw "Stage 5B-4C1C2A entered global clipboard, synthetic mouse, Explorer automation, or new Rust ABI scope. See '$summaryPath'."
}

if (-not $stage5B4C1C2ARustAbiUnchanged) {
    throw "Stage 5B-4C1C2A changed the frozen Rust ABI 2 / capability 511 / ten-export surface. See '$summaryPath'."
}

if ($stage5B4C1C2AJsonSerializeCallCount -ne 1) {
    throw "Stage 5B-4C1C2A evidence must reuse the single source-generated JSON call. See '$summaryPath'."
}

if ($stage5B4C1C2ASourceWarningMessages.Count -gt 0) {
    throw "Stage 5B-4C1C2A native-drop sources produced AOT warnings. See '$summaryPath'."
}

if ($stage5B4C1C2AActualWmc1510Count -ne $stage5B4C1C2AExpectedWmc1510Count) {
    throw "Stage 5B-4C1C2A WMC1510 count changed: expected=$stage5B4C1C2AExpectedWmc1510Count actual=$stage5B4C1C2AActualWmc1510Count. See '$summaryPath'."
}

if ($stage5B4C2AMissingScenarioPatterns.Count -gt 0 -or
    $stage5B4C2AMissingHelperPatterns.Count -gt 0 -or
    $stage5B4C2AMissingProductPatterns.Count -gt 0) {
    throw "Stage 5B-4C2A registration, dispatch, rollback, or reserved-hook lifecycle contracts are incomplete. See '$summaryPath'."
}

if ($stage5B4C2AMissingSmokeScriptPatterns.Count -gt 0) {
    throw "Stage 5B-4C2A two-process, isolation, fingerprint, natural-exit, archive, or cleanup gates are missing. See '$summaryPath'."
}

if ($stage5B4C2AForbiddenScopePatterns.Count -gt 0) {
    throw "Stage 5B-4C2A claimed physical input evidence or entered new Rust ABI scope. See '$summaryPath'."
}

if (-not $stage5B4C2ARustAbiUnchanged) {
    throw "Stage 5B-4C2A changed the frozen Rust ABI 2 / capability 511 / ten-export surface. See '$summaryPath'."
}

if ($stage5B4C2AJsonSerializeCallCount -ne 1) {
    throw "Stage 5B-4C2A evidence must use one source-generated JSON call. See '$summaryPath'."
}

if ($stage5B4C2ASourceWarningMessages.Count -gt 0) {
    throw "Stage 5B-4C2A hotkey sources produced AOT warnings. See '$summaryPath'."
}

if ($stage5B4C2AActualWmc1510Count -ne $stage5B4C2AExpectedWmc1510Count) {
    throw "Stage 5B-4C2A WMC1510 count changed: expected=$stage5B4C2AExpectedWmc1510Count actual=$stage5B4C2AActualWmc1510Count. See '$summaryPath'."
}

if ($stage5B4C3AMissingScenarioPatterns.Count -gt 0 -or
    $stage5B4C3AMissingProductPatterns.Count -gt 0) {
    throw "Stage 5B-4C3A deterministic candidate, snooze, recurrence, restore, or cleanup contracts are incomplete. See '$summaryPath'."
}

if ($stage5B4C3AMissingSmokeScriptPatterns.Count -gt 0) {
    throw "Stage 5B-4C3A five-process, isolation, continuity, natural-exit, archive, or cleanup gates are missing. See '$summaryPath'."
}

if ($stage5B4C3AForbiddenScopePatterns.Count -gt 0) {
    throw "Stage 5B-4C3A entered real system notification or new Rust ABI scope. See '$summaryPath'."
}

if (-not $stage5B4C3ARustAbiUnchanged) {
    throw "Stage 5B-4C3A changed the frozen Rust ABI 2 / capability 511 / ten-export surface. See '$summaryPath'."
}

if ($stage5B4C3AJsonSerializeCallCount -ne 1) {
    throw "Stage 5B-4C3A evidence must use one source-generated JSON call. See '$summaryPath'."
}

if ($stage5B4C3ASourceWarningMessages.Count -gt 0) {
    throw "Stage 5B-4C3A Todo recurrence/reminder sources produced AOT warnings. See '$summaryPath'."
}

if ($stage5B4C3AActualWmc1510Count -ne $stage5B4C3AExpectedWmc1510Count) {
    throw "Stage 5B-4C3A WMC1510 count changed: expected=$stage5B4C3AExpectedWmc1510Count actual=$stage5B4C3AActualWmc1510Count. See '$summaryPath'."
}

if ($stage5B4C3B1MissingScenarioPatterns.Count -gt 0 -or
    $stage5B4C3B1MissingProductPatterns.Count -gt 0) {
    throw "Stage 5B-4C3B1 notification registration, payload, display, history, or exact cleanup contracts are incomplete. See '$summaryPath'."
}

if ($stage5B4C3B1MissingSmokeScriptPatterns.Count -gt 0) {
    throw "Stage 5B-4C3B1 three-process, real-display, isolation, natural-exit, archive, or cleanup gates are missing. See '$summaryPath'."
}

if ($stage5B4C3B1ForbiddenScopePatterns.Count -gt 0) {
    throw "Stage 5B-4C3B1 entered activation, broad notification deletion, or new Rust ABI scope. See '$summaryPath'."
}

if (-not $stage5B4C3B1RustAbiUnchanged) {
    throw "Stage 5B-4C3B1 changed the frozen Rust ABI 2 / capability 511 / ten-export surface. See '$summaryPath'."
}

if ($stage5B4C3B1JsonSerializeCallCount -ne 1) {
    throw "Stage 5B-4C3B1 evidence must use one source-generated JSON call. See '$summaryPath'."
}

if ($stage5B4C3B1SourceWarningMessages.Count -gt 0) {
    throw "Stage 5B-4C3B1 Todo notification sources produced AOT warnings. See '$summaryPath'."
}

if ($stage5B4C3B1ActualWmc1510Count -ne $stage5B4C3B1ExpectedWmc1510Count) {
    throw "Stage 5B-4C3B1 WMC1510 count changed: expected=$stage5B4C3B1ExpectedWmc1510Count actual=$stage5B4C3B1ActualWmc1510Count. See '$summaryPath'."
}

if ($stage5B4C3B2AMissingScenarioPatterns.Count -gt 0 -or
    $stage5B4C3B2AMissingProductPatterns.Count -gt 0) {
    throw "Stage 5B-4C3B2A activation grammar, routing, mutation, rejection, or persistence contracts are incomplete. See '$summaryPath'."
}

if ($stage5B4C3B2AMissingSmokeScriptPatterns.Count -gt 0) {
    throw "Stage 5B-4C3B2A three-process, isolation, continuity, natural-exit, archive, or cleanup gates are missing. See '$summaryPath'."
}

if ($stage5B4C3B2AForbiddenScopePatterns.Count -gt 0) {
    throw "Stage 5B-4C3B2A entered external notification activation, broad notification deletion, or new Rust ABI scope. See '$summaryPath'."
}

if (-not $stage5B4C3B2ARustAbiUnchanged) {
    throw "Stage 5B-4C3B2A changed the frozen Rust ABI 2 / capability 511 / ten-export surface. See '$summaryPath'."
}

if ($stage5B4C3B2AJsonSerializeCallCount -ne 1) {
    throw "Stage 5B-4C3B2A evidence must use one source-generated JSON call. See '$summaryPath'."
}

if ($stage5B4C3B2ASourceWarningMessages.Count -gt 0) {
    throw "Stage 5B-4C3B2A Todo activation sources produced AOT warnings. See '$summaryPath'."
}

if ($stage5B4C3B2AActualWmc1510Count -ne $stage5B4C3B2AExpectedWmc1510Count) {
    throw "Stage 5B-4C3B2A WMC1510 count changed: expected=$stage5B4C3B2AExpectedWmc1510Count actual=$stage5B4C3B2AActualWmc1510Count. See '$summaryPath'."
}

if ($stage5B4C3B2B1MissingScenarioPatterns.Count -gt 0 -or
    $stage5B4C3B2B1MissingProductPatterns.Count -gt 0) {
    throw "Stage 5B-4C3B2B1 typed envelope, startup drain, UserInput, or single-instance contracts are incomplete. See '$summaryPath'."
}

if ($stage5B4C3B2B1MissingSmokeScriptPatterns.Count -gt 0) {
    throw "Stage 5B-4C3B2B1 five-process, isolation, natural-exit, archive, or cleanup gates are missing. See '$summaryPath'."
}

if ($stage5B4C3B2B1ForbiddenScopePatterns.Count -gt 0) {
    throw "Stage 5B-4C3B2B1 entered real Windows notification display/activation, broad deletion, legacy argument-only forwarding, or new Rust ABI scope. See '$summaryPath'."
}

if (-not $stage5B4C3B2B1RustAbiUnchanged) {
    throw "Stage 5B-4C3B2B1 changed the frozen Rust ABI 2 / capability 511 / ten-export surface. See '$summaryPath'."
}

if ($stage5B4C3B2B1ScenarioJsonSerializeCallCount -ne 1 -or
    $stage5B4C3B2B1StoreJsonCallCount -ne 2) {
    throw "Stage 5B-4C3B2B1 must retain one fixture JSON call and two source-generated envelope-store JSON calls. See '$summaryPath'."
}

if ($stage5B4C3B2B1SourceWarningMessages.Count -gt 0) {
    throw "Stage 5B-4C3B2B1 forwarding sources produced AOT warnings. See '$summaryPath'."
}

if ($stage5B4C3B2B1ActualWmc1510Count -ne $stage5B4C3B2B1ExpectedWmc1510Count) {
    throw "Stage 5B-4C3B2B1 WMC1510 count changed: expected=$stage5B4C3B2B1ExpectedWmc1510Count actual=$stage5B4C3B2B1ActualWmc1510Count. See '$summaryPath'."
}

if ($stage5B4C3B2B2AMissingScenarioPatterns.Count -gt 0 -or
    $stage5B4C3B2B2AMissingProductPatterns.Count -gt 0) {
    throw "Stage 5B-4C3B2B2A Todo target, content-ready, or visible-refresh contracts are incomplete. See '$summaryPath'."
}

if ($stage5B4C3B2B2AMissingSmokeScriptPatterns.Count -gt 0) {
    throw "Stage 5B-4C3B2B2A isolated surface, natural-exit, archive, or cleanup gates are missing. See '$summaryPath'."
}

if ($stage5B4C3B2B2AForbiddenScopePatterns.Count -gt 0) {
    throw "Stage 5B-4C3B2B2A mislabeled controlled input as a real Windows click, entered broad notification deletion, or expanded Rust scope. See '$summaryPath'."
}

if (-not $stage5B4C3B2B2ARustAbiUnchanged) {
    throw "Stage 5B-4C3B2B2A changed the frozen Rust ABI 2 / capability 511 / ten-export surface. See '$summaryPath'."
}

if ($stage5B4C3B2B2AScenarioJsonSerializeCallCount -ne 0 -or
    $stage5B4C3B2B2AManagedUiJsonSerializeCallCount -ne 1) {
    throw "Stage 5B-4C3B2B2A must reuse the one source-generated managed UI evidence serializer without adding JSON calls. See '$summaryPath'."
}

if ($stage5B4C3B2B2ASourceWarningMessages.Count -gt 0) {
    throw "Stage 5B-4C3B2B2A Todo surface sources produced AOT warnings. See '$summaryPath'."
}

if ($stage5B4C3B2B2AActualWmc1510Count -ne $stage5B4C3B2B2AExpectedWmc1510Count) {
    throw "Stage 5B-4C3B2B2A WMC1510 count changed: expected=$stage5B4C3B2B2AExpectedWmc1510Count actual=$stage5B4C3B2B2AActualWmc1510Count. See '$summaryPath'."
}

if ($stage5B4C3B2B2BMissingScenarioPatterns.Count -gt 0 -or
    $stage5B4C3B2B2BMissingProductPatterns.Count -gt 0) {
    throw "Stage 5B-4C3B2B2B Windows activation provenance, real click, Todo route, or visible-surface contracts are incomplete. See '$summaryPath'."
}

if ($stage5B4C3B2B2BMissingSmokeScriptPatterns.Count -gt 0) {
    throw "Stage 5B-4C3B2B2B interactive running/cold-start, isolation, provenance, natural-exit, archive, or cleanup gates are missing. See '$summaryPath'."
}

if ($stage5B4C3B2B2BForbiddenScopePatterns.Count -gt 0) {
    throw "Stage 5B-4C3B2B2B used synthetic input/UI Automation, direct fixture notification APIs, broad notification deletion, or expanded Rust scope. See '$summaryPath'."
}

if (-not $stage5B4C3B2B2BRustAbiUnchanged) {
    throw "Stage 5B-4C3B2B2B changed the frozen Rust ABI 2 / capability 511 / ten-export surface. See '$summaryPath'."
}

if ($stage5B4C3B2B2BScenarioJsonSerializeCallCount -ne 0 -or
    $stage5B4C3B2B2BManagedUiJsonSerializeCallCount -ne 1) {
    throw "Stage 5B-4C3B2B2B must reuse the one source-generated managed UI evidence serializer without adding JSON calls. See '$summaryPath'."
}

if ($stage5B4C3B2B2BSourceWarningMessages.Count -gt 0) {
    throw "Stage 5B-4C3B2B2B notification-click sources produced AOT warnings. See '$summaryPath'."
}

if ($stage5B4C3B2B2BActualWmc1510Count -ne $stage5B4C3B2B2BExpectedWmc1510Count) {
    throw "Stage 5B-4C3B2B2B WMC1510 count changed: expected=$stage5B4C3B2B2BExpectedWmc1510Count actual=$stage5B4C3B2B2BActualWmc1510Count. See '$summaryPath'."
}

if ($unexpectedWarningCodes.Count -gt 0) {
    throw "The Stage 5B-4C3B2B2B AOT warning set expanded: $($unexpectedWarningCodes -join ', '). See '$summaryPath'."
}

if ($shortcutAlwaysThrowMessages.Count -gt 0) {
    throw "Legacy shortcut COM constructors remain reachable in Native AOT. See '$summaryPath'."
}

if ($musicVolumeAlwaysThrowMessages.Count -gt 0) {
    throw "Legacy music-volume COM constructors remain reachable in Native AOT. See '$summaryPath'."
}

if ($explorerShellAlwaysThrowMessages.Count -gt 0) {
    throw "Legacy Explorer-shell dynamic COM remains reachable in Native AOT. See '$summaryPath'."
}

if ($quickAccessAlwaysThrowMessages.Count -gt 0) {
    throw "Legacy Quick Access dynamic COM remains reachable in Native AOT. See '$summaryPath'."
}

if ($missingExpectedAlwaysThrowTypes.Count -gt 0 -or
    $unexpectedAlwaysThrowMessages.Count -gt 0) {
    throw "The Stage 5B-4A remaining always-throw contract changed. See '$summaryPath'."
}

if ($RequireCleanAnalysis.IsPresent -and
    ($warningCodes.Count -gt 0 -or $alwaysThrowMessages.Count -gt 0)) {
    throw "AOT publish passed structural validation, but analysis is not clean. See '$summaryPath'."
}

[PSCustomObject]@{
    PublishDirectory = $publishDir
    SymbolsDirectory = $symbolsDir
    Summary = $summaryPath
    RuntimeIdentifier = $runtimeIdentifier
    PublishFiles = $publishedFiles.Count
    PublishMiB = [Math]::Round($summary.publishBytes / 1MB, 1)
    SymbolFiles = $symbolFiles.Count
    SymbolMiB = [Math]::Round($summary.symbolBytes / 1MB, 1)
    WarningCodes = $warningCodes -join ", "
    AlwaysThrowCount = $alwaysThrowMessages.Count
    RustAbiVersion = $rustAbiVersion
    RustCapabilities = $rustCapabilities
    RustRequiredExports = $rustRequiredExports -join ", "
}

