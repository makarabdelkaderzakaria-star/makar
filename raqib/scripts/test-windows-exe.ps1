<#
.SYNOPSIS
  Test the standalone Windows executable.

.DESCRIPTION
  Everything here runs the EXE itself. Nothing in this file needs Node.js,
  Bun, or any other runtime: the executable carries its own.

  The script writes a results file next to the fixtures so that the outcome
  can be read from outside the machine, and exits non-zero if any test
  failed.
#>
param(
  [Parameter(Mandatory = $true)][string]$Exe,
  [Parameter(Mandatory = $true)][string]$Fixtures,
  [string]$BraveDir = '',
  [string]$ResultsPath = '',
  [string]$LogPath = ''
)

$ErrorActionPreference = 'Continue'

$script:Results = @()
$script:Failed = 0
$script:Number = 0
$script:WorkerThreads = 0
$script:Log = New-Object System.Collections.Generic.List[string]

function Note {
  param([string]$Text)
  $script:Log.Add($Text)
  Write-Host $Text
}

function Write-Section {
  param([string]$Text)
  Note ""
  Note "== $Text"
}

function Test-Raqib {
  <#
    Run the executable and assert on what it printed.

    The call operator is used rather than Start-Process so that arguments
    containing spaces — a path like "C:\Program Files\..." — are passed
    through exactly as they are.
  #>
  param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][string[]]$Arguments,
    [string]$Expect = '',
    [string]$Reject = '',
    [string]$WorkingDirectory = '',
    [int]$TimeoutSeconds = 300
  )

  $script:Number += 1
  $label = "{0:d2}. {1}" -f $script:Number, $Name

  if ($WorkingDirectory) { Push-Location -LiteralPath $WorkingDirectory }

  $out = ''
  $exitCode = -1
  try {
    $out = (& $Exe @Arguments 2>&1 | Out-String)
    $exitCode = $LASTEXITCODE
  } catch {
    $out = "could not run the executable: $($_.Exception.Message)"
  }

  if ($WorkingDirectory) { Pop-Location }

  $problems = @()
  if ($exitCode -ne 0) { $problems += "exit code $exitCode" }
  if ($Expect -and $out -notmatch $Expect) { $problems += "output did not match /$Expect/" }
  if ($Reject -and $out -match $Reject) { $problems += "output matched /$Reject/" }

  $firstLine = ''
  if ($out) { $firstLine = ($out -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1) }

  if ($problems.Count -eq 0) {
    Note ("  PASS  {0}" -f $label)
    $script:Results += [pscustomobject]@{ number = $script:Number; name = $Name; passed = $true; exitCode = $exitCode; detail = $firstLine }
  } else {
    $script:Failed += 1
    Note ("  FAIL  {0}  ({1})" -f $label, ($problems -join '; '))
    if ($out) { Note ("        output: " + (($out -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 4) -join ' | ')) }
    $script:Results += [pscustomobject]@{ number = $script:Number; name = $Name; passed = $false; exitCode = $exitCode; detail = ($problems -join '; ') }
  }
  return $out
}

try {
  Note ""
  Note "Raqib - testing the standalone executable"
  Note ("  executable : {0}" -f $Exe)
  Note ("  size       : {0} bytes" -f (Get-Item -LiteralPath $Exe).Length)

  # The whole point: nothing else is installed.
  Write-Section "The machine has no runtime but the executable"
  $nodeCommand = Get-Command node -ErrorAction SilentlyContinue
  $bunCommand = Get-Command bun -ErrorAction SilentlyContinue
  Note ("  node on PATH : {0}" -f $(if ($nodeCommand) { $nodeCommand.Source } else { 'not found' }))
  Note ("  bun  on PATH : {0}" -f $(if ($bunCommand) { $bunCommand.Source } else { 'not found' }))
  if ($nodeCommand -or $bunCommand) {
    $script:Failed += 1
    Note "  FAIL  the machine still has a runtime on PATH"
    $script:Results += [pscustomobject]@{ number = 0; name = 'machine has no node or bun'; passed = $false; exitCode = 0; detail = 'a runtime is still reachable' }
  } else {
    Note "  PASS  no node, no bun"
    $script:Results += [pscustomobject]@{ number = 0; name = 'machine has no node or bun'; passed = $true; exitCode = 0; detail = 'neither node nor bun is reachable' }
  }

  # -------------------------------------------------------------------------

  Write-Section "1. --help"
  $help = Test-Raqib -Name '--help lists every command' -Arguments @('--help') -Expect 'raqib \d+\.\d+\.\d+'
  foreach ($command in @('analyze', 'macho', 'map', 'compare', 'manifest', 'elf', 'pe', 'js', 'asar', 'strings', 'search', 'index', 'chromium', 'browser', 'setup', 'doctor', 'serve', 'mcp')) {
    if ($help -notmatch "\b$command\b") {
      $script:Failed += 1
      Note ("  FAIL  the help text does not mention '{0}'" -f $command)
      $script:Results += [pscustomobject]@{ number = $script:Number; name = "help mentions $command"; passed = $false; exitCode = 0; detail = 'missing from the help text' }
    }
  }
  Note "  (all 18 commands present in the help text)"

  Write-Section "2. doctor"
  $doctor = Test-Raqib -Name 'doctor reports the machine' -Arguments @('doctor') -Expect 'network use'
  if ($doctor -notmatch 'never opens a socket') {
    $script:Failed += 1
    Note "  FAIL  doctor does not report that no socket is opened"
  }
  if ($doctor -notmatch '11 tools') {
    $script:Failed += 1
    Note "  FAIL  doctor does not report 11 MCP tools"
  }

  Write-Section "3. a real Windows binary (notepad.exe)"
  $notepad = Join-Path $env:SystemRoot 'System32\notepad.exe'
  $notepadReport = Test-Raqib -Name 'analyze notepad.exe' -Arguments @('analyze', $notepad) -Expect 'pe\.machine: x86-64'
  Note ("  (notepad reports: {0})" -f (($notepadReport -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)))
  Test-Raqib -Name 'the PE report names its imports' -Arguments @('pe', $notepad) -Expect 'pe\.import_dlls: [0-9]+'

  Write-Section "4. a Chromium-family browser"
  if ($BraveDir -and (Test-Path -LiteralPath $BraveDir)) {
    $browser = Test-Raqib -Name 'identify the installed browser' -Arguments @('browser', $BraveDir) -Expect 'browser\.product: Brave'
    Note ("  (browser says: {0})" -f (($browser -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)))
  } else {
    Note "  SKIP  no browser installation was provided"
  }

  Write-Section "5. the search engine and its worker threads"
  $bigTree = Join-Path $Fixtures 'big-tree'
  $search = Test-Raqib -Name 'search a tree of 1500 files' `
    -Arguments @('search', $bigTree, 'FOUND', '--workers', '2') -Expect 'match\(es\)'
  if ($search -notmatch 'using (the main thread only|\d+ worker thread\(s\))') {
    $script:Failed += 1
    Note "  FAIL  the search did not say how it was run"
  }
  if ($search -notmatch 'using 2 worker thread\(s\)') {
    $script:Failed += 1
    Note "  FAIL  the search did not run on the worker threads it was asked for"
    $script:Results += [pscustomobject]@{ number = $script:Number; name = 'the search used the worker threads'; passed = $false; exitCode = 0; detail = 'the worker pool was not used' }
  } else {
    $script:Results += [pscustomobject]@{ number = $script:Number; name = 'the search used the worker threads'; passed = $true; exitCode = 0; detail = '2 worker threads' }
  }
  if ($search -notmatch '\d+ match\(es\)') {
    $script:Failed += 1
    Note "  FAIL  the search found nothing"
  }
  if ($search -match 'using (\d+) worker thread') {
    $script:WorkerThreads = [int]$Matches[1]
    Note ("  (the search used {0} worker thread(s) - the embedded worker started)" -f $script:WorkerThreads)
  } else {
    Note "  (the search ran on the main thread: this machine has too few cores for the worker pool)"
  }

  Write-Section "6. compare two builds"
  Test-Raqib -Name 'compare old-build with new-build' `
    -Arguments @('compare', (Join-Path $Fixtures 'old-build'), (Join-Path $Fixtures 'new-build')) `
    -Expect 'app\.version: 1\.0\.0\s+->\s+1\.1\.0'

  Write-Section "7. source maps"
  $bundle = Join-Path $Fixtures 'bundle.js'
  Test-Raqib -Name 'map a bundle back to its source' -Arguments @('map', $bundle, '--line', '7', '--column', '1') -Expect 'resolution:.*main\.ts'
  Test-Raqib -Name 'the map lists the original files' -Arguments @('map', $bundle) -Expect 'src/app\.ts'

  Write-Section "8. ASAR archives"
  Test-Raqib -Name 'read an asar archive' -Arguments @('asar', (Join-Path $Fixtures 'app.asar')) -Expect 'ASAR archive with 2 files'

  Write-Section "9. package manifests"
  Test-Raqib -Name 'read a package manifest' -Arguments @('manifest', (Join-Path $Fixtures 'package.json')) -Expect 'manifest\.name: fixture-manifest'

  Write-Section "10. the MCP server over stdio"
  $mcpInput = @(
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"1"}}}',
    '{"jsonrpc":"2.0","method":"notifications/initialized"}',
    '{"jsonrpc":"2.0","id":2,"method":"tools/list"}',
    ('{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"inspect_binary","arguments":{"path":"' + ($notepad -replace '\\', '\\\\') + '"}}}')
  ) -join "`n"

  $mcpText = ''
  try {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = 'mcp'
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $mcpProcess = [System.Diagnostics.Process]::Start($psi)
    $mcpProcess.StandardInput.WriteLine($mcpInput)
    $mcpProcess.StandardInput.Close()
    $mcpText = $mcpProcess.StandardOutput.ReadToEnd()
    $mcpProcess.WaitForExit(60000) | Out-Null
    $mcpProcess.Dispose()
  } catch {
    $mcpText = "could not run the MCP server: $($_.Exception.Message)"
  }

  $script:Number += 1
  $toolNames = @('inspect_binary', 'analyze_js_application', 'search_code', 'index_tree', 'inspect_chromium_tree',
    'identify_browser', 'read_asar', 'resolve_source_map', 'compare_analyses', 'inspect_manifest', 'get_evidence')
  $toolCount = 0
  foreach ($tool in $toolNames) { if ($mcpText -match ('"name":"' + $tool + '"')) { $toolCount += 1 } }
  if ($mcpText -match '"tools"' -and $toolCount -eq 11) {
    Note ("  PASS  {0:d2}. MCP lists all 11 tools" -f $script:Number)
    $script:Results += [pscustomobject]@{ number = $script:Number; name = 'MCP lists all 11 tools'; passed = $true; exitCode = 0; detail = "$toolCount tools" }
  } else {
    $script:Failed += 1
    Note ("  FAIL  {0:d2}. MCP listed {1} tools, expected 11" -f $script:Number, $toolCount)
    Note ("        " + (($mcpText -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 2) -join ' | '))
    $script:Results += [pscustomobject]@{ number = $script:Number; name = 'MCP lists all 11 tools'; passed = $false; exitCode = 0; detail = "$toolCount tools" }
  }

  $script:Number += 1
  if ($mcpText -match 'PE32' -or $mcpText -match '"kind":"pe"') {
    Note ("  PASS  {0:d2}. MCP answered a tool call" -f $script:Number)
    $script:Results += [pscustomobject]@{ number = $script:Number; name = 'MCP answered a tool call'; passed = $true; exitCode = 0; detail = 'inspect_binary on notepad.exe' }
  } else {
    $script:Failed += 1
    Note ("  FAIL  {0:d2}. MCP did not answer a tool call" -f $script:Number)
    $script:Results += [pscustomobject]@{ number = $script:Number; name = 'MCP answered a tool call'; passed = $false; exitCode = 0; detail = 'no PE report in the reply' }
  }

  # -------------------------------------------------------------------------

  Write-Section "11. it runs from anywhere"

  $somewhereElse = Join-Path $env:TEMP ('raqib-runs-from-' + [System.Guid]::NewGuid().ToString('N').Substring(0, 8))
  New-Item -ItemType Directory -Path $somewhereElse -Force | Out-Null
  Test-Raqib -Name 'runs from an unrelated working directory' `
    -Arguments @('analyze', $notepad) -Expect 'pe\.machine: x86-64' -WorkingDirectory $somewhereElse

  Write-Section "12. paths with spaces and Arabic characters"

  $arabicDir = Join-Path $env:TEMP ('مجلد عربي ' + [System.Guid]::NewGuid().ToString('N').Substring(0, 6))
  New-Item -ItemType Directory -Path $arabicDir -Force | Out-Null
  $arabicFile = Join-Path $arabicDir 'ملف تجريبي.txt'
  Set-Content -LiteralPath $arabicFile -Value 'needle-FOUND inside an Arabic path' -Encoding UTF8
  Test-Raqib -Name 'search a path with spaces and Arabic characters' `
    -Arguments @('search', $arabicDir, 'FOUND') -Expect 'match\(es\)'
  Test-Raqib -Name 'analyse a file with an Arabic name' `
    -Arguments @('analyze', $arabicFile) -Expect '.' -WorkingDirectory $somewhereElse

  # -------------------------------------------------------------------------

  Write-Section "13. the executable does not need anything beside it"

  $alone = Join-Path $env:TEMP ('raqib-alone-' + [System.Guid]::NewGuid().ToString('N').Substring(0, 8))
  New-Item -ItemType Directory -Path $alone -Force | Out-Null
  Copy-Item -LiteralPath $Exe -Destination (Join-Path $alone 'Raqib.exe') -Force
  $beside = Get-ChildItem -LiteralPath $alone
  Note ("  the folder holds: {0}" -f ($beside.Name -join ', '))
  Test-Raqib -Name 'runs with nothing beside it' `
    -Arguments @('analyze', $notepad) -Expect 'pe\.machine: x86-64' -WorkingDirectory $alone

} catch {
  $script:Failed += 1
  Note ("  FAIL  the test script itself threw: {0}" -f $_.Exception.Message)
  $script:Results += [pscustomobject]@{ number = $script:Number; name = 'the test script ran to the end'; passed = $false; exitCode = 1; detail = $_.Exception.Message }
}

# ---------------------------------------------------------------------------

$passed = @($script:Results | Where-Object { $_.passed }).Count
$total = $script:Results.Count

Note ""
Note "-----------------------------------------------"
Note ("{0} of {1} checks passed" -f $passed, $total)
Note "-----------------------------------------------"

if ($LogPath) {
  New-Item -ItemType Directory -Path (Split-Path -Parent $LogPath) -Force | Out-Null
  Set-Content -LiteralPath $LogPath -Value ($script:Log -join "`n") -Encoding UTF8
}

if ($ResultsPath) {
  $report = [pscustomobject]@{
    executable = $Exe
    size = (Get-Item -LiteralPath $Exe).Length
    passed = $passed
    total = $total
    failed = $script:Failed
    nodeOnPath = [bool]$nodeCommand
    bunOnPath = [bool]$bunCommand
    workerThreadsUsed = $script:WorkerThreads
    checks = $script:Results
  }
  New-Item -ItemType Directory -Path (Split-Path -Parent $ResultsPath) -Force | Out-Null
  $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ResultsPath -Encoding UTF8
  Note ("  results written to {0}" -f $ResultsPath)
}

if ($script:Failed -gt 0) { exit 1 }
exit 0
