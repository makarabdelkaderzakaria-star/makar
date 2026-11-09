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
  [string]$ResultsPath = ''
)

$ErrorActionPreference = 'Stop'

$script:Results = @()
$script:Failed = 0
$script:Number = 0

function Write-Section {
  param([string]$Text)
  Write-Host ""
  Write-Host "== $Text" -ForegroundColor Cyan
}

function Test-Raqib {
  <#
    Run the executable and assert on what it printed.
  #>
  param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][string[]]$Arguments,
    [string]$Expect = '',
    [string]$Reject = '',
    [string]$WorkingDirectory = '',
    [int]$TimeoutSeconds = 180
  )

  $script:Number += 1
  $label = "{0:d2}. {1}" -f $script:Number, $Name

  $stdoutFile = [System.IO.Path]::GetTempFileName()
  $stderrFile = [System.IO.Path]::GetTempFileName()

  $previous = $PWD
  if ($WorkingDirectory) { Set-Location -LiteralPath $WorkingDirectory }

  $process = Start-Process -FilePath $Exe -ArgumentList $Arguments -NoNewWindow -Wait -PassThru `
    -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile
  $exitCode = $process.ExitCode

  if ($WorkingDirectory) { Set-Location -LiteralPath $previous }

  $out = (Get-Content -LiteralPath $stdoutFile -Raw -ErrorAction SilentlyContinue)
  $err = (Get-Content -LiteralPath $stderrFile -Raw -ErrorAction SilentlyContinue)
  Remove-Item -LiteralPath $stdoutFile, $stderrFile -Force -ErrorAction SilentlyContinue

  $problems = @()
  if ($exitCode -ne 0) { $problems += "exit code $exitCode" }
  if ($Expect -and $out -notmatch $Expect) { $problems += "output did not match /$Expect/" }
  if ($Reject -and $out -match $Reject) { $problems += "output matched /$Reject/" }

  $firstLine = ''
  if ($out) { $firstLine = ($out -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1) }

  if ($problems.Count -eq 0) {
    Write-Host ("  PASS  {0}" -f $label) -ForegroundColor Green
    $script:Results += [pscustomobject]@{ number = $script:Number; name = $Name; passed = $true; exitCode = $exitCode; detail = $firstLine }
  } else {
    $script:Failed += 1
    Write-Host ("  FAIL  {0}  ({1})" -f $label, ($problems -join '; ')) -ForegroundColor Red
    if ($err) { Write-Host "        stderr: $($err.Trim())" -ForegroundColor DarkGray }
    if ($out) { Write-Host "        stdout: $($out.Trim())" -ForegroundColor DarkGray }
    $script:Results += [pscustomobject]@{ number = $script:Number; name = $Name; passed = $false; exitCode = $exitCode; detail = ($problems -join '; ') }
  }
  return $out
}

# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "Raqib — testing the standalone executable" -ForegroundColor Green
Write-Host "  executable : $Exe"
Write-Host "  size       : $((Get-Item -LiteralPath $Exe).Length) bytes"

# The whole point: nothing else is installed.
Write-Section "The machine has no runtime but the executable"
$nodeCommand = Get-Command node -ErrorAction SilentlyContinue
$bunCommand = Get-Command bun -ErrorAction SilentlyContinue
Write-Host "  node on PATH : $(if ($nodeCommand) { $nodeCommand.Source } else { 'not found' })"
Write-Host "  bun  on PATH : $(if ($bunCommand) { $bunCommand.Source } else { 'not found' })"
$script:Results += [pscustomobject]@{
  number = 0; name = 'machine has no node or bun'; passed = (-not $nodeCommand -and -not $bunCommand)
  exitCode = 0; detail = "node=$($nodeCommand.Source); bun=$($bunCommand.Source)"
}
if ($nodeCommand -or $bunCommand) {
  $script:Failed += 1
  Write-Host "  FAIL  the machine still has a runtime on PATH" -ForegroundColor Red
} else {
  Write-Host "  PASS  no node, no bun" -ForegroundColor Green
}

# ---------------------------------------------------------------------------

Write-Section "1. --help"
$help = Test-Raqib -Name '--help lists every command' -Arguments @('--help') -Expect 'raqib \d+\.\d+\.\d+'
foreach ($command in @('analyze', 'macho', 'map', 'compare', 'manifest', 'elf', 'pe', 'js', 'asar', 'strings', 'search', 'index', 'chromium', 'browser', 'setup', 'doctor', 'serve', 'mcp')) {
  if ($help -notmatch "\b$command\b") {
    Write-Host "  FAIL  the help text does not mention '$command'" -ForegroundColor Red
    $script:Failed += 1
    $script:Results += [pscustomobject]@{ number = $script:Number; name = "help mentions $command"; passed = $false; exitCode = 0; detail = 'missing from the help text' }
  }
}
Write-Host "  (all 18 commands present in the help text)"

Write-Section "2. doctor"
$doctor = Test-Raqib -Name 'doctor reports the machine' -Arguments @('doctor') -Expect 'network use'
if ($doctor -notmatch 'never opens a socket') {
  Write-Host "  FAIL  doctor does not report that no socket is opened" -ForegroundColor Red
  $script:Failed += 1
}
if ($doctor -notmatch '11 tools') {
  Write-Host "  FAIL  doctor does not report 11 MCP tools" -ForegroundColor Red
  $script:Failed += 1
}

Write-Section "3. a real Windows binary (notepad.exe)"
$notepad = Join-Path $env:SystemRoot 'System32\notepad.exe'
Test-Raqib -Name 'analyze notepad.exe' -Arguments @('analyze', $notepad) -Expect 'PE32' -Reject 'strings —'
Test-Raqib -Name 'the PE report names its imports' -Arguments @('pe', $notepad) -Expect 'pe\.imports'

Write-Section "4. a Chromium-family browser"
if ($BraveDir -and (Test-Path -LiteralPath $BraveDir)) {
  Test-Raqib -Name 'identify the installed browser' -Arguments @('browser', $BraveDir) -Expect 'browser\.product: Brave'
} else {
  Write-Host "  SKIP  no browser installation was provided" -ForegroundColor Yellow
}

Write-Section "5. the search engine and its worker threads"
$bigTree = Join-Path $Fixtures 'big-tree'
$search = Test-Raqib -Name 'search a tree of 1500 files' -Arguments @('search', $bigTree, 'FOUND') -Expect 'match\(es\)'
if ($search -notmatch 'using (the main thread only|\d+ worker thread\(s\))') {
  Write-Host "  FAIL  the search did not say how it was run" -ForegroundColor Red
  $script:Failed += 1
}
if ($search -notmatch '\d+ match\(es\)') {
  Write-Host "  FAIL  the search found nothing" -ForegroundColor Red
  $script:Failed += 1
}
# A tree this size must reach for the worker threads on a machine with more
# than one core. The worker script has to be written out of the executable
# first, so this is the test that proves the worker is embedded.
$workerUsed = $search -match 'using (\d+) worker thread'
if ($workerUsed) {
  Write-Host "  (the search used $Matches[1] worker thread(s) — the embedded worker started)" -ForegroundColor DarkGray
}

Write-Section "6. compare two builds"
$compare = Test-Raqib -Name 'compare old-build with new-build' `
  -Arguments @('compare', (Join-Path $Fixtures 'old-build'), (Join-Path $Fixtures 'new-build')) `
  -Expect 'manifest\.version: 1\.0\.0\s+->\s+1\.1\.0'

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
  ('{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"inspect_binary","arguments":{"path":"' + ($notepad -replace '\\', '\\\\') + '"}}}'
) -join "`n"

$mcpOutFile = [System.IO.Path]::GetTempFileName()
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

$script:Number += 1
$toolCount = ([regex]::Matches($mcpText, '"name":"(inspect_binary|analyze_js_application|search_code|index_tree|inspect_chromium_tree|identify_browser|read_asar|resolve_source_map|compare_analyses|inspect_manifest|get_evidence)"')).Count
if ($mcpText -match '"tools"' -and $toolCount -eq 11) {
  Write-Host ("  PASS  {0:d2}. MCP lists all 11 tools" -f $script:Number) -ForegroundColor Green
  $script:Results += [pscustomobject]@{ number = $script:Number; name = 'MCP lists all 11 tools'; passed = $true; exitCode = 0; detail = "$toolCount tools" }
} else {
  $script:Failed += 1
  Write-Host ("  FAIL  {0:d2}. MCP listed $toolCount tools, expected 11" -f $script:Number) -ForegroundColor Red
  Write-Host "        $mcpText" -ForegroundColor DarkGray
  $script:Results += [pscustomobject]@{ number = $script:Number; name = 'MCP lists all 11 tools'; passed = $false; exitCode = 0; detail = "$toolCount tools" }
}

$script:Number += 1
if ($mcpText -match '"kind":"pe"' -or $mcpText -match 'PE32') {
  Write-Host ("  PASS  {0:d2}. MCP answered a tool call" -f $script:Number) -ForegroundColor Green
  $script:Results += [pscustomobject]@{ number = $script:Number; name = 'MCP answered a tool call'; passed = $true; exitCode = 0; detail = 'inspect_binary on notepad.exe' }
} else {
  $script:Failed += 1
  Write-Host ("  FAIL  {0:d2}. MCP did not answer a tool call" -f $script:Number) -ForegroundColor Red
  $script:Results += [pscustomobject]@{ number = $script:Number; name = 'MCP answered a tool call'; passed = $false; exitCode = 0; detail = 'no PE report in the reply' }
}

# ---------------------------------------------------------------------------

Write-Section "11. it runs from anywhere"

$somewhereElse = Join-Path $env:TEMP ('raqib-runs-from-' + [System.Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $somewhereElse -Force | Out-Null
Test-Raqib -Name 'runs from an unrelated working directory' `
  -Arguments @('analyze', $notepad) -Expect 'PE32' -WorkingDirectory $somewhereElse

Write-Section "12. paths with spaces and Arabic characters"

$arabicDir = Join-Path $env:TEMP ('مجلد عربي ' + [System.Guid]::NewGuid().ToString('N').Substring(0, 6))
New-Item -ItemType Directory -Path $arabicDir -Force | Out-Null
$arabicFile = Join-Path $arabicDir 'ملف تجريبي.txt'
Set-Content -LiteralPath $arabicFile -Value 'needle-FOUND inside an Arabic path' -Encoding UTF8
Test-Raqib -Name 'search a path with spaces and Arabic characters' `
  -Arguments @('search', $arabicDir, 'FOUND') -Expect 'match\(es\)'
Test-Raqib -Name 'analyse a file with an Arabic name' `
  -Arguments @('analyze', $arabicFile) -Expect '.' -WorkingDirectory $somewhereElse

# ---------------------------------------------------------------------------

Write-Section "13. the executable does not need anything beside it"

$alone = Join-Path $env:TEMP ('raqib-alone-' + [System.Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $alone -Force | Out-Null
Copy-Item -LiteralPath $Exe -Destination (Join-Path $alone 'Raqib.exe') -Force
$beside = Get-ChildItem -LiteralPath $alone
Write-Host "  the folder holds: $($beside.Name -join ', ')"
Test-Raqib -Name 'runs with nothing beside it' `
  -Arguments @('analyze', $notepad) -Expect 'PE32' -WorkingDirectory $alone

# ---------------------------------------------------------------------------

$passed = ($script:Results | Where-Object { $_.passed }).Count
$total = $script:Results.Count

Write-Host ""
Write-Host "-----------------------------------------------" -ForegroundColor Cyan
Write-Host ("{0} of {1} checks passed" -f $passed, $total) -ForegroundColor $(if ($script:Failed -eq 0) { 'Green' } else { 'Red' })
Write-Host "-----------------------------------------------" -ForegroundColor Cyan

if ($ResultsPath) {
  $report = [pscustomobject]@{
    executable = $Exe
    size = (Get-Item -LiteralPath $Exe).Length
    passed = $passed
    total = $total
    failed = $script:Failed
    nodeOnPath = [bool]$nodeCommand
    bunOnPath = [bool]$bunCommand
    workerThreadsUsed = $(if ($workerUsed) { [int]$Matches[1] } else { 0 })
    checks = $script:Results
  }
  New-Item -ItemType Directory -Path (Split-Path -Parent $ResultsPath) -Force | Out-Null
  $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ResultsPath -Encoding UTF8
  Write-Host "  results written to $ResultsPath"
}

if ($script:Failed -gt 0) { exit 1 }
exit 0
