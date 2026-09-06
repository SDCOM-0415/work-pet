# WorkDaddy Windows 自动更新替换脚本。
# 独立于 daemon 运行：停止 watchdog、替换安装目录、启动新版并验证 API；失败时保留日志并回滚。
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$SrcZip,
  [string]$AppDir = '',
  [string]$Port = '47832',
  [string]$LogPath = '',
  [string]$AttemptId = 'unknown',
  [string]$Profile = 'workbuddy-cn'
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Profile) -or $Profile -eq '__WBS_DEFAULT_PROFILE__') { $Profile = 'workbuddy-cn' }
if ($Profile -ne 'workbuddy-ai') { $Profile = 'workbuddy-cn' }
$productName = if ($Profile -eq 'workbuddy-ai') { 'WorkDaddy AI' } else { 'WorkDaddy' }
if ([string]::IsNullOrWhiteSpace($AppDir)) { $AppDir = Join-Path $env:LOCALAPPDATA (Join-Path 'Programs' $productName) }
$dataRoot = Join-Path $env:APPDATA 'WorkDaddy'
$DataDir = if ($Profile -eq 'workbuddy-ai') { Join-Path $dataRoot 'profiles\workbuddy-ai' } else { $dataRoot }
$LogDir = Join-Path $DataDir 'update'
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
if ([string]::IsNullOrWhiteSpace($LogPath)) { $LogPath = Join-Path $LogDir 'apply.log' }
$transcriptStarted = $false
try {
  Start-Transcript -Path $LogPath -Append -Force | Out-Null
  $transcriptStarted = $true
} catch {
  # Transcript is diagnostic only; continue with Write-Host if the file cannot be opened.
}

function Write-ApplyLog {
  param([Parameter(Mandatory = $true)][string]$Message)
  Write-Host ("[apply] {0} {1}" -f (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK'), $Message)
}

function Stop-ApplyTranscript {
  if ($script:transcriptStarted) {
    try { Stop-Transcript | Out-Null } catch {}
    $script:transcriptStarted = $false
  }
}

function Test-ExclusiveFile {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { return $true }
  $stream = $null
  try {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    return $true
  } catch {
    return $false
  } finally {
    if ($stream) { $stream.Dispose() }
  }
}

function Release-LockedLauncher {
  param([string]$LauncherPath)
  if (Test-ExclusiveFile $LauncherPath) { return $true }
  $needle = ([IO.Path]::GetFullPath($LauncherPath)).Replace('/', '\').ToLowerInvariant()
  try {
    Get-CimInstance Win32_Process -Filter "Name = 'cmd.exe'" -ErrorAction SilentlyContinue | ForEach-Object {
      $commandLine = ([string]$_.CommandLine).Replace('/', '\').ToLowerInvariant()
      if ($commandLine.Contains($needle) -and $_.ProcessId -ne $PID) {
        & taskkill /F /T /PID $_.ProcessId 2>$null | Out-Null
      }
    }
  } catch {
    Write-ApplyLog "扫描 launcher.cmd 锁失败: $($_.Exception.Message)"
  }
  for ($i = 0; $i -lt 20; $i++) {
    if (Test-ExclusiveFile $LauncherPath) { return $true }
    Start-Sleep -Milliseconds 300
  }
  return (Test-ExclusiveFile $LauncherPath)
}

function Stop-WatchdogAndPort {
  $pidFile = Join-Path $DataDir 'watchdog.pid'
  if (Test-Path -LiteralPath $pidFile) {
    try {
      $watchdogPid = [int]((Get-Content -LiteralPath $pidFile -Raw).Trim())
      if ($watchdogPid -gt 0) {
        Write-ApplyLog "停止 watchdog pid=$watchdogPid"
        # 【重要】绝不能带 /T！taskkill 的 /T 按 ParentProcessId 递归连坐整棵子树，
        # 而本脚本(powershell)就是 watchdog→daemon→powershell 链上的叶子，/T 会把自身也杀掉，
        # 导致替换从未执行（apply.log 里做完「停止 watchdog」这步就没下文了）。
        # 只精确杀 watchdog 一个进程即可；daemon 已被 daemon.js 自我退出，端口兜底逻辑单独处理。
        & taskkill /F /PID $watchdogPid 2>$null | Out-Null
      }
    } catch {
      Write-ApplyLog "停止 watchdog 失败: $($_.Exception.Message)"
    }
  }

  for ($wait = 0; $wait -lt 15; $wait++) {
    $listening = @(netstat -ano | Select-String (":$Port\s") | Select-String 'LISTENING')
    if ($listening.Count -eq 0) { return }
    if ($wait -ge 3) {
      foreach ($line in $listening) {
        $parts = ($line.ToString().Trim() -split '\s+')
        $portPid = $parts[$parts.Count - 1]
        if ($portPid -match '^\d+$') {
          Write-ApplyLog "端口 $Port 仍被 pid=$portPid 占用，强制结束"
          # 同样不要 /T：占用端口的进程极可能是 daemon（本脚本的父链成员），/T 会连坐自身。
          & taskkill /F /PID $portPid 2>$null | Out-Null
        }
      }
    }
    Start-Sleep -Seconds 1
  }
  $remaining = @(netstat -ano | Select-String (":$Port\s") | Select-String 'LISTENING')
  if ($remaining.Count -gt 0) { throw "端口 $Port 在 15 秒后仍被占用" }
}

function Rollback-App {
  param([string]$OldDir, [string]$TargetDir)
  Write-ApplyLog "开始回滚旧版本"
  try { Stop-WatchdogAndPort } catch { Write-ApplyLog "回滚前停止新版进程失败: $($_.Exception.Message)" }
  try { if (Test-Path -LiteralPath $TargetDir) { Remove-Item -LiteralPath $TargetDir -Recurse -Force -ErrorAction SilentlyContinue } } catch {}
  if (Test-Path -LiteralPath $OldDir) {
    try { Move-Item -LiteralPath $OldDir -Destination $TargetDir -Force -ErrorAction Stop } catch {
      Write-ApplyLog "回滚失败: $($_.Exception.Message)"
    }
  }
  $oldLauncher = Join-Path $TargetDir 'scripts\launcher.cmd'
  $oldLauncherVbs = Join-Path $TargetDir 'scripts\launcher-hidden.vbs'
  try {
    if (Test-Path -LiteralPath $oldLauncherVbs) {
      Start-Process -FilePath (Join-Path $env:WINDIR 'System32\wscript.exe') -ArgumentList ('//nologo "' + $oldLauncherVbs + '"') -WorkingDirectory (Split-Path $oldLauncher) -ErrorAction Stop | Out-Null
    } elseif (Test-Path -LiteralPath $oldLauncher) {
      Start-Process -FilePath $oldLauncher -WorkingDirectory (Split-Path $oldLauncher) -ErrorAction Stop | Out-Null
    }
  } catch {
    Write-ApplyLog "回滚后启动旧 launcher 失败: $($_.Exception.Message)"
  }
}

$oldDir = "$AppDir.old"
$tmpDir = Join-Path $env:TEMP ("workdaddy-update-" + [guid]::NewGuid().ToString('N'))
$backupMade = $false
try {
  Write-ApplyLog "start attempt=$AttemptId src=$SrcZip dst=$AppDir port=$Port pid=$PID"
  if (-not (Test-Path -LiteralPath $SrcZip -PathType Leaf)) { throw "更新包不存在: $SrcZip" }
  Stop-WatchdogAndPort

  foreach ($launcherPath in @((Join-Path $AppDir 'scripts\launcher.cmd'), (Join-Path $oldDir 'scripts\launcher.cmd'))) {
    if (-not (Release-LockedLauncher $launcherPath)) { throw "无法释放 launcher.cmd 文件锁: $launcherPath" }
  }

  if (Test-Path -LiteralPath $oldDir) { Remove-Item -LiteralPath $oldDir -Recurse -Force -ErrorAction Stop }
  if (Test-Path -LiteralPath $AppDir) {
    Move-Item -LiteralPath $AppDir -Destination $oldDir -Force -ErrorAction Stop
    $backupMade = $true
  }

  New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
  Expand-Archive -LiteralPath $SrcZip -DestinationPath $tmpDir -Force
  $srcRoot = $tmpDir
  if (-not (Test-Path (Join-Path $tmpDir 'scripts\daemon.js'))) {
    $hit = Get-ChildItem -LiteralPath $tmpDir -Recurse -Filter 'daemon.js' -File | Select-Object -First 1
    if ($hit) { $srcRoot = Split-Path $hit.FullName -Parent | Split-Path -Parent }
  }
  foreach ($required in @('scripts\daemon.js', 'scripts\launcher.cmd', 'scripts\win-launcher.js')) {
    if (-not (Test-Path (Join-Path $srcRoot $required) -PathType Leaf)) { throw "更新包缺少 $required" }
  }
  $sourceDaemonText = Get-Content -LiteralPath (Join-Path $srcRoot 'scripts\daemon.js') -Raw
  $sourceDaemonMatch = [regex]::Match($sourceDaemonText, "const DAEMON_VERSION = '([^']+)'")
  $sourceDaemonVersion = if ($sourceDaemonMatch.Success) { $sourceDaemonMatch.Groups[1].Value } else { '' }
  $packageName = [IO.Path]::GetFileNameWithoutExtension($SrcZip)
  $packageVersionMatch = [regex]::Match($packageName, '([0-9]+\.[0-9]+\.[0-9]+)')
  $packageVersion = if ($packageVersionMatch.Success) { $packageVersionMatch.Groups[1].Value } else { '' }
  Write-ApplyLog "artifact inspect package=$packageName packageVersion=$packageVersion daemonVersion=$sourceDaemonVersion"
  if ([string]::IsNullOrWhiteSpace($sourceDaemonVersion)) { throw '更新包 daemon.js 缺少 DAEMON_VERSION' }
  if (-not [string]::IsNullOrWhiteSpace($packageVersion) -and $sourceDaemonVersion -ne $packageVersion) {
    throw "更新包内部 daemon 版本 $sourceDaemonVersion 与文件目标版本 $packageVersion 不一致"
  }

  New-Item -ItemType Directory -Force -Path $AppDir | Out-Null
  & robocopy $srcRoot $AppDir /MIR /NFL /NDL /NJH /NJS /NP | Out-Null
  $rc = $LASTEXITCODE
  Write-ApplyLog "robocopy code=$rc"
  if ($rc -ge 8) { throw "robocopy 复制失败 (code=$rc)" }

  $launcher = Join-Path $AppDir 'scripts\launcher.cmd'
  $launcherVbs = Join-Path $AppDir 'scripts\launcher-hidden.vbs'
  if (Test-Path -LiteralPath $launcherVbs) {
    $started = Start-Process -FilePath (Join-Path $env:WINDIR 'System32\wscript.exe') -ArgumentList ('//nologo "' + $launcherVbs + '"') -WorkingDirectory (Split-Path $launcher) -PassThru -ErrorAction Stop
  } else {
    $started = Start-Process -FilePath $launcher -WorkingDirectory (Split-Path $launcher) -PassThru -ErrorAction Stop
  }
  Write-ApplyLog "已启动新版 launcher pid=$($started.Id)，等待 daemon"
  $ready = $false
  for ($i = 0; $i -lt 60; $i++) {
    try {
      $status = Invoke-RestMethod -Uri ("http://127.0.0.1:{0}/api/status" -f $Port) -Method Get -TimeoutSec 2
      if ($status.version) { $ready = $true; Write-ApplyLog "新版 daemon 已就绪 version=$($status.version)"; break }
    } catch {}
    Start-Sleep -Seconds 1
  }
  if (-not $ready) { throw '新版 daemon 在 60 秒内未就绪' }
  $runningVersion = [string]$status.version
  Write-ApplyLog "running daemon version=$runningVersion expected=$packageVersion"
  if (-not [string]::IsNullOrWhiteSpace($packageVersion) -and $runningVersion -ne $packageVersion) {
    throw "新版 daemon 实际版本 $runningVersion 与目标版本 $packageVersion 不一致"
  }

  if (Test-Path -LiteralPath $oldDir) {
    Remove-Item -LiteralPath $oldDir -Recurse -Force -ErrorAction SilentlyContinue
  }
  Write-ApplyLog "done attempt=$AttemptId"
  Stop-ApplyTranscript
  exit 0
} catch {
  Write-ApplyLog "FAILED attempt=$AttemptId error=$($_.Exception.Message)"
  if ($backupMade) { Rollback-App -OldDir $oldDir -TargetDir $AppDir }
  Stop-ApplyTranscript
  exit 1
} finally {
  try { if (Test-Path -LiteralPath $tmpDir) { Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue } } catch {}
  # 清除更新标记：无论成败都不再阻止 watchdog 拉起 daemon（避免留下「daemon 死光」的悬空状态）
  try { Remove-Item -LiteralPath (Join-Path $LogDir 'pending.json') -Force -ErrorAction SilentlyContinue } catch {}
}
