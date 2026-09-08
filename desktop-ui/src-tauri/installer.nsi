!macro customInit
  nsExec::Exec 'taskkill /F /IM workpet.exe /T'
  nsExec::Exec 'powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name = \'node.exe\'\" | Where-Object { $_.ExecutablePath -like \'*WorkPet*\' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"'
  Sleep 1000
!macroend

!macro customInstall
  nsExec::Exec 'powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name = \'node.exe\'\" | Where-Object { $_.ExecutablePath -like \'*WorkPet*\' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"'
  Sleep 500
  ; 默认不创建桌面快捷方式：Tauri NSIS 安装完会在桌面生成 WorkPet.lnk，这里删除它
  nsExec::Exec 'powershell -NoProfile -Command "$d=[Environment]::GetFolderPath(\'Desktop\'); Remove-Item -LiteralPath (Join-Path $d \'WorkPet.lnk\') -ErrorAction SilentlyContinue"'
!macroend

!macro customUnInstall
  nsExec::Exec 'taskkill /F /IM workpet.exe /T'
  nsExec::Exec 'powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name = \'node.exe\'\" | Where-Object { $_.ExecutablePath -like \'*WorkPet*\' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"'
  Sleep 1000
!macroend
