!macro customInit
  nsExec::Exec 'taskkill /F /IM work-pet.exe /T'
  nsExec::Exec 'powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name = \'node.exe\'\" | Where-Object { $_.ExecutablePath -like \'*WorkPet*\' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"'
  Sleep 1000
!macroend

!macro customInstall
  nsExec::Exec 'powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name = \'node.exe\'\" | Where-Object { $_.ExecutablePath -like \'*WorkPet*\' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"'
  Sleep 500
!macroend

!macro customUnInstall
  nsExec::Exec 'taskkill /F /IM work-pet.exe /T'
  nsExec::Exec 'powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name = \'node.exe\'\" | Where-Object { $_.ExecutablePath -like \'*WorkPet*\' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"'
  Sleep 1000
!macroend
