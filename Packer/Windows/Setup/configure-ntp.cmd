%windir%\System32\reg.exe ADD HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters /v NtpServer /t REG_SZ /d "0.kr.pool.ntp.org,0x1 1.kr.pool.ntp.org,0x1 2.kr.pool.ntp.org,0x1" /f
%windir%\System32\reg.exe ADD HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters /v Type /t REG_SZ /d "NTP" /f
%windir%\System32\reg.exe ADD HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient /v SpecialPollInterval /t REG_DWORD /d 900 /f
%windir%\System32\sc.exe triggerinfo w32time start/networkon stop/networkoff
