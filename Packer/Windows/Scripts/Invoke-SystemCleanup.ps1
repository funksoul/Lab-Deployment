<#
    .SYNOPSIS
    Performs cleanup of aesthetic artifacts on the system.
    
 #>

# Remove Run Key Persistence
Try {
    Write-Host "Cleaning up registry keys."
    Remove-ItemProperty 'HKLM:\SOFTWARE\Wow6432node\Microsoft\Windows\CurrentVersion\Run' -Name * -Force
    Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name * -Force
    Remove-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name * -Force
}
Catch {
    Write-Error "Could not remove run keys as part of the cleanup script. Exiting."
    Write-Host $_.Exception | format-list -force
    Exit 1
}
