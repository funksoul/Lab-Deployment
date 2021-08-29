Get-PackageProvider -Name nuget -Force
$Updates = Start-WUScan
$Updates | ForEach-Object {
    $_
    Install-WUUpdates -Updates $_
}
