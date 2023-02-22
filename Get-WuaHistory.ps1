<# 
A simple script to get update history, set to 150 but change to what you want. Just import the module (or run in the scripting pane of ISE).
usage Get-WuaHistory | format-table
#>

function Convert-WuaResultCodeToName
{
param( [Parameter(Mandatory=$true)]
[int] $ResultCode
)
$Result = $ResultCode
switch($ResultCode)
{
2
{
$Result = "Success"
}
3
{
$Result = "Success with err"
}
4
{
$Result = "Failed"
}
}
return $Result
}
function Get-WuaHistory
{
$session = (New-Object -ComObject 'Microsoft.Update.Session')
$history = $session.QueryHistory("",0,150) | ForEach-Object {
$Result = Convert-WuaResultCodeToName -ResultCode $_.ResultCode
$_ | Add-Member -MemberType NoteProperty -Value $Result -Name Result
$_ | Add-Member -MemberType NoteProperty -Value $_.UpdateIdentity.UpdateId -Name UpdateId
$_ | Add-Member -MemberType NoteProperty -Value $_.UpdateIdentity.RevisionNumber -Name RevisionNumber
$_ | Add-Member -MemberType NoteProperty -Value $Product -Name Product -PassThru
Write-Output $_
}
$History |
Where-Object {![String]::IsNullOrWhiteSpace($_.title)} |
Select-Object Result, Date, Title, SupportUrl, Product, UpdateId, RevisionNumber
}
