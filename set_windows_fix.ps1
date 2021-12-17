#
## Search log4j files in C: AND fix if possible
#
## (c) suuhm 2021
#

$SDIR="C:\"

Write-Host "Searching for log4j files in $SDIR and put in CSV"
Get-childitem -Path $SDIR -Include log4j*.jar -File -Recurse -ErrorAction SilentlyContinue | select Lastwritetime, directory, name | export-csv -append -notypeinformation found_log4j_files.csv

sleep 3.4

Write-Host "Fix on Windows:"
# Variable name:LOG4J_FORMAT_MSG_NO_LOOKUPS
# Variable value: true

# Powershell command to set the variable:
[System.Environment]::SetEnvironmentVariable('LOG4J_FORMAT_MSG_NO_LOOKUPS','true',[System.EnvironmentVariableTarget]::Machine)

sleep 2.1
Write-Host "Successfully Done!"
