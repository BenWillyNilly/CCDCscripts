Import-Csv .\BaselineTasks.csv | ForEach-Object {
    '"{0}|{1}"' -f $_.TaskPath,$_.TaskName
}