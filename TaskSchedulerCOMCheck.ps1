$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
    if ($Task.Actions.ClassId -ne $null)
    {
        if ($Task.Triggers.Enabled -eq $true)
        {
            if ($Task.Principal.GroupId -eq "Users")
            {
                Write-Host "Task Name: " $Task.TaskName
                Write-Host "Task Path: " $Task.TaskPath
                Write-Host "CLSID: " $Task.Actions.ClassId
                Write-Host
            }
        }
    }
}
