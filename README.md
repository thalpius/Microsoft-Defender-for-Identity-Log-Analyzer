# Microsoft Defender for Identity Log Analyzer

You can use this Microsoft Defender for Identity Log Analyzer to view the log files used by Microsoft Defender for Identity. The tools offers the following featured:

- Descending order of the log entries so the newest entries are on top.
- A filter for Errors, Warning, Information and Debug for easy troubleshooting.
- A description field on what steps to take at certain messages. The option is there, but no description is added so far.

What I will add soon is:

- An export button to export the latest log files for easy sending or storing.
- Adding descriptions at common messages with more information on how to solve the issue.

For more information, please check: https://learn.microsoft.com/en-us/defender-for-identity/troubleshooting-using-logs

# Using Microsoft Defender for Identity Log Analyzer

Start the application on a Domain Controller where the Microsoft Defender for Identity sensor is installed or overwrite the log files location in a JSON file. The colored icons on the dashboard shows if the log files are read correctly.

The application uses the following default folders for the log files:

``C:\Program Files\Azure Advanced Threat Protection Sensor\<SENSORVERSION>\Logs``

# Overwrite the default folders

If you want to read the log files from a different folder or not from the Domain Controller, overwrite the folder using a JSON configuration file. Create a file called `Microsoft Defender for Identity Log Analyzer.json` in the same folder as the applcation and overwrite the locations:

```json
{
   "sensor":"D:\\Install\\Sensors\\2.191.15751.45259\\Logs\\Microsoft.Tri.Sensor.log",
   "sensorUpdater":"D:\\Install\\Sensors\\2.191.15751.45259\\Logs\\Microsoft.Tri.Sensor.Updater.log",
   "sensorUpdaterErrors":"D:\\Install\\Sensors\\2.191.15751.45259\\Logs\\Microsoft.Tri.Sensor.Updater-Errors.log",
   "sensorErrors":"D:\\Install\\Sensors\\2.191.15751.45259\\Logs\\Microsoft.Tri.Sensor-Errors.log"
}
```

# Screenshots

The dashboard shows if the log files are read correctly:

![Alt text](/Screenshots/MicrosoftDefenderForIdentityLogAnalyzer01.png?raw=true "Microsoft Defender for Identity Log Analyzer Dashboard")

Here is an example of a filtered log:

![Alt text](/Screenshots/MicrosoftDefenderForIdentityLogAnalyzer02.png?raw=true "Microsoft Defender for Identity Log Analyzer Logs")
