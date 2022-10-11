# Microsoft Defender for Identity Log Analyzer



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
