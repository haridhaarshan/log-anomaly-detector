# Log Anomaly Detector

A Java tool that analyzes authentication logs to detect brute-force attacks and anomalous login behavior, using rule-based and statistical methods, and produces risk-scored alerts.

I built this to understand how security monitoring (SOC-style detection) works at a small scale: take system data, find abnormal behavior, raise an alert.

## What it detects

| Detector | What it catches | Risk |
|---|---|---|
| `BruteForceDetector` | Many failed logins from one IP in a short window (default: 5 in 60 seconds), using a sliding window | MEDIUM / HIGH |
| `OddHourDetector` | Successful logins outside normal hours (before 6 AM or after 10 PM) | MEDIUM |
| `AccountSpreadDetector` | One user logging in from many different IPs (default: 4+), which can indicate a stolen account | HIGH |
| `StatDetector` | IPs whose number of attempts is a statistical outlier (z-score >= 2) | MEDIUM |

## Project structure

```
Main.java                  Entry point, runs all detectors, writes the report
LogEvent.java              One parsed log line
LogParser.java             Reads the CSV log file into LogEvent objects
LogGenerator.java          Creates sample logs with attacks hidden inside
Detector.java              Interface that every detection rule implements
BruteForceDetector.java
OddHourDetector.java
AccountSpreadDetector.java
StatDetector.java
Alert.java                 A finding with a type, risk level and message
```

## How to run

Requires Java 11 or newer.

```bash
javac *.java
java Main                  # generates sample_logs.csv and analyzes it
java Main my_logs.csv      # analyze your own log file
```

Log format (CSV with a header):

```
timestamp,ip,username,status
2026-11-20 02:14:01,203.0.113.45,admin,FAIL
2026-11-20 10:30:12,10.0.0.10,priya,SUCCESS
```

## Sample output

```
Loaded 80 log events.

===== ALERT REPORT (4 alerts) =====
[HIGH] Brute force: 203.0.113.45 had 20 failed logins within 60 seconds
[HIGH] Account spreading: rahul logged in from 6 different IPs: [...]
[MEDIUM] Odd-hour login: priya logged in successfully at 2026-11-20 03:27:45 from 10.0.0.10
[MEDIUM] Statistical outlier: 203.0.113.45 made 20 attempts (average 4.4, z-score 3.70)
```

The report is also saved to `alerts_report.txt`.

## How it works

1. `LogGenerator` creates realistic office activity plus three planted attacks (brute force, odd-hour login, account spreading).
2. `LogParser` converts each CSV line into a `LogEvent` and sorts events by time.
3. Each `Detector` scans the events and returns a list of `Alert` objects.
4. `Main` sorts alerts by risk (HIGH first), prints them and saves a report.

Adding a new rule only requires a new class implementing `Detector` and one line in `Main`.

## Ideas for future improvement

- Read real Linux `auth.log` / SSH logs
- Add per-user baselines (learn each user's normal login hours)
- Replace fixed thresholds with a machine-learning anomaly model (for example Isolation Forest)
- Add unit tests with JUnit
- Real-time monitoring instead of batch analysis

## What I learned

Log analysis, sliding-window algorithms, z-score anomaly detection, designing extensible code with interfaces, and how brute-force and account-takeover attacks look in data.
