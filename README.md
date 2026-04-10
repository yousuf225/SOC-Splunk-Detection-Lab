# 🔐 Splunk SIEM – SOC Monitoring & Brute Force Detection

## 📌 Overview

This project demonstrates the implementation of a Security Information and Event Management (SIEM) solution using Splunk to monitor system logs, detect SSH brute-force attacks, and identify potential account compromise scenarios.

The lab simulates real-world SOC operations, including log ingestion, detection engineering, alerting, and incident analysis.

---

## 🎯 Objectives

* Monitor authentication logs in real time
* Detect brute-force login attempts
* Correlate failed and successful logins
* Configure alerts based on attack patterns
* Build a basic SOC monitoring dashboard

---

## 🧱 Lab Architecture

**Kali Linux (Attacker) → Ubuntu (Log Source) → Splunk (SIEM)**

---

## ⚙️ Technologies Used

* Splunk (SIEM)
* Ubuntu Linux (Log Source)
* Kali Linux (Attack Simulation)

---

## 📂 Log Source

* File monitored: `/var/log/auth.log`

Contains SSH authentication logs such as:

* Failed password attempts
* Successful logins

---

## 🔍 Detection Use Cases

### 1. Failed SSH Login Detection

```spl id="spl1"
index=main "Failed password"
```

### 2. Brute Force Detection

```spl id="spl2"
index=main "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| where count > 5
```

### 3. Successful Login Detection

```spl id="spl3"
index=main "Accepted password"
```

### 4. Brute Force → Successful Login (Critical)

```spl id="spl4"
index=main ("Failed password" OR "Accepted password")
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| eval status=if(searchmatch("Failed password"), "failed", "success")
| stats count(eval(status="failed")) as failed_attempts, count(eval(status="success")) as successful_logins by src_ip
| where failed_attempts > 5 AND successful_logins > 0
```

---

## 🚨 Alert Configuration

| Alert Type | Condition                 | Severity |
| ---------- | ------------------------- | -------- |
| Medium     | 5–9 failed attempts       | Medium   |
| High       | ≥10 failed attempts       | High     |
| Critical   | Failed + Successful login | Critical |

**Settings:**

* Real-time alerts enabled
* Trigger condition: Number of results > 0
* Throttling: 5–10 minutes (to prevent alert flooding)

---

## 📊 Dashboard

A SOC dashboard was created to visualize:

* Failed login attempts
* Attacking IP addresses
* Successful logins
* Alert activity

---

## 🧪 Attack Simulation

* Multiple failed SSH login attempts were generated from Kali Linux
* Followed by a successful login
* Splunk detected the activity and triggered alerts

---

## 🔎 Key Findings

* Multiple failed login attempts indicate brute-force behavior
* Successful login after failures suggests potential account compromise
* Alert throttling reduces duplicate alerts and improves efficiency

---

## 🧠 MITRE ATT&CK Mapping

| Technique      | ID    |
| -------------- | ----- |
| Brute Force    | T1110 |
| Valid Accounts | T1078 |

---

## 📸 Evidence

*Add screenshots here:*

* Dashboard view
* Failed login logs
* Detection query results
* Triggered alerts
* Successful login events

---

## 📌 Conclusion

This project demonstrates practical SOC skills, including:

* Log analysis
* Detection rule creation
* Alert configuration and tuning
* Incident identification

It reflects real-world security monitoring workflows used in SOC environments.
