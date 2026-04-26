🚀 Real-Time Network Intrusion Detection System (NIDS) using Machine Learning 

A web-based system for detecting and alerting suspicious network activities in real time using machine learning.
🌟 Features

    📡 Real-Time Packet Capture – Monitors live network traffic.
    🤖 Machine Learning-Based Detection – Classifies network traffic as normal or malicious.
    📊 Dashboard & Visualization – Displays traffic trends and intrusion alerts.
    📧 Automated Email Alerts – Notifies users of detected threats.
    📂 Upload & Analyze – Allows users to upload network logs for analysis.


## Troubleshooting

### 1) `InconsistentVersionWarning` (scikit-learn model mismatch)
If you see messages like:
- `Trying to unpickle estimator ... from version 1.4.2 when using version 1.3.2`

Install the exact project dependencies in the same Python environment you use to run `app.py`:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If needed, force the exact sklearn version used by the model files:

```powershell
python -m pip install --upgrade scikit-learn==1.4.2
```

### 2) `No libpcap provider available` on Windows
Live packet capture with Scapy requires Npcap on Windows.

1. Install Npcap (from the official Npcap installer).
2. During install, enable compatibility options for WinPcap if prompted.
3. Restart the terminal and run the app again.

Without Npcap, offline CSV prediction still works, but live capture can fail.

### 3) `MySQLdb.OperationalError: (2002, ... 10061)` on register/login
This means the Flask app cannot reach MySQL.

1. Start **MySQL** in XAMPP Control Panel.
2. Confirm it is listening on port `3306`.
3. Ensure the database exists:

```sql
CREATE DATABASE IF NOT EXISTS arun;
```

4. Ensure your `users` table exists before testing register/login.
