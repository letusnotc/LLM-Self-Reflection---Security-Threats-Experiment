# README — `auth_logs_small.csv`
### CERT Insider Threat Dataset (r4.2) — Sampled & Labeled

---

## 1. Source Dataset

**Original:** CERT Insider Threat Dataset Release 4.2
**From:** Carnegie Mellon University / Software Engineering Institute
**Kaggle:** `andrihjonior/cert-insider-threat-dataset-r4-2`
**Original Size:** ~16 GB across 5 log files + answer files

---

## 2. How We Sampled It

Loading all 16 GB at once crashes memory, so a **chunk-based smart sampling** strategy was used.

### Strategy: "Grab All Insiders + Fixed Benign Sample"

Each of the 5 log files (`logon.csv`, `file.csv`, `device.csv`, `email.csv`, `http.csv`) was read in **chunks of 50,000 rows at a time** — never the full file.

For each chunk, two things happened:

- **Insider users** → Every row belonging to any of the 191 known insider users was kept (collected across all chunks until the full file was scanned)
- **Benign users** → Only the first **10,000 rows** of non-insider users were kept per file, then scanning stopped early

This means:
- We never loaded more than ~50,000 rows into RAM at once
- We guaranteed all insider activity was captured
- We kept a controlled, small benign sample

### Files Loaded

| Log File | Total Rows Loaded | Insider User Rows | Benign Rows |
|---|---|---|---|
| logon.csv | 54,101 | 44,101 | 10,000 |
| file.csv | 38,683 | 28,683 | 10,000 |
| device.csv | 54,134 | 44,134 | 10,000 |
| email.csv | 47,619 | 37,619 | 10,000 |
| http.csv | 47,691 | 37,691 | 10,000 |
| **Total** | **242,228** | **192,228** | **50,000** |

---

## 3. How Labels Were Assigned

Labels were **not** assigned just by username. Instead, each row was labeled using a **3-condition time window check**:

```
label = 1  if:
    (1) row's user  == a known insider user
    AND
    (2) row's date  >= that insider's threat START date
    AND
    (3) row's date  <= that insider's threat END date

label = 0  otherwise (benign)
```

This means an insider user's **normal activity before or after their threat window is labeled 0 (benign)** — only their activity during the active attack window is labeled 1.

The threat windows came from `answers/insiders.csv` which contains:

| Column | Description |
|---|---|
| `user` | Employee ID of the insider |
| `start` | Date their malicious activity began |
| `end` | Date their malicious activity ended |
| `scenario` | Which threat scenario they enacted |
| `details` | Description of what they did |

### Final Label Distribution

| Label | Meaning | Count | % |
|---|---|---|---|
| 0 | Benign / normal activity | 229,354 | 94.7% |
| 1 | Insider threat activity | 12,874 | 5.3% |
| **Total** | | **242,228** | |

This ~5% malicious rate reflects **real-world insider threat scenarios** where malicious events are always a small minority.

---

## 4. Final CSV Columns

The output file `auth_logs_small.csv` has the following columns:

| Column | Type | Description |
|---|---|---|
| `date` | datetime | Timestamp of the event |
| `user` | string | Employee ID (e.g. `CSC0217`) |
| `pc` | string | Workstation/PC identifier |
| `source` | string | Which log file the row came from: `logon`, `file`, `device`, `email`, or `http` |
| `activity` | string | What action was performed (e.g. `Logon`, `Logoff`, `Connect`, `Send`, `WWW Visit`) |
| `filename` | string | File path accessed (only for `file` source rows, NaN otherwise) |
| `url` | string | Website visited (only for `http` source rows, NaN otherwise) |
| `to` | string | Email recipient (only for `email` source rows, NaN otherwise) |
| `from` | string | Email sender (only for `email` source rows, NaN otherwise) |
| `size` | float | Size in bytes of file or email (NaN if not applicable) |
| `label` | int | **Target variable: 1 = insider threat, 0 = benign** |
| `id` | string | Unique event ID from original log |
| `content` | string | Email body content flag (email rows only) |
| `cc` | string | CC recipients (email rows only) |
| `bcc` | string | BCC recipients (email rows only) |
| `attachments` | string | Attachment info (email rows only) |

> **Note:** Many columns will be `NaN` for rows from other sources. For example, `filename` is only populated for `file` source rows — it will be `NaN` for logon, device, email, and http rows. This is expected.

---

## 5. What a Malicious Row Looks Like

```
date                    user      source   activity    label
2010-06-10 13:13:31    CSC0217   logon    Logon         1
2010-06-10 13:28:49    CSC0217   logon    Logoff        1
2010-06-10 15:18:19    CSC0217   device   Connect       1
2010-06-10 15:20:36    CSC0217   file     NaN           1
2010-06-10 15:22:06    CSC0217   device   Disconnect    1
```

This shows a classic insider threat pattern: user logs in → connects a USB device → accesses a file → disconnects the USB → logs off, all within ~2 hours.

---

## 6. Intended Use

This dataset is ready for:
- **Binary classification** (predict `label`: 0 or 1)
- **Anomaly detection** (treat label=1 as anomaly)
- **Behavioral analysis** (study patterns of insider users vs normal users)
- **Feature engineering** (e.g. after-hours activity, USB + file access combinations)

**Total insider users in dataset:** 191
**Time range:** January 2010 — May 2011
**License:** Creative Commons Attribution 4.0 International (CC BY 4.0)