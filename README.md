# Person 3 - Threat Scoring & Filtering Engine

## Overview
This project is part of a group cybersecurity tool designed to reduce false positives by combining local file analysis with global threat intelligence.

My role (Person 3 – "The Judge") is to analyze and score files using data provided by:
- Person 1: File analysis (hashes, suspicious indicators)
- Person 2: Threat intelligence (VirusTotal, MalwareBazaar)

The system assigns a risk score and produces a final verdict.

---

## Objective
To build a scoring and filtering system that:
- Combines multiple sources of threat data
- Assigns weighted scores to suspicious indicators
- Reduces false positives
- Produces a clear and explainable verdict

---

## How It Works

### Step 1: File Analysis (Person 1)
- Extracts SHA256 hash
- Identifies suspicious indicators
- Outputs JSON

### Step 2: Threat Intelligence (Person 2)
- Queries VirusTotal
- Queries MalwareBazaar
- Returns detection data

### Step 3: Scoring (Person 3)
- Scores all data
- Reduces false positives
- Outputs verdict

---

## Verdict Levels

| Score | Result |
|------|--------|
| 80+  | Malicious |
| 45–79 | Suspicious |
| 15–44 | Likely Safe |
| 0–14 | Safe |

---

## Run the Program

```bash
python3 person3_scoring.py
