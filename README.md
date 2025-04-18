# Cyberattack Detection Project - EEL 6803

This repository contains a complete Python-based framework to detect cyberattacks in synthetic network traffic using a hybrid approach:
- Rule-Based Detection
- Anomaly-Based Detection
- GPT-3.5 Large Language Model (LLM) Classification

## 📁 Files Overview

- `gen.py` — Generates a synthetic dataset of network traffic saved as `traffic.csv`
- `traffic.csv` — Simulated network flows (1,000 rows of benign and malicious traffic)
- `script.py` — Final unified script that:
  - Performs rule-based and anomaly-based detection
  - Sends each row to OpenAI GPT-3.5 for classification
  - Combines all methods into a final label: `Low`, `Medium`, or `High`
  - Saves output to `results.csv`
- `results.csv` — Output containing all raw data + detection flags + LLM results + final labels

## 🧪 How It Works

1. **Generate Synthetic Dataset**
   ```bash
   python gen.py
   ```
   - This creates `traffic.csv` with realistic metadata and attack patterns

2. **Run Unified Detection Pipeline**
   ```bash
   python script.py
   ```
   - This processes the dataset and saves `results.csv`

## 🔐 OpenAI API Key
To use GPT-3.5 for LLM detection:
1. Get your API key at https://platform.openai.com/account/api-keys
2. In `script.py`, replace:
   ```python
   openai.api_key = "sk-REPLACE_ME"
   ```
   with your actual key (keep it secret).

## 🧠 Detection Breakdown

- **Rule-Based:**
  - Flags known malicious IPs, ports, or keywords (e.g., "C2", "cleanup")
- **Anomaly-Based:**
  - Flags uncommon protocols (SMB, ICMP) or oversized packets
- **LLM-Based:**
  - GPT-3.5 classifies each row's intent and assigns a probability + attack type
- **Final_Label:**
  - Aggregates all three methods into `Low`, `Medium`, or `High`

## 📊 Sample Output Columns
- `Rule`, `Anomaly`, `Score`
- `LLM_Probability`, `LLM_Type`
- `Final_Label`

## 🔍 Example Use Cases
- Compare traditional vs. AI-driven detection
- Validate LLM accuracy on known attack signatures
- Prototype hybrid threat detection workflows

## 🛠 Requirements
- Python 3.8+
- `pandas`, `openai`, `matplotlib`
- Run `pip install -r requirements.txt` (or install manually)

## 📈 Optional Visualizations
You can generate bar charts or pie charts from `results.csv` to show:
- Final label distribution
- Breakdown by detection method

## 👥 Authors
- Hamzah Masri  
- Sanskar Lohani  
- Alexander Barrios  
- Aditya Bikkasani  
- Dr. Gustavo Chaparro (Instructor)

---
