import pandas as pd
import openai
import time

# Configuration
openai.api_key = "sk-REPLACE_ME"  # Replace with your actual API key
model = "gpt-3.5-turbo"
input_file = "traffic.csv"
output_file = "results.csv"
MAX_ROWS = 50  # Change based on how many GPT calls you want

# Variables
keywords = ["C2", "Upload", "cleanup", "delete", "phishing"]
ports = [4444, 5555]
ips = ["198.51.100.25", "203.0.113.45", "172.217.5.110"]
MAX_SIZE = 1000
RARE_PROTOCOLS = ["SMB", "ICMP"]

# Get Load Traffic Data
df = pd.read_csv(input_file).head(MAX_ROWS)

# Rule Detection
def rule(row):
    info = str(row.get("Info", "")).lower()
    if any(k.lower() in info for k in keywords):
        return 1
    if row.get("Destination IP") in ips:
        return 1
    if row.get("Port") in ports:
        return 1
    return 0

# Anomaly Detection
def anomaly(row):
    if row.get("Packet Size", 0) > MAX_SIZE:
        return 1
    if row.get("Protocol") in RARE_PROTOCOLS:
        return 1
    return 0

# LLM Prompt
system_msg = (
    "You are a cybersecurity network forensics analyst. Based on network flow metadata, estimate the likelihood "
    "that the activity represents a cyberattack. Respond with JSON: "
    "{\"probability\": \"XX%\", \"attack_type\": \"TYPE\"}."
)

def build_prompt(row):
    return (
        f"Analyze this network activity:\n"
        f"- Timestamp: {row['Timestamp']}\n"
        f"- Source IP: {row['Source IP']}\n"
        f"- Destination IP: {row['Destination IP']}\n"
        f"- Protocol: {row['Protocol']}\n"
        f"- Port: {row['Port']}\n"
        f"- Packet Size: {row['Packet Size']}\n"
        f"- Info: {row['Info']}\n\n"
        "Return only the JSON object."
    )

# Apply Detections and GPT
llm_probs = []
llm_types = []
final_labels = []

for i, row in df.iterrows():
    # Rule & anomaly
    rule_flag = rule(row)
    anomaly_flag = anomaly(row)
    score = rule_flag + anomaly_flag

    # GPT call
    try:
        response = openai.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_msg},
                {"role": "user", "content": build_prompt(row)}
            ],
            temperature=0.3,
            max_tokens=100,
        )
        reply = response.choices[0].message.content
        print(f"[{i+1}] {reply}")
        parsed = eval(reply)
        prob = int(parsed["probability"].replace("%", "").strip())
        attack_type = parsed["attack_type"]
    except Exception as e:
        print(f"Error on row {i+1}: {e}")
        prob = 0
        attack_type = "Error"

    # Final label logic
    if score >= 2 or prob >= 70:
        label = "High"
    elif score == 1 or 40 <= prob < 70:
        label = "Medium"
    else:
        label = "Low"

    llm_probs.append(f"{prob}%")
    llm_types.append(attack_type)
    final_labels.append(label)

    time.sleep(1.1)

# Append Output
df["Rule"] = df.apply(rule, axis=1)
df["Anomaly"] = df.apply(anomaly, axis=1)
df["Score"] = df["Rule"] + df["Anomaly"]
df["LLM_Probability"] = llm_probs
df["LLM_Type"] = llm_types
df["Final_Label"] = final_labels

# Save Results
df.to_csv(output_file, index=False)
print(f"\nFinal combined results saved to {output_file}")
