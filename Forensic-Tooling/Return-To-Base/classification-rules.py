from dataclasses import dataclass

@dataclass
class ForesicFile:
    file_path: str
    hidden: bool
    timestomped: bool
    malware_detected: bool

@dataclass
class ForesicProcess:
    process_name: str
    injected_dlls: bool

@dataclass
class Threat:
    threat_type: str
    risk_level: str
    rootkit_detected: bool

def evaluate_risk(file: ForesicFile, process: ForesicFile, threat: Threat):
    if file.hidden and not file.timestomped and not file.malware_detected:
        risk_level = "Low"

    if process.injected_dlls:
        risk_level = "Medium"

    if threat.risk_level == "High":
        alert_user(threat)

def calculate_risk_score(file, process, threat):
    score = 0
    if file.hidden: score += 2
    if file.timestomped: score += 3
    if threat.malware_detected: score += 5
    if process.injected_dlls: score += 4
    if threat.rootkit_detected: score += 10
    
    if score >= 10:
        return "High"
    elif score >= 5:
        return "Medium"
    else:
        return "Low"

def alert_user(threat):
    print(f"Alert! {threat.threat_type} detected with risk level {threat.risk_level}")

# Calculate Risk
# Define the variables
file = ForesicFile(file_path="example.txt", hidden=True, timestomped=False, malware_detected=False)
process = ForesicProcess(process_name="example.exe", injected_dlls=True)
threat = Threat(threat_type="Malware", risk_level="High", rootkit_detected=True)

# Calculate Risk
risk = calculate_risk_score(file, process, threat)

# Alert if high risk
if risk == "High":
    alert_user(threat)

# Print final risk classification
print(f"Final Risk Classification: {risk}")