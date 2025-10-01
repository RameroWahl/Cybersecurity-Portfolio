# 🛡️ Incident Report: Parcel-Phish Campaign Targeting South Africa  

![Status: Closed](https://img.shields.io/badge/Status-Closed-brightgreen)  
![Category: Phishing](https://img.shields.io/badge/Category-Phishing-red)  
![Impact: High](https://img.shields.io/badge/Impact-High-orange)  
![Environment: Cloudflare_R2](https://img.shields.io/badge/Environment-Cloudflare_R2-blue)  

---

## 📌 1. Summary  
An **SMS phishing campaign** impersonating *The Courier Guy* attempted to trick victims into paying a small fake delivery fee (R18.22). The SMS link redirected through *snip.ly* to a **Cloudflare R2 bucket**, hosting a spoofed courier page. The landing page contained a hidden form (`cc.html`) designed to harvest **payment card details**.  

The phishing kit was reported, escalated, and ultimately **taken down**.  

---

## ⏱️ 2. Discovery & Timeline  

| Time / Offset | Action / Observation |
|---------------|-----------------------|
| T0 | Received SMS: *“Your delayed parcel is ready for tomorrow’s dispatch with R18.22 due…”* |
| + few min | Shortlink expanded → `pub-bcb009eac8e4409c864e417963591a43.r2.dev/index.html` |
| + same session | HTTP 200 OK, spoofed Courier Guy page served |
| + analysis | Extracted `<title>` = *The Courier Guy*, form action = `cc.html` |
| + reporting | Abuse report filed with Cloudflare (Case ID: f9953edf3040bae5) |
| + defense | Zscaler IPS blocked outbound request to `cc.html` |
| + escalation | SOC sandbox replay → “**Reported for phishing**” banner returned |
| Final | Site confirmed **down**; Mastercard escalation initiated |

---

## 🔍 3. Technical Analysis  

> **⚠️ Key Observation**  
> Attackers used *Cloudflare R2* object storage + *snip.ly* link forwarding to host a realistic-looking phishing kit.

### 3.1 Infrastructure  
- **Host:** `pub-bcb009eac8e4409c864e417963591a43.r2.dev`  
- **Edge Headers:** CF-RAY (Cape Town PoP)  
- **Title:** `<title>The Courier Guy</title>`  
- **Collector Endpoint:** `cc.html`  
- **Example Input Field:** `vehicle1` (obfuscated placeholder)  

### 3.2 Suspicious Indicators  
- Embedded **Facebook Pixel, TikTok Pixel, Hotjar** — used to mimic real analytics.  
- **UTM parameters** in link → attacker tracking campaign success.  
- Spoofed branding (*Courier Guy*).  

---

## 🎯 4. Impact Assessment  

- **Target Victims:** South African mobile subscribers receiving SMS blast.  
- **Data at Risk:** Full payment card data (PAN, Expiry, CVV, Name, Billing).  
- **Financial Risk:** High – cards could be tested, used for fraud, or resold.  
- **Reputational Risk:** Courier Guy brand spoofed, lowering trust in legitimate comms.  
- **Operational Risk:** Re-upload possible if Cloudflare tenant not fully suspended.  

---

## 🛠️ 5. Response & Mitigation  

### Actions Taken  
✔ Abuse report submitted to Cloudflare.  
✔ Host blocked internally.  
✔ Escalated to Card Fraud & Mastercard.  
✔ SOC sandbox replay confirmed **phishing takedown**.  

### Outcome  
- Phishing site flagged and disabled.  
- Host now returns *“Reported for phishing”* banner.  
- Risk to customers neutralized.  

---

## 📚 6. Lessons Learned  

- 🧩 **Shortlinks + Cloud buckets = perfect phishing combo** → always expand links.  
- 🔎 **Parsing form actions early is critical** → reveals exfil endpoints.  
- 🚫 **Enterprise filtering (Zscaler)** proved effective → blocked exfil attempt.  
- 📝 **Evidence matters** → HTML dump + headers made escalation clean.  
- 🔒 **Tenant-level suspension > object removal** → prevents re-uploads.  
- 📱 **Awareness training is vital** → low-value lures (R18.22) are highly effective.  

---

## ✅ 7. Conclusion  
This case highlights how attackers exploit **modern cloud storage** and **URL shorteners** to deploy scalable phishing kits.  
By acting quickly — reporting, analyzing, and escalating — the campaign was contained before significant damage occurred.  

Key takeaway: **Incident response doesn’t require a title — it requires vigilance.**  
Even as a Data Engineer in training, contributing early detection and structured reporting directly helped protect the ecosystem.  

---

