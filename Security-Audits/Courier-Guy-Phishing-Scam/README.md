# 🚨 Courier-Guy-Phishing-Scam — Security Audit

**TL;DR:** Reported and analyzed a live SMS→shortlink phishing kit that impersonated *The Courier Guy*. The landing page HTML was saved and analysed (no form submission was performed). Abuse was reported and the hosting object was later taken down / flagged by SOC. All IOCs in public files are defanged.

---

## 📌 Overview
This folder contains the public, defanged analysis for an SMS-driven phishing campaign that redirected victims via a snip.ly link to a Cloudflare R2-hosted phishing page. The goal of this audit is to document the incident, show safe analysis techniques, and preserve a reproducible, non-executable artifact for learning and SOC handoffs.

> **Safety first:** do **not** open `phishing_page.html` in a browser. View it in a plain text editor only (Notepad, VS Code with extensions disabled, or `less` / `cat`).

---

## 🔎 What I have (artifacts)
- `Phishing-scam.md` — Full incident write-up / report (public, defanged).  
- `phishing_page.html` — Saved raw HTML of the landing page (static review only).  
- `README.md` — (this file) — overview, methodology, safe handling notes.

> Note: The collector endpoint (`cc.html`) was observed referenced inside the saved HTML during analysis, however a separate `cc.html` collector file was **not** retrieved nor stored in this repository.

---

## 🎯 Objectives
- Document the incident discovery, technical analysis, and escalation steps in a safe, shareable way.  
- Extract and preserve non-actionable IOCs and evidence for SOC / brand protection (defanged).  
- Provide clear, safe instructions for other analysts who may inspect the artifact.

---

## 🧪 Methodology (safe, non-executing)
1. **Capture:** Saved the landing page HTML using `Invoke-WebRequest` (header/HTML capture only).  
2. **Static analysis:** Scanned the HTML for `<title>`, `<form action=...>`, `<input>` names, and third-party analytics tags (TikTok / Facebook / Hotjar / GTM). All analysis was performed on the saved file (no form posts).  
3. **Escalation:** Reported the host via Cloudflare abuse and coordinated with SOC (Zscaler blocked outbound fetches from corporate). SOC confirmed takedown/status.  
4. **Defanging:** All live-host strings and URLs in public files are defanged (e.g., `r2[.]dev`, `pub-xxxx[.]r2[.]dev`).

---

## 🗂 Key findings (from saved HTML)
- **Page title:** `The Courier Guy` (brand impersonation).  
- **Collector reference:** `cc.html` referenced as the form action in the HTML (collector file not retrieved).  
- **Tracking / analytics:** multiple third-party pixels and GTM (used to make the page appear legitimate and to track campaign clicks).  
- **Page size & type:** full HTML landing page (static form-based phishing UI).

---

## 🛡 Recommendations
- **Users:** Don’t click shortlinks from unsolicited SMS parcel alerts; verify via official sites or apps.  
- **SOC / Ops:** Treat shortlink + cloud object storage hosting as high-risk; add signatures/blocks for repeated shortlink domains and monitor R2/S3-style buckets for unusual HTML objects.  
- **Threat Intel:** If possible, request full tenant details from the hosting provider (Cloudflare) for merchant/gateway tracing — SOC did a sandbox capture and confirmed takedown.

---

## ⚠️ Safe review instructions (for analysts)
- Open `phishing_page.html` only in a plain text editor (Notepad, `code --disable-extensions`, `less`, or `cat`).  
- Do **not** double-click the file or open it in a browser.  
- If you need to follow-up with dynamic analysis, run the fetch in an **isolated sandbox** (air-gapped VM) under SOC control — do not do this on corporate networks.

---

## How I contributed
- Performed safe capture and static analysis of the landing page HTML.  
- Extracted branding, form action references, and analytics indicators.  
- Escalated to SOC and Cloudflare; documented the incident in `Phishing-scam.md`.

---

## Where to next (for SOC / future work)
- SOC: if permitted, perform a controlled sandbox fetch to retrieve the collector script (cc.html) and check server-side exfil endpoints / mailto addresses.  
- Threat Intel: add the defanged host and UTM shortlink to global blocklists and to Mastercard escalation packet if merchant/payment artifacts are found.  
- Portfolio: consider adding a short `scripts/extract_iocs.ps1` later (safe snippets only) to show how the HTML was parsed.

---

**End of README**
