# Phishing Triage Checklist

## Purpose

This checklist helps a non-expert examine a suspicious email or
message without interacting with dangerous content.

## Golden Rule

**Pause, Verify, Report**

## Step 1: Pause

- Do not click suspicious links.
- Do not scan unexpected QR codes.
- Do not open unexpected attachments.
- Do not call telephone numbers provided in suspicious messages.
- Do not approve unexpected MFA requests.
- Notice whether the message creates urgency, fear or pressure.

## Step 2: Check the Sender

Check the following:

- Display name
- Full sender email address
- Reply-To email address
- Sender domain spelling
- Return-Path, when available

Possible red flags include:

- The display name claims to be a trusted person but the address is external.
- The sender and Reply-To domains do not match.
- The sender domain contains a spelling mistake.
- The sender domain contains words such as secure, login, account or update.

## Step 3: Check the Link

- Hover over the link without clicking.
- Read the domain carefully.
- Check whether the link uses HTTPS.
- Check for URL shorteners.
- Check for IP-address links.
- Check for excessive subdomains.
- Check whether a familiar company name appears before another root domain.

## Step 4: Check the Request

Ask the following questions:

- Was I expecting this request?
- Is the sender asking for my password?
- Is the sender requesting an OTP or MFA code?
- Is the message requesting money or a wire transfer?
- Is the message asking me to buy gift cards?
- Is the sender asking me to bypass normal procedures?
- Does the sender demand secrecy?
- Can I verify the request using a trusted phone number?

## Step 5: Check Attachments

Unexpected files with these extensions may be dangerous:

- .exe
- .scr
- .js
- .vbs
- .bat
- .cmd
- .iso
- .img
- .lnk
- .zip
- .rar
- .docm
- .xlsm

Do not enable macros or bypass security warnings.

## Decision Tree

```text
Incoming Suspicious Message
             |
             v
Are any red flags present?
       | Yes              | No
       v                  v
Are there several       Can the sender and
strong indicators?      request be verified?
   | Yes    | Unsure       | Yes       | No
   v        v              v           v
Malicious  Suspicious     Safe      Suspicious
   |        |              |           |
Block and  Warn user      Close       Warn user
escalate   and verify                 and verify