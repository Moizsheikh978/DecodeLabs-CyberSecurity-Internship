# Sample Phishing Analysis Report

## Sample 1: Legitimate Project Update

### Classification

**Safe / Low Risk**

### Red Flags Found

No major red flags were found.

### Analysis

The sender address and Reply-To address use the same domain.
The message does not create urgency and does not request a
password, payment, MFA code or other sensitive information.

The attached file is a PDF with a normal filename.

### Recommended Action

Close the triage event while continuing normal caution.

---

## Sample 2: Suspicious Password Reset

### Classification

**Malicious**

### Red Flags Found

1. The sender and Reply-To domains do not match.
2. The subject creates urgency.
3. The message claims that the password will expire.
4. The recipient is asked to verify the account.
5. The recipient is asked to sign in through a supplied link.
6. The link does not use HTTPS.
7. The link contains several suspicious words such as secure,
   login and update.
8. The familiar Microsoft name is used to create trust.

### Why the Message Is Unsafe

The message combines sender impersonation, urgency and a
credential-verification request. The supplied link may direct
the user to a fake login page designed to steal credentials.

### Recommended Action

Do not click the link. Block the sender and escalate the
message to the security team.

---

## Sample 3: Malicious Executive Payment Request

### Classification

**Malicious**

### Red Flags Found

1. The sender and Reply-To domains do not match.
2. The subject demands immediate action.
3. The message requests a wire transfer.
4. The message demands secrecy.
5. The recipient is told not to discuss the request.
6. The recipient is asked to bypass normal procedure.
7. The attachment uses the dangerous .iso extension.

### Why the Message Is Unsafe

The message uses authority, urgency, secrecy and financial
pressure. These techniques may be used in a business email
compromise attack.

The unexpected ISO attachment may also contain malicious files.

### Recommended Action

Do not transfer money or open the attachment. Verify the
request using a known internal telephone number. Block and
escalate the message.