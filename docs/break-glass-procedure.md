# Break-Glass Procedure
## Emergency IAM Access — GitOps IAM Pipeline

**Last reviewed:** 2024-01-01
**Owner:** Security Team
**NIST 800-53:** AC-2(2), IR-6, AU-9

---

## What is Break-Glass Access?

Break-glass is an emergency procedure for situations where the normal GitOps pipeline cannot be used — for example, during a production incident requiring immediate IAM changes, or when the pipeline itself is broken.

Break-glass access is **always logged, always time-limited, and always requires post-incident remediation**. It is never routine.

---

## When to Use Break-Glass

Use break-glass only when ALL of the following are true:

- An active incident is declared (incident ticket exists)
- The normal GitOps PR process cannot meet the time requirement
- At least two senior security team members are available to authorize

Do NOT use break-glass for:
- Convenience (normal PR "takes too long")
- Routine changes that were forgotten
- Testing or development

---

## Break-Glass Role

```
ARN: arn:aws:iam::<ACCOUNT_ID>:role/break-glass-admin-prod
```

Assuming this role requires:
- MFA device present
- Approval from two members of the security team
- An active incident ticket number

---

## Procedure

### Step 1 — Declare an incident

Open an incident ticket in your tracking system. Record:
- Time of incident declaration
- Nature of the emergency
- Who declared the incident

### Step 2 — Get dual authorization

Contact two members of the security team. Both must:
- Acknowledge the emergency in the incident ticket
- Record their name, time, and the specific IAM change being authorized

This dual authorization is the technical equivalent of two-person integrity (TPI).

### Step 3 — Assume the break-glass role

```bash
# This will trigger an immediate CloudWatch alarm and Slack alert
aws sts assume-role \
  --role-arn arn:aws:iam::<ACCOUNT_ID>:role/break-glass-admin-prod \
  --role-session-name "break-glass-$(date +%Y%m%d-%H%M)-INCIDENT-<TICKET_ID>" \
  --serial-number arn:aws:iam::<ACCOUNT_ID>:mfa/<YOUR_USERNAME> \
  --token-code <MFA_TOKEN>
```

The session name **must** include the incident ticket ID. This links the CloudTrail session to the incident record.

### Step 4 — Make only the minimum necessary change

Document every action taken during the break-glass session in the incident ticket before you take it.

### Step 5 — Notify the security team

Immediately notify the security team channel that break-glass access has been activated, even if the alarm already fired.

### Step 6 — End the session

Close the terminal session as soon as the minimum necessary change is made. Do not retain the role credentials.

---

## Post-Incident Requirements (within 24 hours)

1. **Open a cleanup PR** — Either formalize the break-glass change in Terraform, or revert it. The PR description must reference the incident ticket.

2. **Write an incident summary** — What happened, what changed, why the normal pipeline couldn't be used.

3. **CloudTrail review** — Pull all IAM API calls from the break-glass session and verify they match what was authorized in the incident ticket.

4. **Close the incident ticket** with a link to the cleanup PR and the CloudTrail review.

---

## What Gets Logged Automatically

Every action taken under the break-glass role appears in CloudTrail with:
- The session name (which includes the incident ticket ID)
- The exact IAM API call
- The before/after state of any modified resource
- A timestamp

Additionally, CloudWatch triggers an alarm the moment the role is assumed, which:
- Posts to the `#security-alerts` Slack channel
- Opens a GitHub Issue tagged `break-glass` and `incident`
- Sends an email to the security distribution list

---

## Quarterly Break-Glass Test

The break-glass procedure must be tested quarterly to ensure it works when needed. Tests must be:
- Scheduled in advance
- Announced to the security team
- Conducted in a non-production account
- Documented in `docs/access-reviews/`

---

## Reference

| Item | Value |
|---|---|
| Break-glass role ARN | `arn:aws:iam::<ACCOUNT_ID>:role/break-glass-admin-prod` |
| CloudWatch alarm | `break-glass-role-assumption` |
| Security Slack channel | `#security-alerts` |
| Incident tracking | Your ticketing system |
| Maximum session duration | 1 hour |
| Post-incident deadline | 24 hours |
