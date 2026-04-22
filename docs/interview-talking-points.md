# Interview Talking Points
## GitOps for IAM Management — DevSecOps + ICAM Portfolio Project

Use this as a prep guide. The goal is to be able to speak fluently at three levels:
the policy/governance rationale, the technical implementation, and the operational outcome.
Most candidates can only do one. You can do all three.

---

## The 90-Second Project Summary

> "I built a GitOps pipeline for managing AWS IAM as infrastructure-as-code. The core idea is
> that every IAM role and policy change — instead of being made directly in the AWS console —
> has to go through a pull request, get scanned by automated security tools, get reviewed and
> approved by a human, and then get applied by the pipeline using a short-lived OIDC token.
> The whole thing is auditable end-to-end: Git history tells you who proposed what and when
> it was approved, CloudTrail tells you what actually happened in AWS, and a nightly drift
> detection job alerts you if anyone makes an out-of-band change. I mapped the whole thing
> to NIST 800-53 controls — AC-2, AC-6, CM-3, SI-7 — because I wanted it to be something
> I could actually walk an ISSO through, not just something that looks good on GitHub."

Tailor the last sentence depending on the role — for federal/cleared positions, name-drop
the specific controls. For commercial security engineering roles, emphasize the automation
and the no-static-keys architecture.

---

## Question: "Walk me through the project architecture."

**Lead with the problem, not the solution:**

"The problem I was solving is that most organizations treat IAM as something that gets
configured manually — someone logs into the console, makes a change, and there's no
consistent process for review or approval. That creates audit gaps, drift from the intended
security baseline, and no easy way to roll back a bad change. GitOps solves all three."

**Then walk the pipeline left to right:**

1. Engineer opens a PR with a Terraform change to an IAM role or policy
2. Automated scans run — Checkov for misconfigurations, tfsec for AWS-specific issues,
   and custom OPA policies for org-specific rules like blocking wildcard actions
3. `terraform plan` output is posted as a PR comment so reviewers can see exactly what
   will change without running anything themselves
4. A human approver — scoped by change class — reviews and approves
5. On merge to main, the pipeline authenticates to AWS via OIDC and runs `terraform apply`
6. CloudTrail captures everything that happens in AWS, Git captures everything that happened
   in the review process, and a nightly job checks for drift

**Close with the outcome:**

"The result is that IAM changes are treated with the same rigor as application code changes.
You have a complete chain of custody from idea to execution."

---

## Question: "How does this relate to Zero Trust?"

"Zero Trust has a few core principles that this project directly implements.

First, never trust, always verify — the pipeline never uses stored credentials. It uses OIDC
to get a short-lived token, and the trust policy on the AWS role is scoped to a specific
GitHub repository and branch. Even if someone compromised a different repo or branch, they
couldn't use it to trigger an IAM apply.

Second, least privilege — the OPA policy blocks wildcard actions at PR time. Permission
boundaries cap what any role can ever do regardless of what policies get attached later.
The pipeline service role itself only has IAM read/write — it can't touch compute or storage.

Third, assume breach — the drift detection is the assume-breach control. We operate on the
assumption that someone might make an unauthorized change, so we actively look for evidence
of it every night rather than assuming that if we didn't see it happen, it didn't happen."

---

## Question: "What's OPA and why did you use it instead of just relying on Checkov?"

"Checkov and tfsec are great for known-bad patterns — they check against CIS benchmarks
and AWS best practices that are already encoded in their rule sets. But they don't know
your organization's specific policies.

OPA with Conftest lets you write your own rules in a policy language called Rego. So I
wrote policies specific to this environment — for example, any policy that grants
`iam:PassRole` must include a Condition block that scopes what roles can be passed.
That's not a generic AWS best practice, it's a specific control requirement. Checkov
won't catch it. OPA will.

The other advantage is that OPA policies live in the same repo as the Terraform code,
so they're versioned and reviewed with the same process. You can't silently change a
policy without it going through a PR."

---

## Question: "Why OIDC instead of an IAM access key for the pipeline?"

"An IAM access key is a static credential — it doesn't expire, it has to be rotated
manually, and if it gets committed to the repo or exposed in logs, it's compromised until
someone notices and rotates it. That's a huge blast radius for a credential that has IAM
write access.

OIDC works differently. GitHub generates a signed JWT for each workflow run that identifies
the specific repo, branch, and job. AWS is configured to trust GitHub's OIDC provider and
will exchange that JWT for a short-lived role session. The token expires in an hour. There's
nothing to rotate, nothing to store, and nothing to leak that would be useful after the
workflow finishes.

This maps to NIST IA-5 — authenticator management — specifically the requirement to use
short-lived credentials for automated processes. It's also a CIS AWS benchmark requirement."

---

## Question: "How would you handle a break-glass emergency — someone needs IAM access right now?"

"This is a really important design question because if your governance process has no
emergency escape valve, people will route around it entirely during incidents.

The break-glass procedure is documented in the repo. A designated break-glass role exists
in AWS with elevated IAM permissions. Assuming it requires two conditions: MFA, and
approval from two people at the security team lead level or above. When the role is
assumed, it immediately triggers a CloudWatch alarm and a Slack alert to the security team.

Every action taken under the break-glass role is logged in CloudTrail with a distinct
session tag, so the post-incident review can pull exactly what was done. And within 24
hours of the incident being resolved, a cleanup PR is required — either formalizing the
emergency change through the normal pipeline, or reverting it. The break-glass assumption
event and the cleanup PR are linked in the audit trail.

The key principle is: emergency access is allowed, but it's never invisible."

---

## Question: "How does this map to NIST 800-53?"

"The project was designed with 800-53 in mind from the start because I wanted it to be
something that could support an ATO, not just a portfolio piece.

The core mapping is:

CM-3 is the most direct fit — the entire PR workflow is a technical implementation of
configuration change control. Who proposes, who reviews, who approves, documentation
of the decision — all of that is built into the process.

AC-2 covers account management — all roles are managed as code, every change is reviewed,
and the access review script supports the periodic review requirement.

AC-6 covers least privilege — OPA blocks wildcards, permission boundaries cap the ceiling,
and the pipeline role itself is scoped to IAM only.

SI-7 is drift detection — integrity verification that the live system matches the authorized
baseline.

AU-2 and AU-12 cover audit logging — Git history plus CloudTrail give you two independent
sources of truth for every change.

I have a full control mapping document in the repo that I can walk an ISSO or auditor
through directly."

---

## Question: "What would you add if you had more time?"

This question tests whether you understand the limitations of your own work. Pick 2-3 real gaps:

**Automated remediation of drift:**
"Right now drift detection alerts but doesn't remediate. The next step would be to
automatically open a PR when drift is detected — either proposing a Terraform change to
match the live state, or reverting the out-of-band change, depending on severity. That
closes the loop without requiring manual intervention."

**Just-in-time access:**
"The permission model is still relatively static — roles exist and are assumable at any
time. Integrating something like AWS IAM Identity Center with a JIT access workflow would
mean elevated roles only exist for the duration of a specific task and are revoked
automatically. That's a stronger posture than permanent role assumption."

**Automated access certification:**
"The access review script generates a report, but someone still has to read it and
take action. Integrating with a GRC tool or building a lightweight certification workflow
where role owners have to actively re-certify access quarterly would automate the
AC-2(3) periodic review requirement end-to-end."

---

## The Differentiating Statement

If you get a chance to summarize what makes this project different, use this:

"Most DevSecOps portfolio projects show that someone can wire up a pipeline.
This one shows that I understand why each gate in the pipeline exists — what control it
satisfies, what threat it mitigates, and how an auditor would evaluate it. That comes from
my background in compliance and continuous monitoring. I'm not just implementing security
tooling, I'm implementing a governance process that happens to be automated."

---

## Key Terms to Use Naturally

- Non-repudiation (Git + CloudTrail together)
- Chain of custody (PR → approval → apply → audit)
- Least privilege enforcement (OPA policies)
- Configuration drift (nightly detection job)
- Short-lived credentials / ephemeral tokens (OIDC)
- Policy-as-code (OPA/Conftest)
- Permission boundary (Terraform resource)
- Separation of duties (author ≠ approver ≠ executor)
- Break-glass procedure (emergency access)
- Access certification / periodic review (AC-2(3))
