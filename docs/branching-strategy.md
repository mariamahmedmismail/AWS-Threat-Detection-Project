# Branching Strategy

**Project:** DEPI Project 4 - AWS Threat Detection, Monitoring, Incident Response and Forensics
**Owner:** Ganna | **Version:** 1.0

## 1. Rules

- `main` is always the submitted state. Nobody commits directly to it.
- Every change goes through a pull request (PR) from a short-lived branch.
- Every PR is reviewed by the author's pair before it is merged (see section 4).
- Merge with **Squash and merge**, so `main` keeps one clean commit per PR.
- Delete the branch after merging.

## 2. Branch names

| Pattern | Used for | Example |
|---|---|---|
| `week1/<topic>` | Week 1: logging and audit | `week1/athena-queries` |
| `week2/<topic>` | Week 2: threat detection | `week2/mitre-mapping` |
| `week3/<topic>` | Week 3: incident scenarios | `week3/ec2-playbook` |
| `week4/<topic>` | Week 4: automation and notifications | `week4/lambda-quarantine` |
| `docs/<topic>` | Reports, diagrams, README | `docs/final-report` |
| `fix/<topic>` | Fixes after the 28 Nov scope freeze | `fix/readme-typo` |

## 3. Commit messages

Start with a short verb phrase in the present tense, for example `Add Athena saved queries`
or `Fix retention rule description`. One logical change per commit.

## 4. Review pairs

| Author | Reviewer |
|---|---|
| Ganna | Menna |
| Menna | Ganna |
| Mariam | Esraa |
| Esraa | Mariam |
| Muhammad | Abdullah |
| Abdullah | Muhammad |

## 5. Workflow

1. `git checkout main` and `git pull`.
2. `git checkout -b week1/<topic>`.
3. Commit your work, then `git push -u origin week1/<topic>`.
4. Open a PR into `main`. Tag your reviewer.
5. The reviewer approves, or asks for changes.
6. Squash and merge, then delete the branch.

## 6. Safety rules

- **Never commit secrets.** No access keys, passwords or account credentials in files, scripts or screenshots.
  Blur or remove account IDs in screenshots.
- Rotate any test key immediately after use.
- The CI workflow scans every PR for secrets and checks Markdown formatting.

## 7. Dates

| Date | Rule |
|---|---|
| 28 Nov | Scope freeze. Only fixes and documentation after this |
| 30 Nov | Implementation merged to `main` |
| 4 Dec | Final submission |
