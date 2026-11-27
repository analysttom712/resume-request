# resume-request

Resume on request for [thomasbaynum.dev](https://thomasbaynum.dev). A recruiter fills in
name, email and company; I get an email with an **Approve** link; one click emails them my
resume. Nobody can download the resume without my approval, and requests delete themselves
after 30 days.

Built with AI assistance (Claude Code). I set the requirements, reviewed the design and
approve every merge.

## How it works

```
website form ──POST /request──▶ API Gateway (HTTP API, throttled) ──▶ Submit Lambda
                                                                       │ validate, store (DynamoDB, 30-day TTL)
                                                                       └▶ SES: email to me with signed Approve link
me ──GET /approve (confirm page)──▶ Approve Lambda ──POST /approve──▶ claim request once (DynamoDB condition)
                                                                       ├▶ read PDF from private S3 bucket
                                                                       └▶ SES: email the PDF to the requester
```

| Piece | Why |
|---|---|
| **SAM template** (`template.yaml`) | All infrastructure in one reviewable file; `sam deploy` turns it into a CloudFormation stack. |
| **API Gateway HTTP API** | One HTTPS endpoint with CORS limited to the website and route throttling (1 request/second, burst 5) so a script can't run up the bill. |
| **Two Lambda functions** (Python 3.13, arm64) | Standard library + boto3 only, so there is nothing to bundle or patch. Each has its own least-privilege role. |
| **DynamoDB** (on demand) | Holds pending requests. Time to Live deletes each one 30 days after it arrives. |
| **S3** (private) | Holds the PDF. All public access blocked, TLS required, versioned so an old resume can be restored. |
| **SES** | Sends from `resume@thomasbaynum.dev` with DKIM, SPF (custom MAIL FROM) and DMARC. Replies go to my Gmail. |
| **SSM Parameter Store** (SecureString) | Holds the key that signs approve links. Never in code or logs. |

### Controls, and the test that proves each one

| Control | How | Test |
|---|---|---|
| Forged links refused | Approve link carries an HMAC-SHA256 signature over request id + expiry, checked in constant time | `test_forged_link_is_refused` |
| Links expire | Signed expiry, 7 days | `test_expired_link_is_refused` |
| Each request sends once | Conditional update PENDING → SENDING; a second click or replay gets "already handled" | `test_reused_link_is_refused` |
| Link scanners can't approve | GET only shows a confirm page; only the button (POST) sends | `test_happy_path_sends_resume_once` |
| Data deleted after 30 days | DynamoDB TTL on every request item | `test_happy_path_sends_resume_once` |
| Bots and floods | Throttling, Origin check, hidden honeypot field, strict validation, one owner email per address per day, daily cap (20) | `test_honeypot_*`, `test_wrong_origin_*`, `test_same_address_*`, `test_daily_cap_*` |
| No personal data in logs | Logs record the request id only; 14-day retention | code review |

## Deploy

Prerequisites: AWS CLI v2 signed in (`aws login --profile <profile>`), Python 3.13.

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements-dev.txt aws-sam-cli
```

1. **Signing key** (once). CloudFormation can't create SecureString parameters, so create it
   from a random value that is never printed:

   ```powershell
   $key = .venv\Scripts\python -c "import secrets; print(secrets.token_urlsafe(48))"
   aws ssm put-parameter --name /resume-request/hmac-key --type SecureString --value $key --profile <profile> --region us-east-2
   Remove-Variable key
   ```

2. **Stack**: `.venv\Scripts\sam deploy --profile <profile>` (settings in `samconfig.toml`).
3. **Resume**: upload the PDF to the bucket named in the `ResumeBucketName` output, at the
   `ResumeKey` output path:
   `aws s3 cp <your-resume.pdf> s3://<bucket>/resume/Thomas-Baynum-Resume.pdf --profile <profile>`
4. **SES**: domain identity for `thomasbaynum.dev` with Easy DKIM and MAIL FROM
   `mail.thomasbaynum.dev`; the DNS records go in Cloudflare as **DNS only**. Until SES
   production access is granted, mail only reaches verified addresses.

Replacing the resume later is step 3 again; versioning keeps the previous copy for 90 days.

## Cost

At a handful of requests a month this is effectively $0: API Gateway HTTP API about $1 per
million requests, Lambda and DynamoDB on demand within their free allowances, SES about
$0.10 per 1,000 emails, S3 a few cents a year for one PDF. Throttling and the daily cap bound
the worst case.

## Safety checks

Same pattern as [total-rewards-analytics](https://github.com/analysttom712/total-rewards-analytics):

- `scripts/public_scan.py` blocks secrets, AWS keys and account IDs, home-folder paths,
  SSN-shaped numbers, PDFs and Office documents, and any word in the local blocklist.
- The pre-commit hook runs it on every commit: `git config core.hooksPath .githooks` once per clone.
- CI (`.github/workflows/checks.yml`) runs the scan, ruff, pytest and cfn-lint on every pull
  request and fails closed.
- The blocklist file `.scan-blocklist.local.txt` is gitignored; CI reads the same words from the
  `SCAN_BLOCKLIST` repository secret.

## Tests

```powershell
.venv\Scripts\python -m pytest
```

The tests run the real handlers against in-memory fakes of DynamoDB, SES, S3 and SSM
(`tests/fakes.py`), so they need no AWS account.
