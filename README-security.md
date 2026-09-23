# Ideathon 2026 backend security

## Security audit

The workspace contained only static HTML and a live Apps Script URL; no backend source was available to audit. The browser performed MIME and size checks, but those are not security controls. The new `Code.gs` is the server-side implementation for the payload currently sent by `form.html`.

### Findings and required changes

- **Critical:** Backend source was absent from the repository, so server-side validation, authorization, duplicate prevention, and file controls could not be verified. Deploy `Code.gs` as the only public handler.
- **Critical:** Never put spreadsheet IDs, Drive folder IDs, service credentials, or Turnstile secrets in HTML. Store them as Script Properties.
- **High:** Client-provided filenames, MIME types, and extensions are untrusted. `Code.gs` checks all three, decodes the bytes, checks PDF/JPEG/PNG magic bytes, enforces one file and a 10 MB decoded limit, and generates the stored filename from a server-generated registration ID.
- **High:** `Code.gs` strictly validates the complete payload, nested objects, types, lengths, email, phone, team size, member count, degree allowlist, track allowlist, and unknown fields.
- **High:** Duplicate detection, ID generation, file creation, and sheet append run under `LockService`. Duplicate email or phone submissions are rejected.
- **High:** Drive files are created in a configured private folder and explicitly set to private. Do not share that folder or its files with the public.
- **High:** Configure Turnstile. If `TURNSTILE_SECRET_KEY` exists, a valid `turnstileToken` is required and verified server-side. The current form does not send a token, so add the Turnstile widget/token to the form before setting the secret.
- **Medium:** Apps Script Web Apps do not provide reliable client IP information or configurable CORS headers. The endpoint uses a script-cache identity rate limit (email + phone), which is useful but not a complete bot defense.
- **Medium:** Registration data must be escaped when rendered in any admin page. Never insert sheet values with `innerHTML`; use `textContent` or a framework's escaped rendering.
- **Low:** The public response contains only success, a registration ID, or a generic error. Detailed exception text is sent to Apps Script logs with a correlation ID.

## Script Properties

Set these in **Project Settings > Script properties**. Do not commit values to source control.

- `REGISTRATION_SHEET_ID`: ID of the registration spreadsheet.
- `REGISTRATION_SHEET_NAME`: Exact worksheet tab name.
- `PAYMENT_FOLDER_ID`: ID of a private Drive folder owned by the deployment account.
- `TURNSTILE_SECRET_KEY`: Cloudflare Turnstile secret. Strongly recommended for a public endpoint.

The worksheet must use this column order, with a header row:

`Registration ID, Timestamp, Leader Name, Leader Email, Leader Phone, College, Degree Program, Team Size, Team Name, Members JSON, Innovation Track, Payment Proof File ID`

The file ID stays in the private sheet for administrators and is never returned to the browser.

## Deployment

1. Run the Apps Script as the owner account that owns the spreadsheet and Drive folder.
2. Deploy as a Web App with **Execute as: Me** and **Who has access: Anyone** only if a public custom frontend is required. Do not grant the script project or spreadsheet to anonymous users.
3. Use the `https://script.google.com/macros/s/.../exec` URL only. Do not use HTTP.
4. Keep the frontend request as a simple `text/plain` POST. Apps Script ContentService cannot reliably emit a restrictive CORS policy. A same-origin backend proxy is safer because it can enforce `Origin`, CORS, WAF rules, request limits, and CAPTCHA before forwarding to Apps Script.
5. Restrict the Drive folder to the owner/admin group. Verify an anonymous browser cannot list, download, rename, or delete an uploaded file.
6. Set Apps Script and Google account audit logging/alerts, and review quotas and failed requests before launch.

## Final pre-launch checklist

- [ ] `Code.gs` is the deployed version and the deployment URL is current.
- [ ] Script Properties are set, private, and not present in frontend source.
- [ ] Turnstile is installed in the frontend and `TURNSTILE_SECRET_KEY` is configured.
- [ ] Invalid JSON, missing fields, extra fields, wrong types, oversized bodies, and oversized base64 files are rejected.
- [ ] Polyglot/renamed files are rejected by magic-byte and MIME/extension checks.
- [ ] PDF, JPEG, PNG, duplicate email, duplicate phone, and team sizes 1 through 6 are tested.
- [ ] Team member count is tested for zero, too few, and too many members.
- [ ] Drive permissions are private and the deployment executes as the owner.
- [ ] Sheet and Drive IDs are absent from all frontend files.
- [ ] Admin display uses escaped text and safe download links.
- [ ] Rate limiting and Turnstile failures return generic messages only.
- [ ] Production traffic uses HTTPS and the endpoint is protected by a same-origin proxy/WAF where practical.
- [ ] Logs are monitored without logging payment contents, credentials, or full request bodies.
