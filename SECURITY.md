# Security and evidence boundaries

This is an experimental defensive lab, not a production incident-response service.
Only use it in an isolated environment that you are authorized to administer.

The responder is a privileged security component even when it uses a managed
identity. Protect its source, deployment permissions and role assignments. No
secret is needed for a managed identity, but code execution under that identity
can still exercise its permissions. Monitoring is a detective control, not a
guarantee that misuse will be observed immediately.

Live manifests and unsanitized evidence belong in ignored `private/`. Credentials
stay in memory or environment variables and must never enter CLI arguments,
files, screenshots, Logic App run histories or Git. Do not publish raw evidence
without a separate redaction review. Token claims used by the harness are
metadata checks, not local cryptographic signature verification; Azure performs
the actual authorization.

The subscription confirmation and live ownership tag prevent common mistakes;
they are not a boundary against an administrator who can change tags, manifests
or code. Every experiment is restricted further to exact allowlisted IDs. There
is no automatic resource-group deletion or lock-removal response.

Please report an implementation issue through a GitHub issue containing only
sanitized reproduction details. Do not include credentials, live tenant data,
or a working production attack payload.
