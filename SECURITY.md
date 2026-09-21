# Security considerations

RuleAtlas v0.1 is a local evaluation application and binds only to localhost. It does not include multi-user authentication or a hardened public deployment stack.

Upstream files are untrusted input. The application uses safe YAML loading, does not execute imported Python/code, rejects XML entities, skips symlinks, bounds individual file sizes, validates public repository names, and renders upstream text using DOM text nodes. State-changing browser requests require a local session token and matching origin/host.

Only use repository caches created for this application: sync resets their working tree to the fetched revision. Do not edit or store original work in `data/cache/`.

API tokens belong in environment variables and are not persisted by the application. Remove sensitive context before sharing local exports or error reports. Keep dependency versions updated.

When creating the public GitHub repository, enable private vulnerability reporting and document the project's security contact. Report sensitive issues through that private channel, not a public issue containing secrets.
