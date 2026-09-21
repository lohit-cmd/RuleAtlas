# Roadmap and release boundaries

## v0.1: runnable local foundation

Public-source ingestion, 25-source seed catalog, explicit source assessments, exact ATT&CK/keyword retrieval, original logic inspection, local source discovery, versioned ATT&CK support, exports, and tests.

## Next: semantic retrieval and review

- Optional local embeddings, with clear model/version and reproducible ranking.
- Engineer-labeled query/rule evaluation set; measure recall and ranking quality.
- Structured scenario requirements and evidence-backed semantic review with an uncertain outcome.
- Query-language-aware dependency expansion and field extraction.
- Per-rule review records tied to logic hashes so an upstream change invalidates stale validation.

## Next: maintenance and portability

- Changed-file ingestion and parsing checkpoints for very large repositories.
- Source maintenance snapshots from GitHub API, including archival/migration and actual rule diffs.
- Automated schema checks using each engine's official tooling.
- Replay validation against explicitly compatible datasets.
- Release packaging, Docker deployment, and authenticated multi-user hosting.

Automatic cross-language equivalence, measured true-positive rates, automatic deployment, exhaustive GitHub discovery, and comprehensive engine validation are not implemented in v0.1. RuleAtlas should never imply these guarantees through UI labels or scores.
