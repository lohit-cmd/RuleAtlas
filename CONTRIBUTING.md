# Contributing

Contributions can improve source adapters, credibility evidence, retrieval quality, documentation, and test coverage.

## Adding a source

1. Identify the original public repository; document forks and migrations.
2. Supply evidence for all six checks, marking unknowns `needs_review`.
3. Record format, relevant paths, content type, dependencies, and license references.
4. Add original/minimal synthetic fixtures for parser behavior. Do not copy a third-party corpus into tests.
5. Run `python -m unittest discover -s tests -v`.
6. Describe actual validation performed and remaining uncertainty in the pull request.

An unreviewed source should not be automatically described as trusted. A validated parser does not mean its imported detections were validated. Contributor conduct should be respectful, specific, and evidence-based.

## Improving relevance

Use labeled scenario/rule pairs. Include plausible but incorrect matches, exact sub-technique mismatches, platform incompatibility, missing correlation steps and exclusions. Report retrieval precision/recall separately from detection fidelity. Preserve original source evidence and permit an uncertain result.
