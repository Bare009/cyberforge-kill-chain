"""Rule engine (FR-2, FR-3, B-4).

Loads rules/**/*.yaml and runs them over the parsed Parquet tables with polars.
Writes one detection row per rule hit, labelled with technique, tactic and
stage, and keeping the source lines behind it.
"""
