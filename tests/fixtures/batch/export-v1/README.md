# Completed-batch export schema 1 golden payloads

Synthetic expected payloads for `../released-v0.5`, with all validation states
and raw CSV enabled. The test compares parsed JSON and exact CSV bytes.
Completion metadata is tested by recomputing payload digests and lengths instead
of freezing exporter build identity or measured scratch usage. No original
sample files or private machine paths are required.

The summary freezes retained-key ranking/ties, source-report references, selected-
range byte counts, presentation limits and empty outcome-reason behavior. These
are unreleased schema-1 additions; the released input fixture is unchanged.
