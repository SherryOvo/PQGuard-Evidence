Portable analysis accepts --cpu, --witness, --gpu, --formal and --output absolute
directory arguments. Use strong_baseline and two_host_witness from Online Resource 4,
continuous_batching from Online Resource 6, and current from Online Resource 5.
derive_results.py recomputes all primary cell statistics and counts from raw records.
plot_results.py accepts --analysis-output and --figure-output and makes the three
primary comparison/trade-off figures. It requires numpy and matplotlib.
Independent state/signature verification uses the campaign-specific verify scripts
and public_material.json with the corresponding retained SQLite/WAL files. Make
working copies before opening SQLite: verification can checkpoint working WALs.
Full original handshakes are not exported for every performance cell, so these
verifiers do not constitute independent full-AKE or runtime-attestation verification.
