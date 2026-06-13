# resproj — LCS-based YARA signature generator

Automatic generation of YARA signatures for malware families, based on the
**Longest Common Subsequence (LCS)** of their binary samples. Given a set of
representative binaries from a single family, the tools extract byte sequences
shared across the samples and turn them into a YARA rule that can be used to
detect other members of that family.

The project is built around [`edlib`](https://github.com/Martinsos/edlib), a
C-backed library for fast Levenshtein distance and global/local sequence
alignment.

## Approach

Two generators are provided:

- **`baseline_lcs.py`** — Greedy pairwise reduction. All samples are loaded and
  truncated, a pairwise edit-distance min-heap is built, and the two closest
  sequences are iteratively merged into their common subsequence until a single
  LCS remains. The result is formatted as one YARA hex string with `[-]`
  wildcards inserted between non-contiguous bytes.

- **`lcs_v1.py`**:
  1. **Clustering** — samples are grouped with a union-find (DSU) structure
     based on the edit distance of their prefixes, so that distinct variants of
     a family are handled separately.
  2. **Pair selection** — within each cluster, a representative pair is chosen
     (e.g. the pair whose distance is closest to the cluster median).
  3. **Alignment** — global (Needleman-Wunsch) or local (sliding-window,
     Smith-Waterman-style `HW` mode, via `--local`) alignment extracts matching
     regions and converts them into YARA strings with bounded gaps `[min-max]`.
  4. **Filtering** — generic blocks are discarded (PE headers, null-byte runs,
     low-entropy or arithmetic sequences, blocks that are too short) to reduce
     false positives.

Each produced rule embeds metadata in its `meta:` block (family name, number of
strings, number of bounded gaps, hex byte count, and a per-stage timing
breakdown).

## Installation

Requires Python 3.9+.

```bash
pip install -r requirements.txt
```

## Usage

Point a generator at a directory containing one family's representative
binaries. The output rule is written to `signatures/<family>/<family>.yar`.

```bash
# Baseline generator
python codes/baseline_lcs.py path/to/family_dir -v --workers 4

# Refined generator (global alignment)
python codes/lcs_v1.py path/to/family_dir -v --workers 4

# Refined generator with local sliding-window alignment
python codes/lcs_v1.py path/to/family_dir --local -v --workers 4
```

Common options:

| Option | Description |
|---|---|
| `--truncate-bytes N` | Read up to N bytes per file (default: 1,000,000). |
| `--workers N` | Number of processes for distance computation (default: 0 = single process). |
| `--batch-size N` | Use only the first N files for training (`lcs_v1.py`). |
| `--local` | Use local sliding-window alignment instead of global (`lcs_v1.py`). |
| `-v` / `-vv` | INFO / DEBUG logging. |

## Repository structure

```
.
├── codes/
│   ├── baseline_lcs.py     # Greedy pairwise LCS generator
│   └── lcs_v1.py           # Clustering + alignment + filtering pipeline
├── analyses/               # Experiments and result sets (see below)
├── requirements.txt
└── README.md
```

### Analyses

The `analyses/` directory contains signature folders, compiled rules, scan
outputs

- **`analyse_sweep_param/`** — Parameter sensitivity study. Signatures generated
  while varying one parameter at a time: `cluster_sample_bytes`,
  `cluster_threshold`, `local_window_size`, `local_window_step`,
  `max_strings_per_cluster`, `min_block_bytes`, `min_block_size`, against a
  `baseline_parameters` reference
- **`analyse_selection_paires_med_close_far/`** — Effect of the
  pair-selection strategy within a cluster: `close`, `median`, and `far` pairs
  compared
- **`analyse_batch10/`** — Comparison between our `lcs_v1` generator and
  **VxSig** on batches of 10 samples, with malware/goodware match results and
  timing (`*_matches.txt`, `match_timing.json`)
- **`generation_signatures_on_50samples_lcs_v1/`** — Signatures produced
  by `lcs_v1` on 50 samples, with their compiled rules and match results against
  malware families and goodware

Reference families used throughout the experiments: `berbew`, `blackie`,
`doina`, `ibryte`, `neshta`, `pidgeon`, `salgorea`, `softcnapp`, `symmi`,
`virut`
