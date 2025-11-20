# AF-TIMESTOMPING: Timestamp Manipulation Detection

## Overview
Detects timestamp manipulation (timestomping) by comparing Windows LNK shortcut metadata with MFT filesystem records. Attackers modify file timestamps but LNK files preserve original creation times, creating detectable contradictions.

## Detection Logic

**The Rule (rule_optimized.rq):**
1. Get LNK shortcut file's own creation time (`observableCreatedTime`)
2. Get LNK target metadata (target file path, MFT entry number)
3. JOIN with MFT entries using MFT entry number
4. Extract timestamps:
   - `lnkShortcutCreated` - When the .lnk shortcut file was created
   - `lnkTargetCreated` - Target file creation time recorded in LNK
   - `mftSiCreated` - MFT $STANDARD_INFORMATION (easily modified)
   - `mftFnCreated` - MFT $FILE_NAME (harder to modify)
5. **SPARQL Filter 1**: `lnkShortcutCreated != mftSiCreated`
   - Only return cases where LNK shortcut creation time differs from MFT $SI
6. **SPARQL Filter 2**: `lnkShortcutCreated ≈ mftFnCreated` (match at seconds level)
   - Reduce false positives by verifying LNK captured original time
   - Check if timestamps match at YYYY-MM-DDTHH:MM:SS level (ignoring milliseconds)
   - This is case-agnostic and works on any dataset

**Why This Works:**
- **True Timestomping**: When user creates a shortcut, it captures original time → LNK matches $FN → $SI was modified later
- **False Positive**: Legitimate file operations (downloads, extractions) → All 3 timestamps differ significantly → No timestomping
- Example: LNK: 01:10:37, $FN: 01:10:37.528, $SI: 10:15:43 → Timestomped!

**Example Contradiction:**
```
LNK Shortcut Created: 2025-03-04T01:10:37Z      ← When shortcut was made
MFT $SI Created:      2025-03-04T10:15:43.547Z  ← MODIFIED (fake)
MFT $FN Created:      2025-03-04T01:10:37.528Z  ← ORIGINAL (matches shortcut time!)

LNK Shortcut vs MFT $SI: 9+ hours difference
→ TIMESTOMPING DETECTED: File timestamp was changed after shortcut creation
```

## Stream Filter (stream_filter_timestomp.py)

**Purpose:** Reduce 1.7 GB MFT → 241 KB filtered data (99.99% reduction)

**Filter Logic:**
- **Pass 1**: Extract all `targetMftEntryNumber` values from LNK files
- **Pass 2**: Filter MFT to keep only entries where `entryNumber` matches LNK references AND has `created0x10` timestamp

**Why Needed:**
MFT has 707,047 entries but only ~69 have LNK shortcuts. Filtering extracts only relevant entries before SPARQL JOIN operation.

**Performance:**
- ~30 seconds for 1.7 GB MFT
- Constant 50 MB memory
- 99.99% reduction

## Detection Script (detect_timestomp_optimized.py)

**Purpose:** Load filtered artifacts into RDFlib and execute rule_optimized.rq

**Process:**
1. Load files (auto-detect from filter directory or specify paths):
   - `mft_lnk_filtered.jsonld` - Filtered MFT entries
   - `lnk_files.jsonld` - LNK shortcuts
2. Parse into RDFlib graphs
3. Execute rule_optimized.rq SPARQL query with two-layer filtering:
   - Fast JOIN on MFT entry number
   - Retrieve LNK shortcut creation time + MFT timestamps
   - **SPARQL Filter 1**: `lnkShortcutCreated != mftSiCreated` (detect discrepancy)
   - **SPARQL Filter 2**: `lnkShortcutCreated ≈ mftFnCreated` (reduce false positives)
4. Python displays results:
   - Show all timestamps for analysis
   - Calculate time differences for context
   - Display evidence of timestomping
5. Report timestomping instances

**Output:** Each detection shows LNK shortcut created time, LNK target created time, MFT $SI time, MFT $FN time, and evidence analysis

**Why SPARQL Does Filtering:**
Two-layer SPARQL filtering efficiently detects timestomping and eliminates false positives at query time. Python just displays results and calculates differences for context.

## Workflow

```bash
bash test_workflow.sh
```

**Manual Steps:**

```bash
# Step 1: Filter (optional for files > 100MB)
python3 stream_filter_timestomp.py \
  --mft mft_filled_honest.jsonld \
  --lnk lnk_filled_fixed.jsonld \
  --output-dir /tmp/timestomp/

# Step 2: Detect
python3 detect_timestomp_optimized.py /tmp/timestomp/
```

## Files
- `rule_optimized.rq` - SPARQL query with two-layer filtering (timestamp discrepancy + false positive reduction)
- `stream_filter_timestomp.py` - Pre-filter by MFT entry number
- `detect_timestomp_optimized.py` - Load graphs and run detection
- `test_workflow.sh` - Automated workflow
- `mft_filled_honest.jsonld` (1.7 GB) - Full MFT
- `lnk_filled_fixed.jsonld` (186 KB) - LNK shortcuts

## Example Detection

```
🚨 TIMESTOMPING DETECTED!

1. Timestamp Manipulation Detected
   Target File: C:\Users\ktams\Desktop\Confidential\password.docx

   Timestamps:
     LNK Shortcut Created: 2025-03-04T01:10:37+00:00
     LNK Target Created:   2025-03-04T10:15:43+00:00
     MFT $SI Created:      2025-03-04T10:15:43.547000+00:00
     MFT $FN Created:      2025-03-04T01:10:37.528000+00:00

   🚨 EVIDENCE:
     • $SI differs from $FN by 32706.0 seconds
     • LNK Shortcut matches $FN (diff: 0.5s)
     • Shortcut captured ORIGINAL time, $SI was modified

→ File created at 01:10:37, timestomped to 10:15:43
```

## Performance

| Input | Filter Time | Detection Time | Memory | Reduction |
|-------|-------------|----------------|--------|-----------|
| 1.7GB | ~30 sec     | < 5 sec        | 50 MB  | 99.99%    |

## Key Insight

**Fast Join + Two-Layer SPARQL Filtering:**
- SPARQL does fast JOIN on `entryNum` to retrieve timestamp data
- **Layer 1**: `lnkShortcutCreated != mftSiCreated` (detect timestamp discrepancy)
- **Layer 2**: `lnkShortcutCreated ≈ mftFnCreated` (reduce false positives)
- Python just displays results and calculates time differences for context
- Result: Fast query execution with case-agnostic detection done at database level
