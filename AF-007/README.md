# AF-007: Security Event Log Clearing Detection

## Overview
Detects anti-forensic deletion of Windows Security Event Logs by correlating Event 1102 (log cleared) with USN Journal evidence of Security.evtx file truncation and RecordNumber gaps.

## Detection Logic

**The Rule (RULE.rq):**
1. Find Event 1102 (log cleared) in Security Event Log with timestamp
2. Find USN Journal entries showing Security.evtx with DataTruncation BEFORE Event 1102
3. Calculate temporal correlation (USN modification within 60 seconds before Event 1102)
4. Check RecordNumber gaps (first record should be 1, not 5585)
5. Alert if temporal correlation exists: USN truncation + Event 1102 + RecordNumber gap

**Why This Works:**
- Event 1102 is logged when Security Event Log is cleared through Windows Event Viewer
- But attackers can directly truncate the .evtx file without triggering Event 1102
- USN Journal records ALL file operations including Security.evtx truncation
- USN cannot be easily cleared and preserves evidence even after log clearing
- RecordNumber gaps prove that events were deleted (starts at 5585 instead of 1)

**Three Detection Patterns:**
1. **USN Truncation** - Security.evtx modified with DataTruncation before Event 1102
2. **System Event Pairing** - Compare System logons (EventId 7001) with Security logons (EventId 4624)
3. **RecordNumber Gap** - First record not at 1 indicates deletion

## Stream Filter (stream_filter_evtx.py)

**Purpose:** Reduce 521 MB input → 1-5 MB filtered data (99%+ reduction)

**Filter Logic:**
- **Security Filter:** Keep only Event 1102 (log cleared) entries
- **USN Filter:** Keep only Security.evtx filename entries with any update reasons
- **System Filter:** Optional - keep System logon events for correlation

**Why Needed:**
Event logs can be hundreds of MB. Filtering extracts only Event 1102 and related USN evidence before running SPARQL detection.

**Performance:**
- Handles large event log files without memory issues
- ~100 MB/sec processing speed
- Constant 50 MB memory usage

## Detection Script (detect_af007_optimized.py)

**Purpose:** Load filtered artifacts into RDFlib named graphs and execute RULE.rq

**Process:**
1. Load filtered files:
   - `usn_security_filtered.jsonld` - USN Security.evtx operations
   - `security_1102_filtered.jsonld` - Event 1102 entries
   - `system_events.jsonld` - System logon events (optional)
2. Create RDFlib Dataset with named graphs for each artifact
3. Execute RULE.rq SPARQL query
4. Calculate temporal correlation and RecordNumber gaps
5. Report confidence level (HIGH/MEDIUM/LOW)

**Output:** Timeline showing USN truncation events before Event 1102 with confidence assessment

## Confidence Levels

**HIGH Confidence:**
- USN shows Security.evtx truncation BEFORE Event 1102
- Temporal correlation within 60 seconds
- RecordNumber gap > 100

**MEDIUM Confidence:**
- RecordNumber gap exists but no USN evidence
- Correlation gaps without file system proof

**LOW Confidence:**
- Only correlation gaps (possible audit policy disabled)

## Workflow

```bash
bash test_workflow.sh
```

**Steps:**
1. Filter large event log files to extract Event 1102 and USN Security.evtx entries
2. Run detection on filtered data
3. Report confidence level and evidence

**Manual Usage:**

```bash
# Step 1: Filter large files
python3 stream_filter_evtx.py \
  --usn usn_filled_all.jsonld \
  --security security_evtx_all_filled.jsonld \
  --system evtx_all_filled.jsonld \
  --output-dir /tmp/evtx_filtered/

# Step 2: Run detection
python3 detect_af007_optimized.py /tmp/evtx_filtered/

# Or specify files individually
python3 detect_af007_optimized.py \
  --usn /tmp/evtx_filtered/usn_security_filtered.jsonld \
  --security /tmp/evtx_filtered/security_1102_filtered.jsonld
```

## Files
- `RULE.rq` - SPARQL query correlating Event 1102 with USN truncation
- `stream_filter_evtx.py` - Pre-filter large event logs
- `detect_af007_optimized.py` - Load graphs and run detection
- `test_workflow.sh` - Complete automated workflow

## Example Detection

**HIGH Confidence Alert:**
```
🚨 AF-007 ALERT: Security Event Log Clearing Detected!

Alert Level: HIGH CONFIDENCE

Evidence Found:
  ✓ Event 1102 logged at 2025-09-11 05:57:31.848391
  ✓ USN truncation #1: 55.82 seconds BEFORE Event 1102
     - Timestamp: 2025-09-11 05:56:36.032933
     - Update Reasons: DataOverwrite|DataTruncation

  ✓ USN truncation #2: 22.34 seconds BEFORE Event 1102
     - Timestamp: 2025-09-11 05:57:09.505116
     - Update Reasons: DataOverwrite|DataExtend|DataTruncation

  ✓ RecordNumber Gap: 5,584 missing records
     - First RecordNumber: 5585 (expected: 1)

Timeline:
  05:56:36 → First USN truncation (DataOverwrite|DataTruncation)
  05:57:09 → Second USN truncation (DataOverwrite|DataExtend|DataTruncation)
  05:57:31 → Event 1102 logged (Security log cleared)

User Attribution:
  User: resea
  SID: S-1-5-21-2679750263-731459410-1187419055-1001
  Computer: DESKTOP-139UKNF
  Process ID: 1120

CONCLUSION:
  ✓ USN Journal proves Security.evtx was truncated
  ✓ Temporal correlation confirms tampering before Event 1102
  ✓ RecordNumber gap shows 5,584 events were deleted

  → Strong evidence of deliberate log clearing
```

## Key Achievement

**Cross-Artifact Correlation:** Even when Security Event Log is cleared, USN Journal preserves irrefutable proof of file system tampering. This demonstrates the power of correlating multiple independent data sources for anti-forensics detection.

## Performance

| Input Size | Filter Time | Detection Time | Memory | Reduction |
|------------|-------------|----------------|--------|-----------|
| 521 MB     | 2-3 min     | < 1 sec        | 50 MB  | 99%+      |
| 1 GB       | 5-7 min     | < 2 sec        | 50 MB  | 99%+      |
| 5 GB       | 25-35 min   | < 5 sec        | 50 MB  | 99%+      |

## Forensic Insights

**Why USN Journal is Critical:**
- Cannot be easily cleared without specialized tools
- Records ALL file operations including direct file truncation
- Preserves evidence even after Event Log clearing
- Provides independent verification of log tampering

**Timeline Reconstruction:**
The ~55 second gap between first USN truncation and Event 1102 reveals the attacker's process:
1. Direct file truncation (bypassing audit)
2. Additional modifications
3. Official log clearing through Windows API (triggers Event 1102)
