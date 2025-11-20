# AF-002: Selective Browser History Deletion Detection

## Overview
Detects when a user selectively deletes specific websites from Chrome browsing history while leaving IndexedDB artifacts intact.

## Detection Logic

**The Rule (RULE.rq):**
1. Find domains in MFT IndexedDB folders (e.g., `https_www.youtube.com_0.indexeddb.leveldb`)
2. Check if domain exists in Chrome History SQLite database
3. If domain NOT found in History, check USN Journal for History file tampering
4. Alert if all three conditions met: Domain in IndexedDB + Missing from History + USN tampering evidence

**Why This Works:**
- When users visit websites, Chrome stores data in both History DB and IndexedDB
- Deleting from History UI only removes database entries, not IndexedDB artifacts
- USN Journal records all file modifications including History file changes

## Stream Filter (stream_filter_af002.py)

**Purpose:** Reduce 2.3 GB input → 0.11 MB filtered data (99.99% reduction)

**Filter Logic:**
- **MFT Filter:** Keep only files with "IndexedDB" in path → Extract domain names
- **USN Filter:** Keep only "History" filename with tampering flags (DataTruncation/DataOverwrite/DataExtend)
- **History:** Copy entire file (already small at 13 KB)

**Why Needed:**
SPARQL queries on 2.3 GB take too long and consume excessive memory. Streaming filter extracts only relevant evidence before detection.

## Detection Script (detect_af002.py)

**Purpose:** Load filtered artifacts into RDFlib named graphs and execute RULE.rq

**Process:**
1. Create RDFlib Dataset with 3 named graphs:
   - `urn:graph:mft` - MFT IndexedDB entries
   - `urn:graph:history` - Chrome History URLs
   - `urn:graph:usn` - USN History modifications
2. Parse each JSON-LD file into its graph
3. Execute RULE.rq SPARQL query across all graphs
4. Report contradictions found

**Output:** Lists each domain with IndexedDB evidence but missing from History + USN tampering proof

## Workflow

```bash
bash run_af002_workflow.sh
```

**Steps:**
1. Check if large JSON-LD files exist (case2all.jsonld, usncase2all.jsonld)
2. Run stream filter to extract relevant entries
3. Execute detect_af002.py on filtered data
4. Report results

## Files
- `RULE.rq` - SPARQL query defining detection logic
- `stream_filter_af002.py` - Pre-filter large artifacts
- `detect_af002.py` - Load graphs and run detection
- `run_af002_workflow.sh` - Complete automated workflow

## Example Detection

```
Contradiction #1:
  Domain:       youtube.com
  MFT File:     .\Users\...\IndexedDB\https_www.youtube.com_0.indexeddb.leveldb
  USN Evidence: DataOverwrite|DataExtend|DataTruncation

CONCLUSION: Domain exists in IndexedDB folders (MFT)
            BUT missing from Chrome History database
            AND USN Journal shows History file modification
```

This indicates the user visited youtube.com (IndexedDB proof), manually deleted it from browser history (missing from History DB), and the deletion was captured in the USN Journal.
