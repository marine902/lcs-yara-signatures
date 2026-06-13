"""
LCS to YARA Signature Generator.
Uses edlib for C-backed Levenshtein distance and edit distance computation
clusters samples with union-find, picks a median pair, and builds YARA hex strings from local alignments
"""

from __future__ import annotations
import argparse
import logging
import heapq
import edlib
import os
from time import monotonic
from typing import Dict, Tuple, List
from bisect import bisect_right
from multiprocessing import Pool
import signal
import sys
import statistics 

TRUNCATE_BYTES_DEFAULT = 1000000 

def read_truncated(sample_filepath: str, limit: int) -> bytes:
    """Reads a file up to a specified byte limit."""
    with open(sample_filepath, 'rb') as file:
        return file.read(limit)



def worker_init():
    """Instructs child processes to ignore SIGINT (Ctrl+C) so the parent can handle it."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)



# Could also be parallelized but clearly is not the main bottleneck
def collect_samples(samples_dirpath: str, limit: int, logger: logging.Logger) -> list[bytes]:
    """Loads and truncates all files within a specified directory."""
    samples_filepaths = [os.path.join(samples_dirpath, filename) for filename in sorted(os.listdir(samples_dirpath))]
    if not samples_filepaths:
        raise SystemExit(f"No files found in {samples_dirpath}")
    
    logger.info(f"Found {len(samples_filepaths)} files in '{samples_dirpath}'. Reading up to {limit} bytes each...")
    sequences: list[bytes] = []
    
    for idx, filepath in enumerate(samples_filepaths, 1):
        t0 = monotonic()
        data = read_truncated(filepath, limit)
        dt = monotonic() - t0
        logger.debug(f"[{idx}/{len(samples_filepaths)}] {os.path.basename(filepath)}: read {len(data)} bytes in {dt:.2f}s")
        sequences.append(data)
        
    logger.info(f"Loaded {len(sequences)} byte sequences.")
    return sequences



def pair_lcs(a: bytes, b: bytes) -> bytes:
    """
    Computes a common subsequence of a pair of sequences using edlib's extended CIGAR (Compact Idiosyncratic Gapped Alignment Report) path.
    Extracts only exact match runs ('=') from a Needleman-Wunsch global alignment.
    """
    res = edlib.align(a, b, mode="NW", task="path")
    cigar = res["cigar"]
    if cigar is None:
        return b""

    i = j = 0 # indexes that will respectively track the current position in the sequences A and B
    output = bytearray()
    run = 0
    
    for ch in cigar:
        if ch.isdigit(): # parsing the numbers
            run = run * 10 + (ord(ch) - 48)
            continue
        if run == 0:
            run = 1
            
        if ch == "=": # both sequences share the exact same bytes for the next [run] length
            output.extend(a[i:i+run])
            i += run
            j += run
        elif ch in ("X", "M"): # processed bytes align at this position but they are different
            i += run
            j += run
        elif ch == "I": # processed bytes exist in B but not in A
            j += run
        elif ch == "D": # processed bytes exist in A but not in B
            i += run
            
        run = 0
        
    return bytes(output)



def _compute_edit_distance_task(args: Tuple[int, int, bytes, bytes]) -> Tuple[int, int, int]:
    """Multiprocessing worker function for Levenshtein distance calculation."""
    i, j, a_bytes, b_bytes = args
    dist = edlib.align(a_bytes, b_bytes, mode="NW", task="distance")["editDistance"]
    return (dist, i, j)



def build_distance_heap(items: Dict[int, bytes], active_ids: set[int], pool=None) -> list[Tuple[int, int, int]]:
    """Generates a fresh pairwise distance min-heap for active sequences. O(N^2)"""

    heap: list[Tuple[int, int, int]] = []
    ids = list(active_ids)
    n = len(ids)

    tasks: List[Tuple[int, int, bytes, bytes]] = []
    for ix in range(n):
        i = ids[ix]
        for jx in range(ix + 1, n):
            j = ids[jx]
            tasks.append((i, j, items[i], items[j]))

    if pool and tasks: # mutli-processing
        for dist, i, j in pool.imap(_compute_edit_distance_task, tasks, chunksize=1):
            heap.append((dist, i, j))
    else: # single-process mode
        for i, j, a_bytes, b_bytes in tasks:
            dist = edlib.align(a_bytes, b_bytes, mode="NW", task="distance")['editDistance']
            heap.append((dist, i, j))

    heapq.heapify(heap)
    return heap






#parameters clustering

cluster_sample_bytes=10000 #take only the first 10KB of each sample to compute the distance for clustering to make distance computation more fast
cluster_threshold=0.8 #seuil behind it 2 samples are merged in the same cluster if their distance is whithin


def cluster_samples(sequences: list[bytes], logger: logging.Logger):
    '''
    group the sequences in cluster via union find
    two samples go into the same cluster if they are close enough based on cluster_threshold
    '''
    n=len(sequences)
    prefix= [s[:cluster_sample_bytes] for s in sequences]#take short prefix of each sample for fast distance computation 
    
    #each sample starts in its own cluster (own parent)
    parent=[]
    for i in range(n):
        parent.append(i)

    def find(x):
        while parent[x]!=x:
            parent[x]=parent[parent[x]]#path compression:skip one level to flatten the tree
            x=parent[x]
        return x
    
    def union(x,y):
        
        a=find(x)
        b=find(y)
        if a!=b:#merge only if they are in different clusters
            parent[a]=b


    all_distances={}
    for i in range(n):
        for j in range(i+1,n):
            #compute distance for pair on the short prefix
            d=edlib.align(prefix[i],prefix[j], mode="NW", task="distance")["editDistance"]
            all_distances[(i, j)] = d
    
    if all_distances:
        max_distance=max(all_distances.values()) 
    else:
        max_distance=0
    threshold_distance=cluster_threshold*max_distance

    for (i, j), d in all_distances.items():
        if d<=threshold_distance:
            union(i,j) #if similar close, merge the clusters of the 2 samples


    #regroup samples by cluster
    clusters={}
    for i in range(n):
        s=find(i)
        if s not in clusters:
            clusters[s]=[]
        clusters[s].append(i)
    
    result=list(clusters.values())
    logger.info(f"clustering results:{len(result)} clusters formed")
    return result





def k_lcs(sequences: list[bytes], *, logger: logging.Logger, workers: int) -> bytes:
    """
    Reduces [k] byte sequences to a single common subsequence using a 
    greedy min-heap approach. Iteratively merges the closest pair in-place.
    """
    if not sequences:
        return b""

    # Dictionary mapping sequence ID directly to its byte payload
    items: Dict[int, bytes] = {id: seq for id, seq in enumerate(sequences)}
    active = set(items.keys())

    total_steps = len(sequences) - 1
    pool = None
    if workers:
        pool = Pool(processes=workers, initializer=worker_init)

    step = 1
    try:
        # Loop until only one sequence (i.e., the final LCS) is left
        while len(active) > 1:
            # (Re)Build a fresh min-heap containing only valid active distances
            heap = build_distance_heap(items, active, pool)

            # Get the closest pair (eventual ties are resolved by picking the smallest IDs)
            dist, i, j = heapq.heappop(heap)

            logger.info(f"[step {step}] closest pair: ({i},{j}) |A|={len(items[i])} |B|={len(items[j])} d={dist}")

            # Compute LCS
            t0 = monotonic()
            lcs_ij = pair_lcs(items[i], items[j])
            logger.info(f"[step {step}] edlib LCS -> |LCS|={len(lcs_ij)} in {monotonic() - t0:.2f}s")

            # Overwrite the sequence with the smaller ID, delete the larger one
            keep_id, drop_id = (i, j) if i < j else (j, i)
            items[keep_id] = lcs_ij
            active.remove(drop_id)
            del items[drop_id]
            
            # Filter remaining sequences in-place (removing all bytes not present in the pair LCS found)
            if lcs_ij:
                allowed = set(lcs_ij)
                for k in active:
                    if k != keep_id:
                        items[k] = bytes(b for b in items[k] if b in allowed)

            step += 1

    except KeyboardInterrupt:
            # Catch the keyboard interrupt and terminate the pool instantly
            if pool is not None:
                pool.terminate() # Instantly kills workers without waiting for tasks to finish
                pool.join()
                pool = None      # Prevents the finally block from throwing an error
            raise # Re-raise the exception to be caught in main()

    finally:
        if pool is not None:
            pool.close() # End of the parallelizable part
            pool.join()  # Wait until all workers have finished their task

    last_id = next(iter(active)) # cleanly retrieving the last remaining item in active set
    return items[last_id]



#parameters for yara string 
min_block_bytes=8
min_unique_ratio=0.25
min_sequence_length=20
max_sequence_ratio=0.85
max_null_ratio=0.4

def clean_block(tokens: list[str]) -> list[str] | None:    
    '''
    filter for null bytes, header PE, block too small before returning the block as a yara string
    return None if block is too generic and return the cleaned block otherwise
    '''
    hex_tokens = [t for t in tokens if not t.startswith("[")]
    #filter if too small block to be useful
    if len(hex_tokens)<min_block_bytes:
        return None
    
    #filter if too many repeated bytes 
    unique_bytes=set()
    for t in hex_tokens:
        unique_bytes.add(t)
    unique_ratio = len(unique_bytes) / len(hex_tokens)
    if unique_ratio < min_unique_ratio:
        return None

    #filter if too many consecutive bytes
    byte_vals = []
    for t in hex_tokens:
        byte_vals.append(int(t, 16))
    
    seq_count=0
    for i in range(len(byte_vals)-1):
        if byte_vals[i+1]-byte_vals[i]== 1:
            seq_count+=1
    if len(byte_vals)>min_sequence_length and seq_count/(len(byte_vals)-1)>max_sequence_ratio:
        return None


    #filter if too many null bytes
    null_count=0
    for t in hex_tokens:
        if t == "00":
            null_count += 1
    null_ratio=null_count/len(hex_tokens)
    if null_ratio>max_null_ratio:
        return None
    
    #filter for PE header
    if len(hex_tokens)>=2 and hex_tokens[0]=="4d" and hex_tokens[1]=="5a": #PE header"MZ"
        #cut tokens
        for i, t in enumerate(tokens):
            if t=="5a":
                tokens = tokens[i+1:]
                break
    return tokens



def filter_yara_strings(strings: list[str], max_null_ratio: float = 0.3) -> list[str]:
    """
    second filters applied to the full yara strings produced by align_and_build_yara_strings
    remove strings that start with MZ, have mostly null bytes, have too few unique bytes or are arithmetic sequences
    """
    filtered=[]
    for s in strings:

        #parse the yara string back into a token list
        tockens=s.strip("{} ").split()
        bytes_only = [t for t in tockens if not t.startswith("[")]
        #skip if the string starts with the PE header
        if len(bytes_only) >= 2 and bytes_only[0] == '4d' and bytes_only[1] == '5a':
            continue
        
        if not bytes_only:
            continue

        #skip if more than half the bytes are null
        null_ratio = sum(1 for t in bytes_only if t == "00") / len(bytes_only)
        if null_ratio > 0.5:
            continue

        #skip if too many bytes are the same (very low entropy)
        unique_ratio = len(set(bytes_only)) / len(bytes_only)
        if unique_ratio < 0.10:
            continue

        #skip if the byte values increase by 1 almost every step
        byte_vals = [int(t, 16) for t in bytes_only]
        differences = [byte_vals[i+1] - byte_vals[i] for i in range(len(byte_vals)-1)]
        if len(differences) > 20 and sum(1 for d in differences if d == 1) / len(differences) > 0.85:
            continue

        filtered.append(s)
    return filtered










#yara string constructionparameters
min_block_size=12
max_gap_size=10
max_block_bytes=500
max_strings_per_cluster=30



def align_and_build_yara_strings(a: bytes, b: bytes, max_block_bytes: int = max_block_bytes) -> list[str]:

    #align shorter sequence to longer sequence (less gaps)
    if len(a)>len(b):
        a,b=b,a 
    
    result=edlib.align(a, b, mode="NW", task="path")
    cigar=result["cigar"]
    if cigar is None:
        return []
    
    #parse cigar into list of (operation,count)
    operations=[]
    run =0

    for ch in cigar:
        if ch.isdigit():
            run=run * 10 + (ord(ch) - 48)
        
        else:
            if run== 0:
                run=1
            operations.append((ch, run))
            run=0

    
    #tell the state for building yara strings
    strings=[]
    current_string=[]
    current_len=0
    in_gap=False
    gap_min=0
    gap_max=0
    i=0 #the current position in a


    def flush_gap():
        #write the accumulated gap as [min-max] and reset gap state
        nonlocal in_gap, gap_min, gap_max
        if in_gap:
            current_string.append("["+str(gap_min)+"-"+str(gap_max)+"]")
            in_gap=False
            gap_min=0
            gap_max=0


    def flush_block():
        #finish current block and add it to strings if large enough
        nonlocal current_string, current_len, in_gap, gap_min, gap_max
        if in_gap:
            in_gap=False
            gap_min=0
            gap_max=0
        if current_len>=min_block_size:
            tokens=current_string[:]
            #remove leading and ending spaces
            while tokens and tokens[0][0]=="[":
                tokens.pop(0)
            while tokens and tokens[-1][0]=="[":
                tokens.pop()
            #count actual bytes (not the gap tokens)
            byte_count=0
            for t in tokens:
                if t[0]!="[":
                    byte_count+=1
            if byte_count>=min_block_size:
                strings.append("{ " + " ".join(tokens) + " }")
        current_string.clear()
        current_len=0


    #go through the operations and build yara tokens
    for operation,count in operations:
        if i>=len(a):
            break
        if operation=="=":
            #we have a match so : write bytes to current block
            flush_gap()
            safe=min(count, len(a)-i)
            remaining_bytes=safe
            position=i
            while remaining_bytes>0:
                space=max_block_bytes-current_len
                chunk=min(space, remaining_bytes)
                for k in range(chunk):
                    current_string.append(f"{a[position+k]:02x}")
                current_len+=chunk
                position+=chunk
                remaining_bytes-=chunk
                if current_len>=max_block_bytes:
                    flush_block()#block full so we start a new one
            i+=safe
        elif operation=="X":
            #we have a mismatch so : same number of bytes on both sides, so: gap [n-n]
            safe=min(count, len(a)-i)
            if safe>max_gap_size:
                flush_block()#gap too large so we cut here
            else:
                if not in_gap:
                    in_gap=True
                    gap_min=safe
                    gap_max=safe
                else:
                    #we accumulate with previous gap operations
                    gap_min+=safe
                    gap_max+=safe
            i+=safe

        elif operation=="D":
            #deletion: bytes in a not in b, so : gap [0-n]
            safe=min(count, len(a)-i)
            if safe>max_gap_size:
                flush_block()
            else:
                if not in_gap:
                    in_gap=True
                    gap_min=0 #0 because bytes might be absent in b
                    gap_max=safe
                else:
                    #gap_min stays the same, just gap_max increases 
                    gap_max+=safe
            i+=safe
        elif operation=="I":
            #insertion: bytes in b and not in a, so : gap [0-n]
            if count>max_gap_size:
                flush_block()
            else:
                if not in_gap:
                    in_gap=True
                    gap_min=0 #0 because bytes might be absent in a
                    gap_max=count
                else:
                    gap_max+=count
            #i doesn't advance for insertions (no bytes consumed in a)
    flush_block()
    return strings



#local alignment parameters
local_window_size=1024 #size of each sliding window in bytes
local_window_step=512 #step between two consecutive windows (50% overlap)
local_min_match_ratio=0.4 #minimum fraction of window bytes that must match in b




def local_align_and_build_yara_strings(a: bytes, b: bytes, window_size: int = local_window_size, window_step: int = local_window_step, min_match_ratio: float = local_min_match_ratio) -> list[str]:
    """
    slide a window over a and for each position find the best matching region in b using HW mode
    if the window matches well enough we run a global alignment on the matched region to extract YARA strings
    we stop early once we have enough strings for the current cluster
    """
    strings=[]
    seen_offsets=set() #track positions in b we already processed to avoid duplicate strings

    for start in range(0, len(a)-window_size+1, window_step):
        window=a[start:start+window_size]
        try:
            result = edlib.align(window, b, mode="HW", task="path")
        except Exception:
            continue
        
        #return -1 if alignement failed
        if result["editDistance"] <0:
            continue


        #check the window matches b well enough
        match_ratio=1.0- result["editDistance"]/window_size
        if match_ratio<min_match_ratio:
            continue

        #find the location in b where the window match
        localisations=result.get("locations")
        if not localisations:
            continue
        b_start, b_end=localisations[0]

        #we skip if we already processed a window at this location in b
        if b_start in seen_offsets:
            continue
        seen_offsets.add(b_start)

        #we extract the matched region from b and build yara strings
        b_region=b[b_start:b_end+1]
        new_strings=align_and_build_yara_strings(window, b_region)
        strings.extend(new_strings)

        #stop if enough strings for this cluster
        if len(strings)>=max_strings_per_cluster:
            break

    return strings


    







def yara_format_lcs(lcs: bytes, sequences: list[bytes], *, bytes_per_line: int = 24) -> list[str]:
    """
    Formats raw bytes into a YARA hex string.
    Inserts '[-]' wildcards only between non-contiguous sequences.
    """

    def sequence_lcs_bytes_positions(sequence: bytes, lcs: bytes) -> list[int] | None:
        """Returns the leftmost index positions of 'lcs' as a subsequence within 'sequence'."""
        buckets = [[] for _ in range(256)] # an array of 256 empty lists (one for every possible byte value, 0x00 to 0xFF)
        # Reads an original sequence and logs the index position of every single byte into its corresponding bucket
        for idx, b in enumerate(sequence): 
            buckets[b].append(idx)
            
        pos = []
        curr_index = -1

        # Looks at that byte's bucket and uses bisect_right 
        for b in lcs:
            b_positions = buckets[b]
            k = bisect_right(b_positions, curr_index) # binary search function finding the next occurrence of the processed LCS's byte that is greater than the current index
            if k == len(b_positions):
                return None
            curr_index = b_positions[k]
            pos.append(curr_index)
            
        return pos
    
    if not lcs:
        return []
        
    positions: list[list[int]] = [] # Positions of LCS bytes in each input samples' respective byte sequences
    for sequence in sequences:
        sequence_positions = sequence_lcs_bytes_positions(sequence, lcs)
        if sequence_positions is not None:
            positions.append(sequence_positions)
    
    yara_strings = [] #store all the yara strings
    tokens: list[str] = [f"{lcs[0]:02x}"]
    
    for i in range(len(lcs) - 1):
        contiguous_in_all = all(p[i+1] == p[i] + 1 for p in positions) # checks whether the given pair of LCS bytes is present in all sequences in a contiguous manner
        
        if not contiguous_in_all:
            #compute the gap size in each training sample
            gaps = [p[i+1]- p[i] for p in positions]
            gap_min=min(gaps)
            gap_max=max(gaps)
            if gap_max>50:
                #if gap too large, we cut and start new yara string to avoid too many wildcards
                clean = clean_block(tokens)
                if clean is not None:
                    yara_strings.append(clean)
                tokens=[f"{lcs[i+1]:02x}"]#we start new block with the next byte of the lcs
            else:
                #we insert [min-max] for more fast matching
                tokens.append("["+str(gap_min)+"-"+str(gap_max)+"]")
                tokens.append(f"{lcs[i+1]:02x}")

        else:
            #no gap so just append the next byte
            tokens.append(f"{lcs[i+1]:02x}")
    
    
    clean = clean_block(tokens)
    if clean is not None:
        yara_strings.append(clean)

    #convert each list of tockens to yara hex string format
    return ["{ " + " ".join(t) + " }" for t in yara_strings]




def build_yara_rule_text(family: str,yara_strings: list[str], time_to_build: float, timing_breakdown: dict = None) -> str:
    """Constructs YARA rule string corresponding to the malware family signature."""
    
    #one $si per yara string from yara_format_lcs
    strings_block = ""
    for i, s in enumerate(yara_strings):
        strings_block += f"        $s{i} = {s}\n"
    
    #count bounded gaps and total hex bytes in the final signature
    total_bounded_gaps = sum(s.count("[") for s in yara_strings)
    total_hex_bytes = sum(
        len([t for t in s.strip("{} ").split() if not t.startswith("[")])
        for s in yara_strings
    )

    reported_time_to_build = f"{round(time_to_build, 2)} sec" if time_to_build < 60.0 else f"{round(time_to_build/60.0, 2)} min"
    
    #timing breakdown added to the meta block
    meta_extra = ""
    if timing_breakdown:
        for key, val in timing_breakdown.items():
            meta_extra += f'        {key} = "{round(val, 3)} sec"\n'
    
    return f"""rule {family}
{{
    meta:
        family = "{family}"
        time_to_build = "{reported_time_to_build}"
        nb_strings = "{len(yara_strings)}"
        nb_bounded_gaps = "{total_bounded_gaps}"
        nb_hex_bytes = "{total_hex_bytes}"
{meta_extra}    strings:
{strings_block}
    condition:
        any of them
}}"""




def main():
    ap = argparse.ArgumentParser(description="Malware family YARA signature generator, from k representative samples, based on the LCS (Longest Common Subsequence) algorithm")
    ap.add_argument("family_dirpath", type=str, help="Directory containing the family's representative binaries to build the signature from.")
    ap.add_argument("--truncate-bytes", type=int, default=TRUNCATE_BYTES_DEFAULT, help=f"Read up to N bytes per file (default: {TRUNCATE_BYTES_DEFAULT})")
    ap.add_argument("-v", "--verbose", action="count", default=0, help="-v: INFO, -vv: DEBUG")
    ap.add_argument("--workers", type=int, default=0, help="Number of processes to parallelize distance computation (default: 0)")
    ap.add_argument("--batch-size", type=int, default=None, help="Number of files to use for training (default: all)")
    ap.add_argument("--local", action="store_true", default=False,help="Use local alignment (sliding window HW mode) instead of global NW")
    args = ap.parse_args()

    level = logging.WARNING if args.verbose == 0 else (logging.INFO if args.verbose == 1 else logging.DEBUG)
    logging.basicConfig(level=level, format="%(asctime)s | %(levelname)-5s | %(message)s")
    logger = logging.getLogger("LCS")

    family_dirpath = args.family_dirpath
    if not os.path.isdir(family_dirpath):
        raise SystemExit(f"Not a directory: {family_dirpath}")
        
    family = os.path.basename(os.path.normpath(family_dirpath))
    logger.info(f"Family: {family}")
    logger.info(f"Input directory: {os.path.abspath(family_dirpath)}")
    logger.info(f"Truncation limit: {args.truncate_bytes} bytes")

    try:
        t_total_start = monotonic()
        
        #load training samples
        t0 = monotonic()
        sequences = collect_samples(family_dirpath, args.truncate_bytes, logger)
        t_load = monotonic() - t0
        
        if args.batch_size:
            sequences = sequences[:args.batch_size]
            logger.info(f"Using first {len(sequences)} files (batch-size={args.batch_size})")

        #cluster samples with DSU and pick a median pair per cluster
        t0 = monotonic()
        clusters = cluster_samples(sequences, logger)
        t_clustering = monotonic()- t0

        all_yara_strings = []
        t_pair_selection_total = 0.0
        t_alignment_total = 0.0
        t_filtering_total = 0.0
        
        for cluster in clusters:
            cluster_sequences = [sequences[i] for i in cluster]
            
            if args.local:
                #pick the pair whose distance is closest to the median distance in the cluster
                t_ps = monotonic()
                pairs = []
                for i in range(len(cluster_sequences)):
                    for j in range(i+1, len(cluster_sequences)):
                        d = edlib.align(cluster_sequences[i][:cluster_sample_bytes],
                                        cluster_sequences[j][:cluster_sample_bytes],
                                        mode="NW", task="distance")["editDistance"]
                        pairs.append((d, i, j))
                
                if len(pairs) == 0:
                    yara_strings = []
                    t_pair_selection_total += monotonic() - t_ps
                else:
                    medianne = statistics.median([d for d, i, j in pairs])
                    best_pair = min(pairs, key=lambda x: abs(x[0]-medianne))
                    _, i_medianne, j_medianne = best_pair
                    t_pair_selection_total += monotonic() - t_ps
                    
                    #run the local sliding window alignment on the selected pair
                    t_al = monotonic()
                    yara_strings = local_align_and_build_yara_strings(
                        cluster_sequences[i_medianne], cluster_sequences[j_medianne])
                    t_alignment_total += monotonic() - t_al
                    
                    #apply quality filters before adding the strings
                    t_fi = monotonic()
                    yara_strings = filter_yara_strings(yara_strings)
                    t_filtering_total += monotonic() - t_fi
            
            all_yara_strings.extend(yara_strings)

        time_to_build = monotonic() - t_total_start
        
        timing_breakdown = {
            "t_load": t_load,
            "t_clustering": t_clustering,
            "t_pair_selection": t_pair_selection_total,
            "t_alignment": t_alignment_total,
            "t_filtering": t_filtering_total,
        }
        

        if not all_yara_strings:
            logger.warning(f"no YARA strings generated for {family}")
            print(f"no signature for {family}")
        else:
            rule_text = build_yara_rule_text(family, all_yara_strings, time_to_build, timing_breakdown)
            family_signatures_dirpath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "signatures", family)
            os.makedirs(family_signatures_dirpath, exist_ok=True)
            output_filepath = os.path.join(family_signatures_dirpath, f"{family}.yar")
            with open(output_filepath, 'w') as file:
                file.write(rule_text)
            print(f"Wrote signature to {output_filepath}")


    except KeyboardInterrupt:
        logger.error("Execution interrupted by user (Ctrl+C). Shutting down...")
        sys.exit(1)

if __name__ == "__main__":
    main()
