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
