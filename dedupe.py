import sys
import networkx as nx
from networkx.algorithms import bipartite
import matplotlib.pyplot as plt
import cPickle as pickle
import string
import json
import re
from optparse import OptionParser
import pprint       #used for debug only
import pdb          #used for debug only
#sys.path.append('/users/doug/SW_Dev/dedupe/')


#-------------------------------------------------
#
# To Do:
#
#       1) Update command line parsing.  Replace with argparse since optparse depricated as of Python 2.7
#       2) Optimize detected subgraphs
#       3) Clean-up handling of Globals, CONVERT MAPS TO CLASSES
#       4) Deallocate unused datastructures after pickling, where appropriate.
#
# Generall Approach
#
#       1) Gather file and sub-file signatures (MD5)
#            md5deep -r -o f /Users/doug > file_hashes.out
#            md5deep -r -o f -p 1m /Users/doug > file_1m_subhashes.out
#            sort --key=1,32 file_hashes.out > file_hashes_sorted.out
#
#       2) Identify same-file dedupe candidates
#            Since file signatures were pre-sorted by signature, dedupes
#            are simply sequences of files sharing the same signature
#
#       3) Identify sub-file dedupe candidates
#          A) Compute vectors (edge sets)
#             i)  map file names and unque signatures to numbers to reduce
#                 data footprint during subsequent processing
#             ii) Filter vector set
#                 a) Single block files (single signature) since these are
#                    already covered by file-level dedupe
#                 b) Only one vector per same-file duplicates set
#                 c) remove singleton signatures -- sub-file hash must be
#                    present in multiple files to be relevant for subsequent
#                    graph based analusis
#          B) Graph based analysis using Networkx
#             i)   Construct bipartite graph nodes =(files, checksums)
#             ii)  Identify connected sub-graphs
#             iii) Optimize sub-graphs
#                  a) Determine whether checksums are mutually compatible (ie: non-overlapping ranges)
#                     1) if so, combine all checksums as common parent
#                     2) if not, determine most important checksums, also,
#                        determine if should partition graph
#
#
#   Proposed approach for sub-graph grouping
#   create set of checksums that have highest affinity,
#   starting with most popular checksum.  make sure that offsets don't collide.

#------------------------------------------------------------------


#-----------------------------------
# Global Variables
#-----------------------------------
           
global display_graph_flag
global B

#------------------------------------
# Misc helper func
#------------------------------------

def pload(fname):     
    "load datastructure from pickle format file"
    print 'pickle load ' + fname
    fd = open(fname, 'r')
    val = pickle.load(fd)
    fd.close()
    return val

def pdump(val, fname):     
    "write out datastructure in pickle format"
    if fname :
        print 'pickle dump ' + fname
        fd = open(fname, 'w+')
        pickle.dump(val, fd)
        fd.close()

def jload(fname):     
    "loads datastructure from JSON format file"
    fd = open(fname, 'r')
    val = json.load(fd)
    fd.close()
    return val

def jdump(val, fname, pretty=False):
    "write out datastructure to file in JSON format"
    if fname: 
        fd = open(fname, 'w+')
        if pretty:
            json.dump(val, fd, indent=4)
        else:
            json.dump(val, fd)            
        fd.close()

def dprint(val, debug, nl=False):
    "print debug output"
    if not debug:
        return
    if nl:
        print
    print val

def dpprint(val, debug, nl=False):
    "pretty-print debug output"
    if not debug:
        return
    if nl:
        print
    pprint.pprint(val)

def parse_fname(text):
    return string.rsplit(text, '.', 1)
    
        
#--------------------------------------
# File level deduplication
#--------------------------------------

#parse entry in format hash filename
md5deep_file_re    = re.compile("([0-9abcdef]+)\s+(\S.+)$")

def parse_md5deep_file_entry(text) :
    "parses individual lines from md5deep"
    parse = md5deep_file_re.search(text)
    if parse :
        return(parse.groups()[0],
               parse.groups()[1])
    else:
        print 'not found: ' + text
        exit()

def identify_duplicates(fname) :
    "fname composed of lines containing <filename> <hash> where lines sorted by hash"
    duplicates = []
    fd = open(fname)
    last_val = ""
    file_set = []
    for text in fd:
        (val, name) = parse_md5deep_file_entry(text)
        
        if val <> last_val :
            if len(file_set) > 1 :
                duplicates.append(file_set)
            last_val = val
            file_set = []
        file_set.append(name)
            
    if len(file_set) > 1 :
        duplicates.append(file_set)
        
    fd.close()
    return duplicates

def create_duplicate_map (duplicates) :
    "creates a duplicate map, indexed by first duplicate file"
    dup_map = {}
    for dup_group in duplicates :
        primary = dup_group.pop()
        for secondary in dup_group:
            dup_map[secondary] = primary
    return dup_map

def find_duplicateFiles(d_file, pickle_duplicates_fname=False,
                        json_duplicates_fname=False,
                        debug=False,
                        status=True) :
    "find all duplicate files based on sorted MD5 hashes"

    dprint('identify duplicates', status)
    duplicates = identify_duplicates(d_file)
    
    dprint('dumping duplicates data structures', status)
    pdump(duplicates, pickle_duplicates_fname)
    jdump(duplicates, json_duplicates_fname)
    return duplicates


#---------------------------------------------------
# Tables for mapping fname and hash values to numeric keys
#---------------------------------------------------


class FnameMap(object):
    """
    Class for mapping file names to numeric key
    >>> FnameMap.reset()
    >>> FnameMap.get_id('aaa')
    0
    >>> FnameMap.get_id('bbb')
    1
    >>> FnameMap.get_id('ccc')
    2
    >>> FnameMap.get_name(0)
    'aaa'
    >>> FnameMap.get_name(1)
    'bbb'
    >>> FnameMap.get_name(2)
    'ccc'
    >>> FnameMap.get_name_using_encoded_id('F:2')
    'ccc'
    >>> FnameMap.reset()
    >>> FnameMap.get_id('ddd')
    0
    >>> FnameMap.get_name(0)
    'ddd'
    >>> FnameMap.reset()
    """

    map2val = []  #maps id to file name
    
    @classmethod
    def get_id(cls, text) :
        "Maps file names to unique file numbers and maintains mapping tables"
        idx = len(cls.map2val)
        cls.map2val.append(text)
        return idx
    
    @classmethod
    def get_name(cls, idx) :
        return cls.map2val[idx]

    @classmethod
    def get_name_using_encoded_id(cls, eidx):
        return cls.map2val[cls.decode(eidx)]
    
    @classmethod
    def reset(cls):
        cls.map2val = []

    @staticmethod
    def encode(idx):
        """
        adds type prefix to fno -- ensures uniqueness since fno
        and hno share same node namespace
        >>> FnameMap.encode(1)
        'F:1'
        """
        return 'F:{}'.format(idx)

    @staticmethod
    def decode(text):
        """
        strip off prefix and return numeric value
        >>> FnameMap.decode('F:1')
        1
        """
        (node_type, idx) = string.rsplit(text, ':', 1)
        return int(idx)



class ChecksumMap:    
    """
    Class for mapping checksum values to numeric key, and maintaining counts
    >>> ChecksumMap.reset()
    >>> ChecksumMap.get_id({'c':'aaa', 'r':'x'})
    0
    >>> ChecksumMap.get_id({'c':'bbb', 'r':'y'})
    1
    >>> ChecksumMap.get_id({'c':'ccc', 'r':'z'})
    2
    >>> ChecksumMap.get_id({'c':'bbb', 'r':'y'})
    1
    >>> ChecksumMap.get_id({'c':'ccc', 'r':'z'})
    2
    >>> ChecksumMap.get_id({'c':'bbb', 'r':'y'})
    1
    >>> ChecksumMap.get_hval(0)
    {'c': 'aaa', 'r': 'x'}
    >>> ChecksumMap.get_hval(1)
    {'c': 'bbb', 'r': 'y'}
    >>> ChecksumMap.get_hval(2)
    {'c': 'ccc', 'r': 'z'}
    >>> ChecksumMap.get_count(0)
    1
    >>> ChecksumMap.get_count(1)
    3
    >>> ChecksumMap.get_count(2)
    2
    >>> ChecksumMap.reset()
    >>> ChecksumMap.get_id({'c':'ddd', 'r':'q'})
    0
    >>> ChecksumMap.get_hval(0)
    {'c': 'ddd', 'r': 'q'}
    >>> ChecksumMap.get_count(0)
    1
    >>> ChecksumMap.get_encoded_id({'c':'eee', 'r':'r'})
    'H:1'
    >>> ChecksumMap.get_hval_using_encoded_id('H:1')
    {'c': 'eee', 'r': 'r'}
    >>> ChecksumMap.get_range_using_encoded_id('H:1')
    'r'
    >>> ChecksumMap.reset()
    """

    map2idx = {}
    map2hval = []
    counts = []

    @classmethod
    def get_id(cls, hval) :
        "Maps hashes to unique hash numbers and maintains mapping tables"
        fingerprint = hval['c']+hval['r'] #include range in checksum name
        if fingerprint in cls.map2idx:
            idx = cls.map2idx[fingerprint]
            cls.counts[idx] += 1
            return idx
        else :
            idx = len(cls.map2hval)
            cls.map2idx[fingerprint] = idx
            cls.map2hval.append(hval)
            cls.counts.append(1)
            return idx
        
    @classmethod
    def get_encoded_id(cls, hval):
        return cls.encode(cls.get_id(hval))
        
    @classmethod
    def get_hval(cls, idx) :
        return cls.map2hval[idx]

    @classmethod
    def get_hval_using_encoded_id(cls, eidx):
        return cls.map2hval[cls.decode(eidx)]
        
    @classmethod
    def get_range_using_encoded_id(cls, eidx):
        return cls.map2hval[cls.decode(eidx)]['r']
    
    @classmethod
    def get_count(cls,idx) :
        return cls.counts[idx]
    
    @classmethod
    def reset(cls):
        cls.map2idx = {}
        cls.map2hval = []
        cls.counts = []

    @staticmethod
    def encode(idx):
        """
        adds type prefix to hno -- ensures uniqueness since fno
        and hno share same node namespace
        >>> ChecksumMap.encode(1)
        'H:1'
        """
        return 'H:{}'.format(idx)

    @staticmethod
    def decode(text):
        """
        strip off prefix and return numeric value
        >>> ChecksumMap.decode('H:1')
        1
        """
        (node_type, idx) = string.rsplit(text, ':', 1)
        return int(idx)
    

    
#----------------------------------------------------
# Processing of subfile hashes and convert to vector
#----------------------------------------------------

#  a) aggregate all checksums associated with a file
#  b) if file has been identified as a duplicate, discard
#  c) assign fileno for each filename
#  d) assign hashno for every unique hash
#  e) convert hashes into vector -- fileno + hashno's
#



#parse entry in format hash filename offset start-end
md5deep_subfile_re = re.compile("([0-9abcdef]+)\s+(\S.+)\soffset\s(\d+)-(\d+)$")

def parse_md5deep_subfile_entry(text, include_offset=True) :
    "processing of individual subdile block hash line in md5deep"
    parse = md5deep_subfile_re.search(text)
    if parse :
        return({'c': parse.groups()[0],
                'r':'_{}_{}'.format(parse.groups()[2], parse.groups()[3])},
               parse.groups()[1])               
    else:
        print 'not found: ' + text
        exit()


def construct_vector(name, hash_set, dup_map, debug=False) :
    if name == "" :
        dprint('skipping - no file; ' + name, debug)
        return False
    if name in dup_map:
        dprint('skipping -- duplicate: ' + name, debug)
        return False
    if len(hash_set) < 2 :
        dprint('skipping -- empty or singleton : ' + name, debug)
        return False

    return [FnameMap.get_id(name),
            [ChecksumMap.get_id(hval) for hval in hash_set]]


def construct_subhash_vectors(fname, dup_map, debug=False) :
    "collect set of checksums per file, substituting numeric id (fno, hno) for text values"

    result = []    
    FnameMap.reset()        #initialize mapping tables
    ChecksumMap.reset()

    fd = open(fname)
    last_name = ""
    hash_set = []
    for text in fd:
        (val, name) = parse_md5deep_subfile_entry(text)
        dprint('name: ' + name, debug)
        dprint('val :' + val['c'], debug)
        
        if name <> last_name :
            dprint(last_name, debug)
            vec = construct_vector(last_name, hash_set, dup_map)
            if vec:
                dpprint(vec, debug)
                result.append(vec)
            last_name = name
            hash_set = []
            
        hash_set.append(val)
        
    vec = construct_vector(name, hash_set, dup_map)
    if vec:
        result.append(vec)
    fd.close()
    return result

def prune_vectors(vector_set) :
    "only keep vectors containing at least 1 shared checksum"
    result = []
    
    for fno, hset in vector_set :
        newset = []
        for hno in hset:
            if ChecksumMap.get_count(hno) > 1:
                newset.append(hno)
        if len(newset) > 0:
            result.append([fno, newset])        
    return result


def output_vectors(name, vset):
    "dumps vectors for use with alternative clustering tools"
    if not name:
        return
    fd = open(name, 'w+')
    for vec in vset:
        fd.write('{}, {}'.format(vec, tuple))
    fd.close()

       
def generate_subfile_vectors(dsub_file, duplicates,
                             pickle_duplicates_fname=False,
                             pickle_vectorset_fname=False,
                             json_vectorset_fname=False,
                             list_vectorset_fname = False,
                             debug=False,
                             status=True) :
    "top level routine - convert file checksums to vectors, pruning non-shared entries"   

    dprint('creating duplicates map', status, nl=True)
    if pickle_duplicates_fname :
        dprint('restoring duplicates data structure', status)
        duplicates = pload(pickle_duplicates_fname) 
    dup_map = create_duplicate_map (duplicates)

    dprint('processing sub-file hashes', status, nl=True)
    vector_set = construct_subhash_vectors(dsub_file, dup_map)

    dprint('pruning', status, nl=True)
    pruned_vector_set = prune_vectors(vector_set)
    
    pdump(vector_set, pickle_vectorset_fname)
    jdump(vector_set, json_vectorset_fname)
    output_vectors(list_vectorset_fname, vector_set)
  
    return pruned_vector_set

#----------------------------
# Clustering and Subgraph Optimization
#----------------------------

def file_conflicting_checksums(csums, graph):
    "find those block checksums that map to the same file region"
    global hno2hval_map
    range_sets = {}
    for hno in csums:
        range = ChecksumMap.get_range_using_encoded_id(hno)
        if range in range_sets:
            range_sets[range] |= hno
        else:
            range_sets[range] = [hno]
    #pprint.pprint(range_sets)   
    return {key: value for key, value in range_sets.items() 
            if len(value) > 1}


def process_subgraph(graph, files, csums) :
    global display_graph_flag
    #global B
    conflicts = file_conflicting_checksums(csums, graph)
    if len(conflicts) > 0:
        print
        print 'conflicting checksums'
        pprint.pprint(conflicts)
        raise ConflictingChecksums(conflicts)
    else:
        print 'proposed parent'
        pprint.pprint([ChecksumMap.get_hval_using_encoded_id(hno) for hno in csums])
        print 'files'
        pprint.pprint([FnameMap.get_name_using_encoded_id(fno) for fno in files])


def filter_partitions(partitions, graph) :
    "processing of individual sub-graph"
    #global B
    nodes, checksums =  bipartite.sets(graph) 
    result = []
    for part in partitions :
        new_part = {'f':[],'h':[]}
        for nodenum in part :
            if nodenum[0] == 'F':
                new_part['f'].append(nodenum)
            else :
                new_part['h'].append(nodenum)
        if len(new_part['f']) > 1 :  #only sub-graphs with multiple files
            #pprint.pprint(new_part)
            new_part['n'] = part
            new_part['g'] = nx.subgraph(graph, part)
            process_subgraph(new_part['g'], new_part['f'], new_part['h'])
            result.append(new_part)
    return result


def graph_analysis(vector_set) :
    "top level routine, partitions vector sets and identified common parent for a set of files"
    global B
    B = nx.Graph()
    for fno, hset in vector_set:
        #print '{} {}'.format(fno, hset)
        B.add_node(FnameMap.encode(fno), bipartite=0)
        for hno in hset :
            if hno not in B :
                B.add_node(ChecksumMap.encode(hno), bipartite=1)               
                #B.add_node(ChecksumMap.encode(hno), bipartite=1,
                #           range=hno2hval_map[hno]['r'])
            B.add_edge(FnameMap.encode(fno), ChecksumMap.encode(hno))
    print 'done'
    #files, hashes = bipartite.sets(B)
    partitions = nx.connected_components(B)
    filtered_partitions = filter_partitions(partitions, B)
    return filtered_partitions


#--------------------------------
# Boneyard - node to be deleted in subsequent version
#--------------------------------
def subgraph_analysis(bsub, gsub) :
    "not yet implemented"
    return

def old_process_subgraph(graph, files, csums) :
    global display_graph_flag
    proj = bipartite.overlap_weighted_projected_graph(graph, files, csums)
    if True:
        print
        print 'file centric analysis'
        clustering = nx.bipartite.clustering(graph, files)       
        print 'avg_clust:{}'.format(nx.bipartite.average_clustering(graph, files))
        for node in files:
            pprint.pprint(node)
            print("file:{} edges: {}".format(node, len(nx.edges(graph, node))))           
            print 'clust:{}'.format(clustering[node])
        print
        print 'checksum centric analysis'
        clustering = nx.bipartite.clustering(graph, csums)       
        print 'avg_clust:{}'.format(nx.bipartite.average_clustering(graph, files))
        for node in csums:
            pprint.pprint(node)
            print("csum:{} edges: {}".format(node, len(nx.edges(graph, node))))           
            print 'clust:{}'.format(clustering[node])
        print 'find conflicting checksums'
        conflicts = file_conflicting_checksums(csums, graph)
        if len(conflicts) > 0:
            print
            print 'conflicting checksums'
            pprint.pprint(conflicts)
                
            if  display_graph_flag:
                print 'Bipartite Sub-Graph'
                nx.draw(graph)
                plt.show()
                print 'Projected Sub-Graph'
                nx.draw(proj)
                plt.show()
           
#------------------------------------
# Main
#------------------------------------
idle_flag = True    #used when bypassing command line during debug with Python IDLE environment

if __name__=="__main__":


    parser = OptionParser(usage="usage: %prog [options] whole_checksums [sorted_block_checksums]")

    
    parser.add_option("-c", "--checksum_type", type = 'string', default = "MD5", dest="hash_type",
                      help="format of checksum in input file, where checksum TYPE is MD% or SHA256",
                      metavar="TYPE")   

    parser.add_option("-v", "--dump_vectors", default=False, action="store_true", dest="dump_vectors",
                      help="enables dumping of vectors to .vectors file for use with alternative analysis")

    parser.add_option("-s", "--status", default=False, action="store_true", dest="status",
                      help="prints status information to console")

    parser.add_option("-d", "--debug", default=False, action="store_true", dest="debug",
                      help="logs information to console for debug purposes")    

    parser.add_option("-g", "--show_graph", default=False, action="store_true", dest="show_graphs",
                      help="displays sub-graphs to console for debug purposes")
    
    (options, args) = parser.parse_args()
    
    global d_file        #for IDLE, delete once idle_flag conditional removed
    global dsub_file     #for IDLE


    debug = False                   #for IDLE -- enable debug message output
    status = True                   #for IDLE -- enable general status logging
    enable_subfile_analysis = True  #for IDLE
    display_graph_flag = True       #for IDLE -- enables plotting of sub-graphs for debug
    enable_subfile_analysis = True
    
    if idle_flag :    #special case behavior when debugging with IDLE
        #input files
        d_file = '/users/doug/SW_Dev/dedupe/input_files/file_hashes_sorted.out'    
        #d_file = '/users/doug/SW_Dev/dedupe/inpute_files/sorted_test_hashes.out'
        dsub_file = '/users/doug/SW_Dev/dedupe/input_files/file_64k_subhashes.out'
        #dsub_file = '/users/doug/SW_Dev/dedupe/input_files/file_1m_subhashes.out'
        #dsub_file = '/users/doug/SW_Dev/dedupe/input_files/test_subhashes.out'
    else:
        debug = options.debug
        status = options.status
        display_graph_flag = options.show_graphs
        if args:
            d_file = args[0]
            if len(args) == 2:
                d_subfile = args[1]
                enable_subfile_analysis = True
            else:
                enable_subfile_analysis = False
        else :
            raise MissingInputFiles
        
    (d_file_base, ext) = string.rsplit(d_file, '.', 1)
    jdup_fname = d_file_base + '.json'      
    duplicates = find_duplicateFiles(d_file, json_duplicates_fname=jdup_fname)


    (d_subfile_base, ext) = string.rsplit(dsub_file, '.', 1)
    jvec_fname = False
    lvec_fname = False
    if options.dump_vectors:
        jvec_fname = d_subfile_base + 'vect.json' #Should this option be deleted?
        lvec_fname = d_subfile_base + 'vectors'

        
    vector_set = generate_subfile_vectors(dsub_file, duplicates,
                                          json_vectorset_fname=jvec_fname,
                                          list_vectorset_fname=lvec_fname)

    dprint('graph analysis', status)
    dpprint(vector_set, False)
    graph_analysis(vector_set)
