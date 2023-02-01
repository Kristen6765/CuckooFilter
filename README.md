# CuckooFilter
This is an implementation that allows customized number of bucket (m), number of entry(b) and fingerprint size(f).
### Steps to run the code:
1. Enter 1 to see a pre-constructed example which includes insertion (eviction of an item when the current bucket is full), lookup (both positive and negative lookup queries), and deletion. Enter 2 to try out the code with your own configuration.
2. If you entered 2, then provide the number of bucket (m), number of entry(b) and fingerprint size(f) in the following format (m,b,f), and no space in between. Make sure m is a power of 2. For example: 8,4,8
3. Then enter operations, for example:  
  **add 1**, this is an example of add operation where add 1 to the filter.  
  **lookup 1**, this is an example of lookup operation where check if 1 exist in the filer.  
  **delete 1**, this is an example of delete operation where delete 1 in the filer.  
4. If you want to exist then enter: exit
5. To entirely exiting the execution enter exit again.

Reference: ["Cuckoo Filter: Better than Bloom"](https://www.cs.cmu.edu/~dga/papers/cuckoo-conext2014.pdf) paper by researchers in CMU University.
