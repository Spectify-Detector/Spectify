# Citation
A. Pashrashid, A. Hajiabadi, T. E. Carlson, "Fast, Robust and Accurate Detection of Cache-based Spectre
Attack Phases", 41st IEEE/ACM International Conference on Computer-Aided Design (ICCAD '22)

# How to Run Spectify


Step 1: Building the project
--------------------------------------------------------------------------------------------

*Commands:*

    $ git clone https://github.com/Arash-Rashid/Spectify.git
    $ cd spectify
    $ mkdir build && cd build
    $ cmake ..
    $ make

-   Note: You need gcc version 4.9 or above.

-   After building the project, *detector\_pp* will be used for prime+probe, and *detector\_flush* will be used for flush+flush and flush+reload.


Step 2: Running gem5 and generating execution report
--------------------------------------------------------------------------------------------
*Commands:*

    $ git clone https://github.com/Arash-Rashid/gem5-spectify.git
    $ cd gem5-spectify
    $ git checkout dump\_report
    $ scons build/X86/gem5.opt -j8 
    $ build/X86/gem5.opt --debug-file=report.txt /
    --debug-flags=Tage,Cache,Squash,CacheVerbose  configs/example/se.py /
    --cpu-type=DerivO3CPU  --caches --l2cache  --mem-size=512MB / 
    --mem-type=SimpleMemory --cacheline\_size=64 --bp-type=TAGE  --cmd [binary]

Step 3: Running the detector
--------------------------------------------------------------------------------------------
**For Spectre using prime+probe:**

    $ ./detector\_pp [gem5 report] [#required primed cache sets] [#cache ways] /
    [frame size] [CS clear percentage] [gem5 cpu name] [initial tick] [report interval] 

* \[gem5 report\]: The debug output gem5 generated in step 2
* \[#required primed cache sets\]: Required number of cache sets to be primed for a     successful attack 
* \[#cache ways\]: Number of cache ways
* \[frame size\]: Frame size specifies the number of simulation ticks between two context switches
* \[CS clear percentage\]: The percentage of primed cache sets touched during each context switch
* \[gem5 cpu name\]: CPU name used in gem5 debug reports (gem5 default for a single core is cpu)
* \[initial tick\]: The start simulation tick for detection analysis 
* \[report interval\]: Dump statistics periodically for a specific number of frames

*Example:*
    $ ./detector\_pp ../examples/report.txt 2 2 1000000 0 cpu 0 50


**For Spectre using flush+flush or flush+reload:**

    $ ./detector\_pp [gem5 report] [#required flushed cache lines] [frame size] 
 
* \[gem5 report\]: The debug output gem5 generated in step 2
* \[#required flushed cache lines\]: Required number of cache lines to be flushed for a     successful attack 
* \[frame size\]: Frame size specifies the number of simulation ticks between two context switches

*Example:*
    $ ./detector\_flush ../examples/report-flush.txt 256 1000000


