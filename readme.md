<p align="center">
<img src="images/maze_featureimg.png" width="700">
</p>

# Deobfuscating Maze's Control Flow Obfuscations
This is the source code related to my blogpost published over at [Crowdstrike's blog](). Forgive me, but currently the source code is written using Python 2.7.

## Deobfuscation Methods

Currently, only the Byte-search Method discussed in the blog post is covered. Eventually, I'd like to add a few different methods. 

### Bytesearch Method
Relies upon searching for specific bytes to identify the obfuscations. 

* Takes a bit to run, to many "plan_and_wait()" functions, and I print logs to the output window
* Functions that don't get auto-defined after patching should now be definable in IDA via pressing 'p' 
* The main-brain works, but I am working on some improvements
* bytesearch/maze_cfg_cleanup.py
    * Execute this script to decode the IDB


## IOCs

**Hashes**

* 2a6c602769ac15bd837f9ff390acc443d023ee62f76e1be8236dd2dd957eef3d


## Further Reading
* [A Malware Researcher's Guide to Reversing Maze](https://labs.bitdefender.com/2020/03/a-malware-researchers-guide-to-reversing-maze/) by Mihai Neagu (@mneagu8d) and Bogdan BOTEZATU (@bbotezatu)
    * Leverages IDA's Processor Module Extensions
* [Transparent Deobfuscation With IDA Processor Module Extensions](https://www.msreverseengineering.com/blog/2015/6/29/transparent-deobfuscation-with-ida-processor-module-extensions) by Rolf Rolles