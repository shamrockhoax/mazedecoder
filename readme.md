<p align="center">
<img src="images/maze_featureimg.png" width="700">
</p>

# Deobfuscating Maze's Control Flow Obfuscations
This is the source code related to my blogpost published over at [Crowdstrike's blog](). Forgive me, but currently the source code is written using Python 2.7.

* Bytesearch Method
   * Relies upon searching for specific bytes to identify the obfuscations
   * bytesearch/maze_cfg_cleanup.py
       * Execute this script to decode the IDB






## Further Reading
* [A Malware Researcher's Guide to Reversing Maze](https://labs.bitdefender.com/2020/03/a-malware-researchers-guide-to-reversing-maze/) by Mihai Neagu (@mneagu8d) and Bogdan BOTEZATU (@bbotezatu)
    * Leverages IDA's Processor Module Extensions
* [Transparent Deobfuscation With IDA Processor Module Extensions](https://www.msreverseengineering.com/blog/2015/6/29/transparent-deobfuscation-with-ida-processor-module-extensions) by Rolf Rolles