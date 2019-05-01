# GoatBrother
Process your Bro logs using GoatRider to lookup suspicious addresses  
  
Dependencies:  
  * Bro/Zeek: https://www.zeek.org/
  * GoatRider: https://github.com/BinaryDefense/goatrider
  * python2.7
Just run the bash script and point it at the directory where your capture files are located.  
  
`chmod +x GoatBrother.sh`  
`./GoatBrother.sh`  
  
The script works on CAPs, PCAPs, and PCAPNGs
Results from GoatRider (in the form of goatriderIPOutput.txt and goatriderDomainOutput.txt), along with results from Bro/Zeek are saved in a directory with the same basename as the capture file.  
  
Please ignore TCP checksum warnings during script execution. This comes from Bro and won't effect your results.  
