# KidBrother
Process your Bro logs using GoatRider to lookup suspicious addresses  
This script looks automatically goes through weird.log and x509.log, pulls out domains/ip addresses, then uses Binary Defense's GoatRider to cross check the results against various blacklists, TOR nodes, and the Alexa 100M list.
  
Dependencies:  
  * Bro/Zeek: https://www.zeek.org/
  * GoatRider: https://github.com/BinaryDefense/goatrider
  * python2.7  
  
Just run the bash script and point it at the directory where your capture files are located.  
  
`chmod +x KidBrother.sh`  
`./KidBrother.sh`  
  
The script works on CAPs, PCAPs, and PCAPNGs  
Results from GoatRider (in the form of goatriderIPOutput.txt and goatriderDomainOutput.txt), along with results from Bro/Zeek are saved in a directory with the same basename as the capture file.  
  
Please ignore TCP checksum warnings during script execution. This comes from Bro and won't effect your results.  
