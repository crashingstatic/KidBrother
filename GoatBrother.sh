#!/bin/bash

read -p "Enter (absolute or relative) path of the directory containing the capture files: " DIR

GOAT=$(find / -name "goatrider.py" 2>/dev/null)

if [[ ! -z "$GOAT" ]]
then
	echo "using $GOAT for IP lookup"
else
	cat << EOF
Binary Defense's GoatRider not installed,
Please use the following command to download the script before continuing:
git clone https://github.com/BinaryDefense/goatrider
EOF
break
fi

shopt -s nullglob
for capture in *.pcap *.cap *.pcapng
do
	filename="${capture##*/}"
	extension="${filename##*.}"
	filename="${filename%.*}"
	mkdir "$filename"
	cd "$filename"
	echo "Working on $filename..."
	echo -ne "Parsing $filename with Zeek.............\r"
	bro -r "../$capture"

	bro-cut id.resp_h < weird.log | grep -v "-" | sort | uniq >> suspiciousIPs
	bro-cut san.dns < x509.log | grep -v "-" | sort | uniq >> suspiciousDomains

	echo -ne "Cleaning parsed domains.................\r"

	while read LINE
	do
		IFS=, DOMAIN=($LINE)
		for (( i=0; i<${#DOMAIN[@]}; i++ ))
		do
			echo "$DOMAIN" >> fullDomains
			dig +short "$DOMAIN" >> Domain.dig
			host "$DOMAIN" >> Domain.host
		done

	IFS=$'\n'
	done < suspiciousDomains
	rm suspiciousDomains

	cat Domain.host | sort | uniq >> Domains
	rm Domain.host

	cat Domain.dig | sort | uniq >> Domains
	rm Domain.dig

	echo -ne "Extracting IP addresses for GoatRider...\r"

	while read LINE
	do
		ADDRESS=$(echo "$LINE" | grep -oE "((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])))")
	
		if [[ ! -z "$ADDRESS" ]]
		then
			echo "$ADDRESS" >> suspiciousIPs
		else
			case $LINE in
				*mail*) echo "$LINE" | awk -F"mail is handled by" '{print $2}' | sed 's/\.*$//' | cut -d' ' -f3 >> fullDomains
					;;
				*alias*) echo "$LINE" | awk -F"is an alias for" '{print $2}' | sed 's/\.*$//' >> fullDomains
					;;
				*) echo "$LINE" | sed 's/\.*$//' >> fullDomains
					;;
			esac
		fi
	done < Domains
	rm Domains

	cat fullDomains | sort | uniq >> suspiciousDomains
	rm fullDomains
	cat suspiciousIPs | sort | uniq >> suspiciousIPs.full
	mv suspiciousIPs.full suspiciousIPs

	echo -ne "Checking Domains with GoatRider.........\r"
	python "$GOAT" suspiciousDomains >> goatriderDomainOutput.txt

	echo -e "Checking IP addresses with GoatRider....\r"	
	python "$GOAT" suspiciousIPs >> goatriderIPOutput.txt
	rm -r IPData
	cd ..
done

echo "Done. Please review goatriderIPOutput.txt and goatriderDomainOutput.txt for results."