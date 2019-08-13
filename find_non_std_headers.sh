#!/bin/sh
# Author: Xenakis Alexandros
# Date: 30.07.19

# Script used to extract non-standard header fields from a HAR file from youtube.com.


# Convention: 0==false

# TODO: also check for standard fields but used in a non standard way.

awk '

############################
##### helper functions #####
############################

# Checks if the header given in argument is a standard one. If it is not, the header is added to the list of standard headers in order to be printed only once.  
# [Arg] header: quoted name of header with a comma following. Ex. ["content-type",].  

function isStandardRequestHeader(headerarg){
	stdReqList[1] = "\"a-im\","; 
	stdReqList[2] = "\"accept\","; 
	stdReqList[3] = "\"accept-charset\","; 
	stdReqList[4] = "\"accept-datetime\","; 
	stdReqList[5] = "\"accept-encoding\","; 
	stdReqList[6] = "\"accept-language\","; 
	stdReqList[7] = "\"access-control-request-method\","; 
	stdReqList[8] = "\"access-control-request-headers\","; 
	stdReqList[9] = "\"authorization\","; 
	stdReqList[10] = "\"cache-control\","; 
	stdReqList[11] = "\"connection\","; 
	stdReqList[12] = "\"content-length\","; 
	stdReqList[13] = "\"content-md5\","; 
	stdReqList[14] = "\"content-type\","; 
	stdReqList[15] = "\"cookie\","; 
	stdReqList[16] = "\"date\","; 
	stdReqList[17] = "\"expect\","; 
	stdReqList[18] = "\"forwarded\","; 
	stdReqList[19] = "\"from\","; 
	stdReqList[20] = "\"host\","; 
	stdReqList[21] = "\"http2-settings\","; 
	stdReqList[22] = "\"if-match\","; 
	stdReqList[23] = "\"if-modified-since\","; 
	stdReqList[24] = "\"if-none-match\","; 
	stdReqList[25] = "\"if-range\","; 
	stdReqList[26] = "\"if-unmodified-since\","; 
	stdReqList[27] = "\"max-forwards\","; 
	stdReqList[28] = "\"origin\","; 
	stdReqList[29] = "\"pragma\","; 
	stdReqList[30] = "\"proxy-aythorization\","; 
	stdReqList[31] = "\"range\","; 
	stdReqList[32] = "\"referer\","; 
	stdReqList[33] = "\"te\","; 
	stdReqList[34] = "\"user-agent\","; 
	stdReqList[35] = "\"via\","; 
	stdReqList[36] = "\"upgrade\","; 
	stdReqList[37] = "\"warning\","; 
	nbStdReq = 37; 
	for(i=1; i<=nbStdReq; i++) {
		if(tolower(headerarg) == stdReqList[i]){
			return 1; 
		}	 
	}
	# at this point we have a new header: we add it to the list
	return 0; 
}

# Same as isStandardResponseHeader but for response headers. 
function isStandardResponseHeader(headerarg){
	stdResList[1] = "\"access-control-allow-origin\",";
	stdResList[2] = "\"access-control-allow-credentials\",";
	stdResList[3] = "\"access-control-expose-headers\",";
	stdResList[4] = "\"access-control-max-age\",";
	stdResList[5] = "\"access-control-allow-methods\",";
	stdResList[6] = "\"access-control-allow-headers\",";
	stdResList[7] = "\"accept-ranges\",";
	stdResList[8] = "\"accept-patch\",";
	stdResList[9] = "\"age\",";
	stdResList[10] = "\"alt-svc\",";
	stdResList[11] = "\"allow\",";
	stdResList[12] = "\"cache-control\",";
	stdResList[13] = "\"content-disposition\",";
	stdResList[14] = "\"connection\",";
	stdResList[15] = "\"content-encoding\",";
	stdResList[16] = "\"content-language\",";
	stdResList[17] = "\"content-length\",";
	stdResList[18] = "\"content-location\",";
	stdResList[19] = "\"content-md5\",";
	stdResList[20] = "\"content-range\",";
	stdResList[21] = "\"date\",";
	stdResList[22] = "\"content-type\",";
	stdResList[23] = "\"delta-base\",";
	stdResList[24] = "\"etag\",";
	stdResList[25] = "\"expires\",";
	stdResList[26] = "\"im\",";
	stdResList[27] = "\"link\",";
	stdResList[28] = "\"last-modified\",";
	stdResList[29] = "\"location\",";
	stdResList[30] = "\"pragma\",";
	stdResList[31] = "\"p3p\",";
	stdResList[32] = "\"proxy-authenticate\",";
	stdResList[33] = "\"retry-after\",";
	stdResList[34] = "\"public-key-pins\",";
	stdResList[35] = "\"server\",";
	stdResList[36] = "\"strict-transport-security\",";
	stdResList[37] = "\"set-cookie\",";
	stdResList[38] = "\"trailer\",";
	stdResList[39] = "\"transfer-encoding\",";
	stdResList[40] = "\"tk\",";
	stdResList[41] = "\"upgrade\",";
	stdResList[42] = "\"vary\",";
	stdResList[43] = "\"via\",";
	stdResList[44] = "\"warning\",";
	stdResList[45] = "\"x-frame-options\",";
	stdResList[46] = "\"www-authenticate\",";
	nbStdRes = 46; 
	for(i=1; i<=nbStdRes; i++) {
		if(tolower(headerarg) == stdResList[i]){
			return 1; 
		}	 
	}
	return 0; 
}

############################
###### actual script #######
############################

BEGIN {
	currentLine = 0; # to display info on position 

	# find ports different than 443
	portsList[0] = 443; 
	nb_ports = 1; 

	# find non standard headers
	inRequest = 0; 
	inResponse = 0; 
	inHeader = 0; 
	printNextValue = 0; # used to know when to print the line after the non-std header, the value 	

	# count the number of domains querried 
	domaincounter = 0; 

	print "The non standard headers are: "; # easier to print them as we go instead of storing them
	print "----------------------------";
}

{currentLine++;} 

########################### headers ###########################

# enter in a request 
$1=="\"request\":" { inRequest = 1; } 
inRequest==1 && $1=="\"headers\":" { inHeader = 1; }
# exit a request (temporary dirty way)
inRequest==1 && inHeader==1 && $1=="\"cookies\":" { inHeader = 0; inRequest = 0; } 

# entered in a response 
$1=="\"response\":" { inResponse = 1; } 
inResponse==1 && $1=="\"headers\":" { inHeader = 1; }
# exit a response (temporary dirty way)
inResponse==1 && inHeader==1 && $1=="\"cookies\":" { inHeader = 0; inResponse = 0; } 

inRequest==1 && inHeader==1 && $1=="\"name\":" && isStandardRequestHeader($2)==0 { # found non-std header field of request 
	print "Request header (line ", currentLine, ")"
	print $0;
	printNextValue=1; 
} 

inResponse==1 && inHeader==1 && $1=="\"name\":" && isStandardResponseHeader($2)==0 { # found non-std header field of response
print "Response header (line", currentLine, ")";
	print $0;
	printNextValue=1; 
} 

printNextValue==1 && $1=="\"value\":" { # value of the non-std header found
	print $0; 
	printNextValue=0; 
}

########################### number of domains ###########################

$1=="\"url\":" { domaincounter++; } # domain found

########################### ports ###########################

$1=="\"connection\":" && $2!~/"443"/ { portsList[nb_ports]=$2; nb_ports++; } # port found

END {
	print "The ports are: "
	print "--------------"
	for (i=0; i<nb_ports; i++) {
		print portsList[i]; 
	}


	print "Numbers of domains contacted =", domaincounter; 
	print "------------------------------------"
}
' $1  > $2

