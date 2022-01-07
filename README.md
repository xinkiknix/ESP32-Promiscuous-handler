# ESP32-Promiscuous-handler
ESP32 in promiscuous mode, running on both cores, stores data on internal flash 

Full functional ESP32 promiscuous mode tracking solution
can be usde to check wifi users in the vicinity

Current implementation filters managemnt packages, but filter can be updated.
Found instances are put on a queue for parallel processing.
Data is retrieved from queue  in a separate process and put in a map for filtering unique occurances.
Results are store periodically in a file MapData.csv (use FTP to retrieve the file)
Sample data:

Date,Dest_type,Destination,Sender_type,Sender,SSID,Count
11:59:24 Tue, Dec 21 2021,,,,,
,L,62:dd:d5,G,00:4e:35,2-3GLd,001
,L,62:dd:d5,G,00:4e:35,IMPRIMANTE,001
,L,62:dd:d5,G,00:4e:35,PDA,001
,L,62:dd:d5,G,00:4e:35,xxxx1,001
,L,62:dd:d5,G,00:4e:35,BALANCE,001
,L,d8:8c:79,L,70:74:14,IVECO_xxxxx,003
,L,5a:cd:7a,L,70:74:14,IVECO_xxxx,005
,L,62:dd:d5,G,00:4e:35,xxxspot,001

only first 3 bytes of MAC address are shown for privacy and to limit space usage on flash drive.
