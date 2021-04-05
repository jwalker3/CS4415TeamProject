import subprocess
#import dpkt


"""
Live capture IP connectios using a netstat subprocess (must be run during the DoS attack)
netstat command explanation: 
-n = numeric, -t = TCP, -u = UDP
awk '/^tcp/{ print $5 }' = select the fifth column of the data (Foreign IP address)
sed -r 's/:[0-9]+$//' = remove port number from the data using regular expression
sort = sort the IP addresses
uniq -c = count IP addresses and report the total count
sort -n = sort ouput according to numerical value (by the total count)
"""
netstat = subprocess.run(args=["""netstat -ntu |  awk '/^tcp/{ print $5 }' | sed -r 's/:[0-9]+$//' | sort | uniq -c | sort -n"""],shell=True, stdout=subprocess.PIPE) #calls a netstat terminal subprocess and captures standard output

output = netstat.stdout #capture of the standard output returned from the subprocess

conn = [] #array to store number of connections
addr = [] #array to store IP addresses

if(output): #checks if traffic was captured
	spltOut = output.decode().split('\n') #decode standard output and split by the newline
	for i in range(len(spltOut)): #iterate through the lines of the output
		line = spltOut[i]
		if(len(line)>0): #remove empty lines
			spltLine = line.split(' ') #split line by the spaces
			conn.insert(i, int(spltLine[4])) #extract the number of connections and cast as int
			addr.insert(i, spltLine[5]) #extract the IP address
			if(conn[i]>100): #Number of connections threshold that indicates DoS-like traffic
				print("DoS traffic detected with", conn[i], "IP connections which belong to address", addr[i])
else: #if no network traffic was captured
	print("No traffic captured")



