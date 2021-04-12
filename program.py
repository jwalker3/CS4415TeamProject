import subprocess

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
def active_ips():
	netstat = subprocess.run(args=["""netstat -ntu |  awk '/^tcp/{ print $5 }' | sed -r 's/:[0-9]+$//' | sort | uniq -c | sort -n"""],shell=True, stdout=subprocess.PIPE) #calls a netstat terminal subprocess and captures standard output

	output = netstat.stdout #capture of the standard output returned from the subprocess

	conn = [] #array to store number of connections
	addr = [] #array to store IP addresses
	par1 = 0
	par2 = 0
	if(output): #checks if traffic was captured
		spltOut = output.decode().split('\n') #decode standard output and split by the newline
		for i in range(len(spltOut)): #iterate through the lines of the output
			line = spltOut[i]
			if(len(line)>0): #remove empty lines
				spltLine = line.split(' ') #split line by the spaces
				if(len(spltLine)==8):
					par1=6
					par2=7
				if(len(spltLine)==7):
					par1=5
					par2=6
				if(len(spltLine)==6):
					par1=4
					par2=5
				try:
					conn.insert(i, int(spltLine[par1])) #extract the number of connections and cast as int
					addr.insert(i, spltLine[par2]) #extract the IP address
					if(conn[i]>100): #Number of connections threshold that indicates DoS-like traffic
						print("DoS traffic detected with", conn[i], "IP connections which belong to address", addr[i])
					else:
						print(conn[i], "active IP connections in the system with address", addr[i])
				except:
					pass
	else: #if no network traffic was captured
		print("No active IP connections in the system at the moment")


'''
Sniff network traffic on interface eth0
'''
def sniffer(dur):
	print()
	print("Sniffing network traffic")
	print()
	arg = """tshark -Qi eth0 -w cap -F pcap -a duration:"""+str(dur)
	tshark_sniff = subprocess.run(args=[arg],shell=True)

'''
Read the pcap file with the 5 flow labels and save it to a log file 
'''
def logger(log_file):
	tshark_read_log = subprocess.run(args=["""tshark -Qr cap -T fields -E separator=, -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e _ws.col.Protocol"""],shell=True, stdout=subprocess.PIPE)
	out_log = tshark_read_log.stdout
	try:
		f = open(log_file, "w")
	except:
		print("Error opening log file")
	try:
		f.write(out_log.decode())
	except:
		print("Error writing to log file")
	try:
		f.close()
	except:
		print("Error closing log file")
	print()
	print("Network traffic flows saved to log file", log_file)
	print()

'''
Read the full pcap file and analyze it
'''
def analyzer():
	tshark_read_analyze = subprocess.run(args=["""tshark -Qr cap -T fields -E separator=, -e _ws.col.Info"""],shell=True, stdout=subprocess.PIPE)
	out_analyze = tshark_read_analyze.stdout.decode()
	split_out = out_analyze.split('\n')

	synack_count = 0
	tcpseg_count = 0
	if(out_analyze):
		for p in split_out: #traverse through the lines
			split_line = p.split(' ')#split the line by the comma
			try:
				conc = split_line[3]+split_line[4]+split_line[5] #concatenate columns 3 and 4 of split line
				if("[SYN,ACK]" in conc): #check if concatenated string contains [SYN,ACK]
					synack_count = synack_count+1
				if("TCPsegment" in conc):
					tcpseg_count = tcpseg_count+1
			except:
				pass
	print()
	if( (synack_count>100) and (tcpseg_count>200) ):
		print("Traffic contained", tcpseg_count, "segmented TCP packets and", synack_count, "SYN-ACK's indicating high chance of a Slowloris DoS attack")
	else:
		print("Traffic contained a normal amount of segmented TCP packets and SYN-ACK's")

if __name__ == "__main__":
	duration = input("Please enter the duration (in seconds) for the network scan: ")
	file_name = input("Please enter name of file to save log into: ")
	sniffer(duration)
	logger(file_name)
	analyzer()
	active_ips()


