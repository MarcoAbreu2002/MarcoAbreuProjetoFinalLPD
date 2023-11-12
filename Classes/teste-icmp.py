#python
import os
res = os.popen('ping -c 5  8.8.8.8') #--> Google Ip
for line in res.readlines():
	print(line)


