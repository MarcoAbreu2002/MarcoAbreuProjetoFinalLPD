#python
import os
res = os.popen('ping -c 2  8.8.8.8') #--> Google Ip
for line in res.readlines():
	print(line)


