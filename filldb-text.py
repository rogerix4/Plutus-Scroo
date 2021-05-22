import os
from pymemcache.client import base
from datetime import datetime

DATABASE_PATH = r'database/data.txt'

print('connect memcached...')
client = base.Client(('localhost', 11211))
print('Loading and injecting database')
print(datetime.now().strftime("%m/%d/%Y, %H:%M:%S"))

i_add = 0
f = open(DATABASE_PATH, 'r')
while True:
    alist = []
    lines = f.readlines(4096)
    if not lines:
        break
    for i in lines:
        alist.append(i.rstrip('\n'))
        i_add += 1
    client.set_multi(dict.fromkeys(alist, 1), expire=0)
    #client.set(line, '1', expire = 0) 
    print('\raddresses: ' + str(i_add), end=' ')

f.close()
print('DONE LOADING DATABASE')

print(datetime.now().strftime("%m/%d/%Y, %H:%M:%S"))
ret_list = client.get_multi(['3PQtD6B1crUVvNHt6fVY5HvdajRrJ6EeGq', '1Ca72914TemMMuDpAscEMeZV3494sztc81'])
if ret_list:
    print('sanity check pass')
else:
    print('check failed')
