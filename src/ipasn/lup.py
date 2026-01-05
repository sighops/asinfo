import sys
import ipasn
import pickle

f = open('pickle', 'rb')
db = pickle.loads(f.read())

print(db.get_as_prefixes(15169))
