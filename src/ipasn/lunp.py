import sys
import ipasn

db = ipasn.IpAsn('/Users/caleb/.ipasn/cache/asndb')

print(db.lookup('8.8.8.8'))
