# Illumio Coding Challenge

To Run:
Have a firewall file `firewall_rules.csv` in the same folder as the `firewall.py`. Tested against **Python 2.7**
```
$python firewall.py
```

The code consists of two classes Rule and Firewall. The Rule class does the bulk of the work; it creates the mappings 
containing the inbound and outbound rules. We use the pyton `bisect` module to insert port range and ip-range in ascending 
order. This helps us to use binary search while searching for a port/ip-address, thus reducing time complexity.

In terms of testing, since the time has been limited,  I have just tested against the inputs mentioned in the challenge. The code lacks `unittest` or __assert__ and just prints the output for user visual inspection. 

__If I had more time ?__ 
I would have loved to explore a trie/suffix tree based approach. I believe we can benefit from using tries/variation of tries. Other than this, I will like to remove the tight coupling between Rule and Firewall class. Would also like to do proper regression test

**Teams**
1. Plaftorm
2. Data
