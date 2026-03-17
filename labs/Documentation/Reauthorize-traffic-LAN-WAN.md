Delete by rule number:

```
iptables -L FORWARD --line-numbers
```

You will see something like:

```
1  ACCEPT  RELATED,ESTABLISHED
2  DROP    198.18.100.0/24 → 198.18.200.0/24
3  DROP    198.18.200.0/24 → 198.18.100.0/24...
```


Delete:

```
iptables -D FORWARD 3
iptables -D FORWARD 2
```

⚠️ Always delete the highest one first.

Then verify with :

```
iptables -S FORWARD
```
