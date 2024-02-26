given = "IREHWYJZMEcGCODGMMbTENDDGcbGEMJZGEbGEZTFGYaGKNRTMIcGIMBSGRQTSNDDGAaWGYZRHEbGCNRQMUaDOMbEMRTGEYJYGUaWGOJQMYZHa==="
charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
binary = ""

table = dict()
for i in range(32):
    table[charset[i]] = format(i, "b").zfill(5)
table["="] = "0"*5

for i in range(len(given)) : 
    binary += table.get(given[i])

flag = [ chr(int(binary[8*i : 8*i+8], base=2)) for i in range(len(binary)//8)]

print("".join(flag))