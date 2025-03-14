import csv

if __name__ == '__main__':
    start = 10600
    f = open('ldifout.txt', 'w')
    with open('input2.txt') as csvfile:
        spamreader = csv.reader(csvfile)
        for row in spamreader:
            ldif = f"""
dn: uid={row[0]},dc=hash,dc=com
objectclass: organizationalRole
cn: {row[1]} {row[2]}
"""
            f.write(ldif)
            start += 1
    f.close()
    # f = open('input.txt', 'r')
    # lines = f.readlines()
    # for line in lines:
    #     parts = line.split(',')
    #     print(parts)