import csv

if __name__ == '__main__':
    f = open('ldifgroupout.txt', 'w')
    with open('input2.txt') as csvfile:
        spamreader = csv.reader(csvfile)
        for row in spamreader:

            groups = row[4].split(',')
            for group in groups:
                ldif = f"""
dn: cn={group},ou=Groups,dc=team05,dc=garbage,dc=swccdc,dc=com
changetype: modify
add: memberuid
memberuid: {row[0]}

"""
            
                f.write(ldif)
    f.close()
    # f = open('input.txt', 'r')
    # lines = f.readlines()
    # for line in lines:
    #     parts = line.split(',')
    #     print(parts)