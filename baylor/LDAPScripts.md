
These are scripts for LDAP
CSVs should be in format {user}:{pass}

---
### Onboarding 

``` bash
#!/bin/bash
# onboard_users.sh
# Adjust starting UID/GID as needed.

CSVFILE="onboard_users.csv"
BASE_DN="dc=test,dc=com"
OU="People"
LDAPADMIN="cn=admin,dc=test,dc=com"
START_UID=10001  # starting uidNumber; adjust as needed

count=0

while IFS=: read -r username password; do
  # Skip blank lines or improperly formatted lines
  if [[ -z "$username" || -z "$password" ]]; then
    continue
  fi

  uidNumber=$((START_UID + count))
  gidNumber=$uidNumber  # For simplicity, we set gidNumber = uidNumber. Adjust as needed.
  homeDirectory="/home/${username}"
  loginShell="/bin/bash"
  
  LDIF_FILE="/tmp/onboard_${username}.ldif"
  cat <<EOF > "$LDIF_FILE"
dn: uid=${username},ou=${OU},${BASE_DN}
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: ${username}
cn: ${username}
sn: ${username}
userPassword: ${password}
uidNumber: ${uidNumber}
gidNumber: ${gidNumber}
homeDirectory: ${homeDirectory}
loginShell: ${loginShell}
shadowLastChange: 0
shadowMax: 99999
shadowWarning: 7
EOF

  echo "Onboarding user ${username}..."
  ldapadd -x -D "${LDAPADMIN}" -W -f "$LDIF_FILE"
  
  rm -f "$LDIF_FILE"
  count=$((count + 1))
done < "$CSVFILE"

```

---

### Off boarding

``` bash
#!/bin/bash
# offboard_users.sh

CSVFILE="offboard_users.csv"
BASE_DN="dc=test,dc=com"
OU="People"
LDAPADMIN="cn=admin,dc=test,dc=com"

while IFS= read -r username; do
  # Skip empty lines
  if [[ -z "$username" ]]; then
    continue
  fi

  DN="uid=${username},ou=${OU},${BASE_DN}"
  echo "Deleting user ${username}..."
  ldapdelete -x -D "${LDAPADMIN}" -W "$DN"
done < "$CSVFILE"
```

--- 
### Migrate Users

``` bash
#!/bin/bash
# move_to_employees.sh
# This script moves users from ou=People to ou=Employees by renaming their DN.
# The target OU (Employees) must already exist.

CSVFILE="move_to_employees.csv"
BASE_DN="dc=test,dc=com"
OLD_OU="People"
NEW_OU="Employees"
LDAPADMIN="cn=admin,dc=test,dc=com"

while IFS= read -r username; do
  if [[ -z "$username" ]]; then
    continue
  fi

  OLD_DN="uid=${username},ou=${OLD_OU},${BASE_DN}"
  NEW_RDN="uid=${username}"
  NEW_SUPERIOR="ou=${NEW_OU},${BASE_DN}"

  echo "Moving user ${username} from ${OLD_OU} to ${NEW_OU}..."
  ldapmodrdn -x -D "${LDAPADMIN}" -W -r "$OLD_DN" -N "$NEW_RDN" -S "$NEW_SUPERIOR"
done < "$CSVFILE"
```

---

### Add attribute

``` bash
#!/bin/bash
# The LDAP entry remains in OU=People, but now it carries an extra attribute.

CSVFILE="tag_as_employee.csv"
BASE_DN="dc=test,dc=com"
OU="People"
LDAPADMIN="cn=admin,dc=test,dc=com"

while IFS= read -r username; do
  if [[ -z "$username" ]]; then
    continue
  fi

  DN="uid=${username},ou=${OU},${BASE_DN}"
  LDIF_FILE="/tmp/tag_${username}.ldif"
  cat <<EOF > "$LDIF_FILE"
dn: ${DN}
changetype: modify
add: employeeType
employeeType: employee
EOF

  echo "Tagging user ${username} as employee..."
  ldapmodify -x -D "${LDAPADMIN}" -W -f "$LDIF_FILE"
  rm -f "$LDIF_FILE"
done < "$CSVFILE"
```

---

### Deactivate User

``` bash
#!/bin/bash
# deactivate_users.sh
# This script deactivates users by changing their loginShell to /sbin/nologin.

CSVFILE="deactivate_users.csv"
BASE_DN="dc=test,dc=com"
OU="People"
LDAPADMIN="cn=admin,dc=test,dc=com"
NOLOGIN="/sbin/nologin"

while IFS= read -r username; do
  if [[ -z "$username" ]]; then
    continue
  fi

  DN="uid=${username},ou=${OU},${BASE_DN}"
  LDIF_FILE="/tmp/deactivate_${username}.ldif"
  cat <<EOF > "$LDIF_FILE"
dn: ${DN}
changetype: modify
replace: loginShell
loginShell: ${NOLOGIN}
EOF

  echo "Deactivating user ${username}..."
  ldapmodify -x -D "${LDAPADMIN}" -W -f "$LDIF_FILE"
  rm -f "$LDIF_FILE"
done < "$CSVFILE"
```

---