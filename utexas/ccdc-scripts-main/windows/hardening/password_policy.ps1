# UNTESTED

net accounts /forcelogoff:900   # Force log off {minutes:no}
net accounts /minpwage:0    # Minimum password age {days:0}
net accounts /maxpwage:30   # Max password age {days:unlimited}
net accounts /minpwlen:14    # Minimum password length {0-14, default 6}
net accounts /uniquepw:24   # Length of password history maintained {0-24}
net accounts /lockoutthreshold:10   # Lockout threshold
net accounts /lockoutwindow:15   # Lockout duration
secpol.msc
