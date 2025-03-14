# Fail2Ban
*Made this into a markdown from a 3-piece script.*
[Wiki](https://github.com/fail2ban/fail2ban/wiki)

Steps per machine:
  1. Install fail2ban (below)
  2. Add fail2ban.local to /etc/fail2ban/
  3. Enable any important modules (listed below) by adding `enabled = true` below [<module_name>] in jail.local 
  4. Add jail.local to /etc/fail2ban/
  5. Enable and start fail2ban (below)
  6. Check to make sure it's working with `sudo fail2ban-client status` to see running modules and checking logs in /var/log/fail2ban.log

## Installing (from Package Manager)
```
apt-get update
apt-get install -y fail2ban
```
```
yum update -y
yum install -y fail2ban
```
```
dnf update
dnf install fail2ban
```

## Enabling
Note: Not needed on Debian/Ubuntu as those install scripts already enable F2B.
```
systemctl enable fail2ban
systemctl start fail2ban
```

## Relevant Modules
- sshd
- apache-auth
- apache-overflows
- apache-nohome
- apache-botsearch
- nginx-http-auth
- nginx-botsearch
- nginx-bad-request
- nginx-forbidden
- php-url-fopen
- pure-ftpd
- mysqld-auth
- mssql-auth
- mongodb-auth
- pam-generic
- grafana
- pass2allow-ftp
- slapd
- phpmyadmin-syslog
