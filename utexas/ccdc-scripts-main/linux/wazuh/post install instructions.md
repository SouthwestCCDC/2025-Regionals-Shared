Add the archives index pattern: https://documentation.wazuh.com/current/user-manual/manager/wazuh-archives.html#wazuh-dashboard
Be careful! `@timestamp` is not `timestamp`

to look at logs, go to "Discover" in the top level menu, select the archives index pattern and add a filter for `location` `is` `<log file>`