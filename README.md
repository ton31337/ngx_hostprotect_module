Overview
======================
Nginx module to protect web service from malicious/bogus source IPs.

Configuration
======================
* `hostprotect (on|off)` - enables/disables hostprotect per location. Default off.
* `hostprotect_expire (integer)` - sets expire time in seconds. Default 60.
* `hostprotect_purge_ip (string)` - sets IP address allowed to purge cache. Default "1.1.1.1".

