EXAMPLES:
---------


+---------------------------------------------------------+---------------------------------------------------------------------------+
| **route API**                                           | **route command**                                                         |
+---------------------------------------------------------+---------------------------------------------------------------------------+
| -XPUT add/10.0.0.1                                      | route add default gateway 10.0.0.1                                        |
+---------------------------------------------------------+---------------------------------------------------------------------------+
| -XPUT add/192.168.0.0/255.255.255.0/ens33               | route add -net 192.168.0.0 netmask 255.255.255.0                          |
|                                                         | dev ens33                                                                 |
+---------------------------------------------------------+---------------------------------------------------------------------------+
| -XPUT add/192.168.0.0/255.255.255.0/10.0.0.1            | route add -net 192.168.0.0 netmask 255.255.255.0                          |
|                                                         | gateway 10.0.0.1                                                          |
+---------------------------------------------------------+---------------------------------------------------------------------------+
| -XPUT add/192.168.0.0/255.255.255.0/10.0.0.1/ens33      | route add -net 192.168.0.0 netmask 255.255.255.0                          |
|                                                         | gateway 10.0.0.1 dev ens33                                                |
+---------------------------------------------------------+---------------------------------------------------------------------------+
| -XDELETE del/10.0.0.1                                   | route del default gateway 10.0.0.1                                        |
+---------------------------------------------------------+---------------------------------------------------------------------------+
| -XDELETE del/192.168.0.0/255.255.255.0                  | route del -net 192.168.0.0 netmask 255.255.255.0                          |
+---------------------------------------------------------+---------------------------------------------------------------------------+
| -XDELETE del/192.168.0.0/255.255.255.0/ens33            | route del -net 192.168.0.0 netmask 255.255.255.0                          |
|                                                         | dev ens33                                                                 |
+---------------------------------------------------------+---------------------------------------------------------------------------+
| -XDELETE del/192.168.0.0/255.255.255.0/10.0.0.1/ens33   | route del -net 192.168.0.0 netmask 255.255.255.0                          |
|                                                         | gateway 10.0.0.1 dev ens33                                                |
+---------------------------------------------------------+---------------------------------------------------------------------------+
| -XGET /list                                             | Return the list of existing rules in JSON format. Sample output:          |
|                                                         | [{"target": "NULL", "Destination": "0.0.0.0",                             |
|                                                         | "Gateway": "10.0.0.2","Genmask": "0.0.0.0", "Flags": "UG",                |
|                                                         | "Metric": "0","Ref": "0", "Use": "0", "Iface": "ens33"},                  |
|                                                         | {"target": "NULL", "Destination": "10.0.0.0",                             |
|                                                         | "Gateway": "0.0.0.0", "Genmask": "255.255.255.0", "Flags": "U",           |
|                                                         | "Metric": "0", "Ref": "0", "Use": "0", "Iface": "ens33"},                 |
|                                                         | {"target": "NULL", "Destination": "169.254.0.0",                          |
|                                                         | "Gateway": "0.0.0.0", "Genmask": "255.255.0.0", "Flags": "U",             |
|                                                         | "Metric": "1000", "Ref": "0", "Use": "0", "Iface": "ens33"}]              |
|                                                         |                                                                           |
+---------------------------------------------------------+---------------------------------------------------------------------------+



DEPLOYMENT
----------

1. Requires Python 2.7

2. Generate keys and certificates with config/deploy/routegen::

    ./routegen <server_ip>

See `routegen README` for more details.

3. Edit CONFIG_FILE, LOG_LEVEL in route.py

4. Run in verbose mode with default config file:: [-v]

Test with curl::

    curl -v --cacert <path>/ca.crt --user myuser:mypasswd -XPUT https://<server_ip>:7393/add/192.168.0.0/255.255.255.0/ens33

or when testing on localhost you can skip certificate verification::

    curl -v --insecure --user myuser:mypasswd -XPUT https://127.0.0.1:7393/add/192.168.0.0/255.255.255.0/ens33

or when ``local.server`` enabled there is no authentication::

    curl -v -XPUT http://localhost:7390/add/192.168.0.0/255.255.255.0/ens33
    

RUN PROGRAM
--------------------------

You still need to be root. Unzip tarball, configuration and cd to project folder::

    sudo main.py -f config/route.conf -v


License
-------

Copyrite (c) 2014 `SecurityKISS Ltd <http://www.securitykiss.com>`__,
released under the `MIT License
