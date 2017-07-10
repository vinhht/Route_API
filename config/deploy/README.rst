routegen
======

``routegen`` is a tool that generates necessary PKI artifacts for route:

- root CA (Certificate Authority)
- server certificate and private key for each server


Deployment example
------------------
The typical deployment scenario is a single client (e.g. a central abuse detection and IP reputation system) and multiple route servers listening to firewall modification commands::

                                ======================
                                route server 11.11.11.11
    ======                      ======================
    client
    ======                      ======================
                                route server 22.22.22.22
                                ======================


Using routegen 
------------
You need to run ``routewgen`` for each route server while providing their IP addresses::

./routegen 11.11.11.11
./routegen 22.22.22.22

After running the above commands the folder tree should look like this::

    .
    ├── client
    │   └── ca.crt
    ├── offline
    │   └── ca.key
    ├── server_11.11.11.11
    │   ├── server.crt
    │   └── server.key
    └── server_22.22.22.22
        ├── server.crt
        └── server.key

``client/ca.crt`` and ``offline/ca.key`` are generated only when ``routegen`` runs first time. Folder names indicate where the files should be deployed:

- client - ca.crt should be imported to the client machine (and possibly also to the test HTTP client)
- offline - ca.key used for signing certificates. It should be kept secret, preferrably offline as security of the entire system depends on it
- server_xxx - server.crt and server.key should be deployed to route server with route.conf options pointing to their locations on the server

Using your own Certificate Authority complicates initial setup but makes it easier later to add new servers.
The client needs to import only a single CA once.
Adding a new server boils down to generating new certificate and deploying it on the server. The client will accept it without any modification on the client side. 

Import root CA in the client
----------------------------

Copy ``client/ca.crt`` to the client machine and then use it in the way depending on the client browser:

**curl client**

ca.crt can be provided as command line parameter with each query.

The complete curl request::

    curl -v --cacert <path_to_ca_crt> --user <username>:<passwd> https://<server_ip>:7393/

for example::

    curl -v --cacert config/deploy/client/ca.crt --user myuser:mypasswd https://11.11.11.11:7393/input/eth0/1.2.3.4

Alternatively, to avoid specifying the path to ca.crt with every request, you can add the CA cert to the existing default CA cert bundle. The default path of the CA bundle used can be changed by running configure with the --with-ca-bundle option pointing out the path of your choice.

You can also generate server certificate for localhost::

    curl -v --cacert config/deploy/client/ca.crt --user myuser:mypasswd https://127.0.0.1:7393/

Please note the numeric IP above. For consistency ``routegen`` accepts only IP addresses so you must use 127.0.0.1 instead of localhost.


Deploy keys to the server
-------------------------

Let's assume you deploy to the server with IP 11.11.11.11.

Copy ``server_11.11.11.11/server.crt`` and ``server_11.11.11.11/server.key`` for example to ``ssl/`` folder on host 11.11.11.11.
Update ``route.conf`` in order to point to these files::

    outward.server.certfile = <path>/ssl/server.crt

    outward.server.keyfile = <path>/ssl/server.key