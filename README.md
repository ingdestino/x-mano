FNRM: The Multidomain Federator and Orchestrator
================================================

### What is the FNRM?
The FNRM a multidomain service orchestrator that leverage on existing SOs (Service Orchestrator, see ETSI Mano) for allowing the definition of federations.

This program has been developed for the "Vital" european project (Grant Agreement No: 644843).

### Top-Level Features
* Support for any SO thanks to the FA (Federation Agent) that wraps domain-specific features into a standard format
* Support for programmable network services (NS) that extends flexibility beyond the ETSI Mano standard.
* REST API for accessing the Northbound abstractions
* Support for massive VNFs data storage (NoSQL database)
* Plugin based domain controlling logic
* Basic VNF statistics available through REST interface
* Possibility to recursively federate many FMs together, both vertically and horizontally, resulting in federations of federations

### Requirements
The FNRM requires the following applications, between brackets it is reported the version that has been tested:
* Python 3 (3.4.3)
* RabbitMQ (3.2.4)
* MongoDB (3.2.9)

Since the FNRM is entirely developed in Python, the following packages are necessary (tested version between brackets):
* configobj (5.0.6)
* pika (0.10.0)
* pymongo (3.3.0)
* PyYAML (3.11)
* requests (2.10.0)
* tornado (4.3)

FNRM and dependencies have been tested with Ubuntu 14.04 LTS, Windows 8.1 and Windows 10

### Setup
Both the FM and the FA expect to retrieve configuration information from files located in:

Linux:
* /etc/federation/FM/federator_default.cfg
* /etc/federation/FA/agent_default.cfg

Windows:
* C:\federation\config\FM\federator_default.cfg
* C:\federation\config\FA\agent_default.cfg

Alternatively, the configuration file path can be passed as an argument.

Please check the sample configuration files in the repo

### Run
Run the FM and FA as follow:

    python3 federator_main.py [config_file]
    python3 agent_main.py [config_file]

It is not mandatory to specify the config file, as long as it is already located in the default directory

### Other Info

Checkout out our [website](http://www.ict-vital.eu/)

Code is released under the Apache License, Version 2.0.