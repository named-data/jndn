jNDN:  A Named Data Networking client library for Java
======================================================

Prerequisites
=============

* Required: Java JDK version >= 1.7
* Required: Apache Ant (for building jndn.jar and running unit tests)

Following are the detailed steps for each platform to install the prerequisites.

## Mac OS X 10.7.3, Mac OS X 10.8.4
Install Xcode.
In Xcode Preferences > Downloads, install "Command Line Tools".

To install Apache Ant, install MacPorts from http://www.macports.org/install.php .
In a new terminal, enter:

    sudo port install apache-ant

## Mac OS X 10.9
Install Xcode.  (Xcode on OS X 10.9 seems to already have the Command Line Tools.)

To install Apache Ant, install MacPorts from http://www.macports.org/install.php .
In a new terminal, enter:

    sudo port install apache-ant

## Ubuntu 12.04 (64 bit and 32 bit), Ubuntu 14.04 (64 bit and 32 bit)
To install Apache Ant, in a terminal enter:

    sudo apt-get install ant

Build
=====

To build in a terminal, change directory to the jNDN root.  Enter:

    ant

This builds the default target "dist" which puts jndn.jar in dist/lib.

To run the unit tests, in a terminal enter:

    ant test

To run a sample test file such as TestEncodeDecodeData (see the list below), in a terminal enter:

    java -cp tests/build:dist/lib/jndn.jar net.named_data.jndn.tests.TestEncodeDecodeData

To make documentation and put into doc, in a terminal enter:
  
    find src -type f -name "*.java" | xargs javadoc -d doc

Files
=====
This makes the following library:

* dist/lib/jndn.jar: The jNDN library.

This makes the following test class files in tests/build/net/named_data/jndn/tests:

* TestGetAsync: Connect to one of the NDN testbed hubs, express an interest and display the received data.
* TestPublishAsyncNdnx: Connect to the local NDNx hub, accept interests with prefix /testecho and echo back a data packet. See test-echo-consumer.
* TestPublishAsyncNfd: Connect to the local NFD hub, accept interests with prefix /testecho and echo back a data packet. See test-echo-consumer.
* TestEchoConsumer: Prompt for a word, send the interest /testecho/word to the local hub which is echoed by test-publish-async-nfd (or test-publish-async-ndnx).
* TestEncodeDecodeInterest: Encode and decode an interest, testing interest selectors and the name URI.
* TestEncodeDecodeData: Encode and decode a data packet, including signing the data packet.
* TestEncodeDecodeForwardingEntry: Encode and decode an NDNx forwarding entry.

Running javadoc puts code documentation in doc.
