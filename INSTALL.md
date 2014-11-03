jNDN:  A Named Data Networking client library for Java
======================================================

Prerequisites
=============

* Required: Java JDK version >= 1.7
* Required: Apache Ant (for building jndn.jar and running unit tests)
* Optional: Android SDK (for Android examples)
* Optional: Protobuf (for the ProtobufTlv converter and ChronoSync)

Following are the detailed steps for each platform to install the prerequisites.

## Mac OS X 10.7.3, Mac OS X 10.8.4
Install Xcode.
In Xcode Preferences > Downloads, install "Command Line Tools".

To install Apache Ant, install MacPorts from http://www.macports.org/install.php .
In a new terminal, enter:

    sudo port install apache-ant

Optional: To install Android SDK, install from https://developer.android.com/sdk/index.html .

## Mac OS X 10.9
Install Xcode.  (Xcode on OS X 10.9 seems to already have the Command Line Tools.)

To install Apache Ant, install MacPorts from http://www.macports.org/install.php .
In a new terminal, enter:

    sudo port install apache-ant

Optional: To install Android SDK, install from https://developer.android.com/sdk/index.html .

## Ubuntu 12.04 (64 bit and 32 bit), Ubuntu 14.04 (64 bit and 32 bit)
To install Apache Ant, in a terminal enter:

    sudo apt-get install ant

## Windows
jNDN is tested on Windows 7 64-bit.

To install Apache Ant, download the binary zip and set up environment variables
according to the instructions at http://ant.apache.org/manual/install.html .

Build
=====

To build in a terminal, change directory to the jNDN root.  Enter:

    ant

This builds the default target "dist" which puts jndn.jar in dist/lib.

To run the unit tests, in a terminal enter:

    ant test

To run a sample test file such as TestEncodeDecodeData (see the list below), in a terminal enter:

    java -cp $CLASSPATH:tests/build:dist/lib/jndn.jar net.named_data.jndn.tests.TestEncodeDecodeData

(On Windows, in a command prompt enter the following.)

    java -cp %CLASSPATH%;tests\build;dist\lib\jndn.jar net.named_data.jndn.tests.TestEncodeDecodeData

To make documentation and put into doc, in a terminal enter:
  
    find src -type f -name "*.java" | xargs javadoc -d doc

To run the Android samples, install the Android SDK as shown above. The samples
were tested by installing the following in the Android SDK Manager:
"Android SDK Build tools rev 21.1", all support for Android 5.0 (API 21),
"Extras / Android Support Repository" and "Extras / Android Support Library".
Also, in the Android Virtual Device Manager create an Android 5.0 device. Also,
import adt-bundle/sdk/extras/android/support/v7/appcompat into the workspace.

* samples/android/NDNPing: Ping an NDN testbed server and show the ping time.  To build, in Eclipse you need to right-click on src/net and fix the link to the jndn/src/net folder.

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
