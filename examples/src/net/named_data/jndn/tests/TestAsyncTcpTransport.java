/**
 * Copyright (C) 2015-2016 Intel Corporation.
 *
 * @author: Andrew Brown <andrew.brown@intel.com>
 * @author: Wei Yu <w.yu@intel.com>
 * <p>
 * This program is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General
 * Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 * <p>
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
 * details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public License along with this program.  If not, see
 * <http://www.gnu.org/licenses/>. A copy of the GNU Lesser General Public License is in the file COPYING.
 */
package net.named_data.jndn.tests;

import net.named_data.jndn.transport.AsyncTcpTransport;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

public class TestAsyncTcpTransport {
  private static final Logger LOGGER = Logger.getLogger(TestAsyncTcpTransport.class.getName());
  private static final String NFD_HOST = "localhost";
  private static final int NFD_PORT = 3098;
  private static final int NUM_THREADS_IN_POOL = 3;
  private static final int RECONNECT_DELAY_MS = 10;

  private ScheduledExecutorService pool;
  private MockNfd nfd;
  private AsyncTcpTransport transport;
  private AsyncTcpTransport.ConnectionInfo connectionInfo;

  public static void main(String[] args) throws Exception {
    // disable logging from AsyncTcpTransport to not pollute the console output
    Logger.getLogger(AsyncTcpTransport.class.getName()).setLevel(Level.OFF);

    TestAsyncTcpTransport instance = new TestAsyncTcpTransport();

    instance.before();
    try {
      instance.testHappyPath();
    } catch (Throwable e) {
      LOGGER.log(Level.SEVERE, "Failed to run test", e);
    } finally {
      instance.after();
    }

    instance.before();
    try {
      instance.testWithoutServerInitiallyOn();
    } catch (Throwable e) {
      LOGGER.log(Level.SEVERE, "Failed to run test", e);
    } finally {
      instance.after();
    }

    instance.before();
    try {
      instance.testWithServerRebootWhileIdling();
    } catch (Throwable e) {
      LOGGER.log(Level.SEVERE, "Failed to run test", e);
    } finally {
      instance.after();
    }

    instance.before();
    try {
      instance.testWithServerRebootWhileSending();
    } catch (Throwable e) {
      LOGGER.log(Level.SEVERE, "Failed to run test", e);
    } finally {
      instance.after();
    }

    LOGGER.info("Tests complete");
  }

  private void before() {
    nfd = new MockNfd(NFD_PORT);
    pool = Executors.newScheduledThreadPool(NUM_THREADS_IN_POOL);
    transport = new AsyncTcpTransport(pool);
    connectionInfo = new AsyncTcpTransport.ConnectionInfo(NFD_HOST, NFD_PORT, RECONNECT_DELAY_MS);
  }

  private void after() throws Exception {
    nfd.stop();
    transport.close();
    pool.shutdownNow();
  }

  /**
   * Test that reconnection logic does not break normal operation, i.e. make sure we didn't break the happy path
   */
  private void testHappyPath() throws Exception {
    LOGGER.info("testHappyPath()");

    nfd.start();
    transport.connect(connectionInfo, null, null);

    sendPacketWhile("happy path", new Condition() {
      @Override
      public boolean test(int numAttempts) {
        return nfd.packetCount() < 1 && numAttempts < 10;
      }
    });

    // make sure we received some pings
    if (nfd.packetCount() <= 0) throw new AssertionError();
  }

  /**
   * Test to mimic when the NFD is not up initially (but then starts) and the transport attempts to open and sendPacket
   * data
   */
  private void testWithoutServerInitiallyOn() throws Exception {
    LOGGER.info("testWithoutServerInitiallyOn()");

    transport.connect(connectionInfo, null, null);

    sendPacket("not up initially");

    nfd.start();

    sendPacketWhile("not up initially", new Condition() {
      @Override
      public boolean test(int numAttempts) {
        return nfd.packetCount() < 1 && numAttempts < 10;
      }
    });

    // make sure we received some pings
    if (nfd.packetCount() <= 0) throw new AssertionError();
  }

  private void sendPacket(String bytes) {
    try {
      LOGGER.info("Sending: " + bytes);
      transport.send(ByteBuffer.wrap((bytes + "\n").getBytes()));
    } catch (IOException e) {
      LOGGER.fine("This exception may be expected... the NFD may not be running");
    }
  }

  interface Condition {
    boolean test(int numAttempts);
  }

  private void sendPacketWhile(String bytes, Condition condition) {
    int numAttempts = 0;
    while (condition.test(numAttempts)) {
      sendPacket(bytes);
      numAttempts++;
      sleep(1);
    }
  }

  /**
   * This tests a client constantly sending data and the reboot of mock NFD which triggers the reconnect
   */
  private void testWithServerRebootWhileSending() throws Exception {
    nfd.start();

    transport.connect(connectionInfo, null, null);

    assert (nfd.packetCount() == 0);

    nfd.stop();

    sendPacket("nfd reboot");
    assert (nfd.packetCount() == 0);

    nfd.start();

    sendPacketWhile("nfd reboot", new Condition() {
      @Override
      public boolean test(int numAttempts) {
        return nfd.packetCount() < 1 && numAttempts < 10;
      }
    });

    assert (nfd.packetCount() > 0);
  }

  /**
   * this is to test reboot the nfd while client is not sending any data and client will reconnect after the next few
   * sendPacket request
   */
  private void testWithServerRebootWhileIdling() throws Exception {
    nfd.start();

    transport.connect(connectionInfo, null, null);

    assert (nfd.packetCount() == 0);

    nfd.stop();

    assert (!transport.getIsConnected());

    nfd.start();

    sleep(1000);

    assert (!transport.getIsConnected());
  }

  private void sleep(long ms) {
    try {
      Thread.sleep(ms);
    } catch (InterruptedException e) {
      LOGGER.log(Level.WARNING, e.getMessage());
    }
  }

  private class MockNfd implements Runnable {
    private final int port;
    private Thread thread;
    private ServerSocket server;
    private volatile boolean running;
    private final CountDownLatch started = new CountDownLatch(1);
    private final List<MockNfdReader> readers = new ArrayList<>();
    private final AtomicInteger packetsRead = new AtomicInteger(0);

    MockNfd(int port) {
      this.port = port;
    }

    void start() throws InterruptedException {
      thread = new Thread(this);
      thread.setName("MockNfdThread");
      thread.setDaemon(true);
      thread.start();
      if (!started.await(10, TimeUnit.SECONDS)) throw new IllegalStateException("The mock NFD never started running.");
      LOGGER.info("Started mock NFD");
    }

    public void run() {
      running = true;
      started.countDown();

      try {
        server = new ServerSocket(port);
        while (running) {
          Socket incoming = server.accept(); // blocking call
          MockNfdReader r = new MockNfdReader(incoming, packetsRead);
          r.start();
          readers.add(r);
          //sleep(1000);
        }
      } catch (IOException e) {
        LOGGER.log(Level.FINEST, "Failed to open new connection", e);
      }
    }

    void stop() throws IOException {
      LOGGER.info("Stopping mock NFD...");
      running = false;
      server.close();
      for (MockNfdReader r : readers) {
        r.close();
      }
    }

    int packetCount() {
      return packetsRead.get();
    }
  }

  private class MockNfdReader implements Runnable {
    private final LineNumberReader reader_;
    private final Socket client_;
    private Thread thread;
    private final AtomicInteger packetsRead;

    MockNfdReader(Socket client, AtomicInteger packetsRead) throws IOException {
      LOGGER.info("New mock NFD connection");
      this.packetsRead = packetsRead;
      this.client_ = client;
      reader_ = new LineNumberReader(new InputStreamReader(client_.getInputStream()));
    }

    void start() {
      thread = new Thread(this);
      thread.setName("MockNfdReaderThread");
      thread.setDaemon(true);
      thread.start();
      LOGGER.info("Started mock NFD connection");
    }

    public void run() {
      try {
        String line;
        while ((line = reader_.readLine()) != null) {
          LOGGER.log(Level.INFO, "Received new packet: " + line);
          packetsRead.incrementAndGet();
        }
        reader_.close();
      } catch (IOException e) {
        LOGGER.log(Level.FINEST, "Failed to read packets", e);
      }
    }

    public void close() throws IOException {
      LOGGER.info("Closing mock NFD connection");
      client_.close();
    }
  }
}
