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
package src.net.named_data.jndn.tests.integration_tests;

import net.named_data.jndn.transport.AsyncTcpTransport;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

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
  private Condition EXPECT_PACKET_UNDER_10_ATTEMPTS = new Condition() {
    @Override
    public boolean test(int numAttempts) {
      return nfd.packetCount() < 1 && numAttempts < 10;
    }
  };

  @BeforeClass
  public static void
  beforeClass() {
    // disable logging from AsyncTcpTransport to not pollute the console output
    Logger.getLogger(AsyncTcpTransport.class.getName()).setLevel(Level.OFF);
  }

  @Before
  public void
  before() throws Exception {
    nfd = new TestAsyncTcpTransport.MockNfd(NFD_PORT);
    pool = Executors.newScheduledThreadPool(NUM_THREADS_IN_POOL);
    transport = new AsyncTcpTransport(pool);
    connectionInfo = new AsyncTcpTransport.ConnectionInfo(NFD_HOST, NFD_PORT, RECONNECT_DELAY_MS);
  }

  @After
  public void
  after() throws Exception {
    nfd.stop();
    transport.close();
    pool.shutdownNow();
  }

  /**
   * Test that reconnection logic does not break normal operation, i.e. make sure we didn't break the happy path
   */
  @Test
  public void
  testHappyPath() throws Exception {
    LOGGER.info("testHappyPath()");

    nfd.start();
    connectAndAwait(transport, connectionInfo);

    sendPacketWhile("happy path", EXPECT_PACKET_UNDER_10_ATTEMPTS);

    // make sure we received some pings
    assertTrue(nfd.packetCount() > 0);
  }

  /**
   * Test to mimic when the NFD is not up initially (but then starts) and the transport attempts to open and sendPacket
   * data
   */
  @Test
  public void
  testWithoutServerInitiallyOn() throws Exception {
    LOGGER.info("testWithoutServerInitiallyOn()");

    transport.connect(connectionInfo, null, null);

    sendPacket("not up initially");

    nfd.start();

    sendPacketWhile("not up initially", EXPECT_PACKET_UNDER_10_ATTEMPTS);

    // make sure we received some pings
    assertTrue(nfd.packetCount() > 0);
  }

  /**
   * This tests a client constantly sending data and the reboot of mock NFD which triggers the reconnect
   */
  @Test
  public void
  testWithServerRebootWhileSending() throws Exception {
    nfd.start();

    connectAndAwait(transport, connectionInfo);

    nfd.stop();

    nfd.start();

    sendPacketWhile("nfd reboot", EXPECT_PACKET_UNDER_10_ATTEMPTS);

    assertTrue(nfd.packetCount() > 0);
  }

  /**
   * this is to test reboot the nfd while client is not sending any data and client will reconnect after the next few
   * sendPacket request
   */
  @Test
  public void
  testWithServerRebootWhileIdling() throws Exception {
    nfd.start();

    connectAndAwait(transport, connectionInfo);
    assertEquals(0, nfd.packetCount());

    nfd.stop();

    sleep(100);
    sendPacket("reboot while idling");
    sleep(100);
    assertEquals(0, nfd.packetCount());

    nfd.start();

    sleep(100);
    assertTrue(sendPacket("reboot while idling"));
    assertTrue(transport.getIsConnected());
  }

  private void
  connectAndAwait(AsyncTcpTransport transport, AsyncTcpTransport.ConnectionInfo connectionInfo) throws IOException, InterruptedException {
    final CountDownLatch latch = new CountDownLatch(1);
    transport.connect(connectionInfo, null, new Runnable() {
      @Override
      public void run() {
        latch.countDown();
      }
    });
    assertTrue(latch.await(10, TimeUnit.SECONDS));
  }

  private boolean
  sendPacket(String bytes) {
    try {
      LOGGER.info("Sending: " + bytes);
      transport.send(ByteBuffer.wrap((bytes + "\n").getBytes()));
      return true;
    } catch (IOException e) {
      LOGGER.fine("This exception may be expected... the NFD may not be running");
      return false;
    }
  }

  private interface Condition {
    boolean test(int numAttempts);
  }

  private void
  sendPacketWhile(String bytes, Condition condition) {
    int numAttempts = 0;
    while (condition.test(numAttempts)) {
      sendPacket(bytes);
      numAttempts++;
      sleep(RECONNECT_DELAY_MS); // wait the same amount of time between reconnect delays to coincide with an interval when the connection is re-established
    }
  }

  private void
  sleep(long ms) {
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
    private CountDownLatch started = new CountDownLatch(1);
    private List<MockNfdReader> readers = new ArrayList<>();
    private AtomicInteger packetsRead = new AtomicInteger(0);

    MockNfd(int port) {
      this.port = port;
    }

    /**
     * Start the mock NFD thread and return once it is running
     *
     * @throws InterruptedException in the unlikely event the thread is interrupted
     */
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
          Socket incoming = server.accept(); // blocking call, requiring another check to run
          if (!running) break;
          MockNfdReader r = new MockNfdReader(incoming, packetsRead);
          r.start();
          readers.add(r);
        }
      } catch (IOException | InterruptedException e) {
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
    private AtomicInteger packetsRead;

    MockNfdReader(Socket client, AtomicInteger packetsRead) throws IOException {
      LOGGER.info("New mock NFD connection");
      this.packetsRead = packetsRead;
      this.client_ = client;
      reader_ = new LineNumberReader(new InputStreamReader(client_.getInputStream()));
    }

    void start() throws InterruptedException {
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

    void close() throws IOException {
      LOGGER.info("Closing mock NFD connection");
      client_.close();
    }
  }
}