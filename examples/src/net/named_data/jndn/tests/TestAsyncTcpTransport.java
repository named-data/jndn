/**
 * Copyright (C) 2015-2016 Intel Corporation.
 *
 * @author: Andrew Brown <andrew.brown@intel.com>
 * @author: Wei Yu <w.yu@intel.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU Lesser General Public License is in the file COPYING.
 */
package net.named_data.jndn.tests;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.Test;

import net.named_data.jndn.transport.AsyncTcpTransport;

public class TestAsyncTcpTransport {
  private static final Logger LOGGER = Logger.getLogger(TestAsyncTcpTransport.class.getName());
  private static final int PORT = 3098;
  private static int count = 0;
  private static ServerSocket server = null;

  /**
   * Test that reconnection logic does not break normal operation, i.e. make sure we didn't break the happy path
   */
  @Test
  public void testHappyPath() {
    // start the mock nfd first
    startMockNfd(PORT);

    // reset the count
    count = 0;

    // create pool for tcp transport
    ScheduledExecutorService pool = Executors.newScheduledThreadPool(3);

    // create and start tcp transport
    AsyncTcpTransport transport = createAndStartClient(pool);

    // start sending pings
    ScheduledExecutorService pool2 = Executors.newSingleThreadScheduledExecutor();
    send(pool2, transport, "ping");

    // allow enough time to receive some ping
    for (int i = 0; i < 10; i++) {
      sleep(1000);
      if (count > 0) {
        break;
      }
    }

    // stop server
    stopMockNfd(transport);

    // shutdown the pools
    shutdownPool(pool);
    shutdownPool(pool2);

    // make sure we received some pings
    assertTrue(count > 0);
  }


  /**
   * Test to mimic when the NFD is not up initially (but then starts) and the transport attempts to open and send data
   */
  @Test
  public void testWithoutServerInitiallyOn() {
    // create the pool
    ScheduledExecutorService pool = Executors.newScheduledThreadPool(3);

    // create and start the transport
    AsyncTcpTransport transport = createAndStartClient(pool);

    // start sending pings
    ScheduledExecutorService pool2 = Executors.newSingleThreadScheduledExecutor();
    send(pool2, transport, "ping1");

    // now start the mock nfd
    startMockNfd(PORT);

    // reset count so we know if count > 0 the transport reconnects successfully
    count = 0;

    // allow reconnect enough time to complete
    for (int i = 0; i < 10; i++) {
      sleep(1000);
      if (count > 0) {
        break;
      }
    }

    // stop server
    stopMockNfd(transport);

    // shutdown the pools
    shutdownPool(pool);
    shutdownPool(pool2);

    // we have received some pings
    assertTrue(count > 0);
  }

  /**
   * This tests a client constantly sending data and the reboot of mock NFD which triggers the reconnect
   */
  @Test
  public void testWithServerRebootWhileSending() {
    // start the mock nfd
    startMockNfd(PORT);

    // create the pool for transport
    ScheduledExecutorService pool = Executors.newScheduledThreadPool(3);

    // create and start the transport
    AsyncTcpTransport transport = createAndStartClient(pool);

    // start sending pings
    ScheduledExecutorService pool2 = Executors.newSingleThreadScheduledExecutor();
    send(pool2, transport, "ping2");

    // reboot the mock nfd by closing the current channel
    stopMockNfd(transport);

    // reset the count so if it is > 0 we know the reconnect is success
    count = 0;

    // allow reconnect enough time to complete
    for (int i = 0; i < 10; i++) {
      sleep(1000);
      if (count > 0) {
        break;
      }
    }

    // shutdown the server
    stopMockNfd(transport);

    // cleanup pools
    shutdownPool(pool);
    shutdownPool(pool2);

    // make sure we received some pings
    assertTrue(count > 0);
  }

  /**
   * this is to test reboot the nfd while client is not sending any data and client will reconnect after the next few
   * send request
   */
  @Test
  public void testWithServerRebootWhileIdling() {
    // start the mock nfd
    startMockNfd(PORT);

    // create the pool for transport
    ScheduledExecutorService pool = Executors.newScheduledThreadPool(3);

    // create and start the transport
    AsyncTcpTransport transport = createAndStartClient(pool);

    // start sending pings
    ScheduledExecutorService pool2 = Executors.newSingleThreadScheduledExecutor();
    send(pool2, transport, "ping3");

    // shutdown the send data pool
    shutdownPool(pool2);

    // close current channel of the mock nfd
    stopMockNfd(transport);

    // reset the count
    count = 0;

    // start sending again
    ScheduledExecutorService pool3 = Executors.newSingleThreadScheduledExecutor();
    send(pool3, transport, "ping4");

    // wait long enough for client to reconnect and send some pings
    for (int i = 0; i < 10; i++) {
      sleep(1000);
      if (count > 0) {
        break;
      }
    }

    // stop server
    stopMockNfd(transport);

    // shutdown the pools
    shutdownPool(pool);
    shutdownPool(pool3);

    // we should see something from client after reconnect
    assertTrue(count > 0);
  }

  private AsyncTcpTransport createAndStartClient(ScheduledExecutorService pool) {
    AsyncTcpTransport transport = new AsyncTcpTransport(pool);

    AsyncTcpTransport.ConnectionInfo cinfo = new AsyncTcpTransport.ConnectionInfo("localhost", PORT, true);
    try {
      transport.connect(cinfo, null, null);
    } catch (IOException e) {
      LOGGER.log(Level.WARNING, null, e);
    }
    return transport;
  }

  private void shutdownPool(ScheduledExecutorService pool) {
    pool.shutdown();
    try {
      pool.awaitTermination(10, TimeUnit.SECONDS);
    } catch (InterruptedException e) {
      LOGGER.log(Level.WARNING, null, e);
    }
  }

  private void send(final ScheduledExecutorService pool, final AsyncTcpTransport transport, final String ping) {
    pool.schedule(new Runnable() {
      public void run() {
        try {
          transport.send(ByteBuffer.wrap((ping + "\n").getBytes()));
        } catch (IOException e) {
          LOGGER.log(Level.WARNING, null, e);
        }
        send(pool, transport, ping);
      }
    }, 1, TimeUnit.SECONDS);
  }

  private void sleep(long ms) {
    try {
      Thread.sleep(ms);
    } catch (InterruptedException e) {
      LOGGER.log(Level.WARNING, null, e);
    }
  }

  private void stopMockNfd(AsyncTcpTransport transport) {
    try {
      transport.send(ByteBuffer.wrap("close\n".getBytes()));
    } catch (IOException e) {
      LOGGER.log(Level.WARNING, null, e);
    }
    sleep(3000);
  }

  private void startMockNfd(final int port) {
    if (server == null) {
      new Thread(new Runnable() {
        public void run() {
          try {
            server = new ServerSocket(port);
            while (true) {
              LOGGER.log(Level.INFO, "before accept new connection");
              new MockNfdChannel(server.accept());
              sleep(1000);
            }
          } catch (IOException e) {
            LOGGER.log(Level.WARNING, null, e);
          }
        }
      }).start();
    }
  }

  private class MockNfdChannel extends Thread {
    private final Socket client_;

    MockNfdChannel(Socket client) {
      this.client_ = client;
      start();
    }

    public void run() {
      try {
        LineNumberReader reader = new LineNumberReader(new InputStreamReader(client_.getInputStream()));
        String line;

        while ((line = reader.readLine()) != null) {
          if ("close".equals(line)) {
            LOGGER.log(Level.INFO, "exit received");
            break;
          } else {
            LOGGER.log(Level.INFO, "received:" + line);
            count++;
          }
        }
        reader.close();
      } catch (IOException e) {
        LOGGER.log(Level.WARNING, null, e);
      } finally {
        if (client_ != null) {
          try {
            client_.close();
          } catch (IOException e) {
            LOGGER.log(Level.WARNING, null, e);
          }
        }
      }
    }
  }
}
