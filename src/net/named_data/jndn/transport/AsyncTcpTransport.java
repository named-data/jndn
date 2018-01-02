/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 *
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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

package net.named_data.jndn.transport;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousChannelGroup;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.encoding.ElementListener;
import net.named_data.jndn.encoding.ElementReader;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.util.Common;

/**
 * AsyncTcpTransport extends Transport for async communication over TCP by
 * dispatching reads from an AsynchronousSocketChannel to a
 * ScheduledExecutorService. On Android, this requires Android API level 26.
 *
 * If enabled in the connection information, this transport implements reconnection
 * logic if the:
 * 1. read completion handler fails
 * 2. write completion handler fails
 * 3. connect fails
 *
 * The reconnect is scheduled with a default 5 second delay on the same thread pool
 * passed in the constructor; only one reconnect will be scheduled at a time. During
 * the reconnection phase, reads and writes will fail (they would in any case because
 * the connection is broken). If the reconnect fails, it will schedule another reconnect
 * at the default interval. Note that while reconnect will solve the connection issue
 * after it succeeds, but will not re-register prefixes. This should must be handled
 * appropriately by client logic.
 *
 * To test the reconnect logic:
 * 1. launch nfd
 * 2. launch client using this transport
 * 3. wait prefix registered and some interests expressed successfully from client
 * 4. stop nfd
 * 5. client will catch IOException (broken pipe, connection refused, etc) when it tries
 * to express interests
 * 6. start nfd again
 * 7. client will be able to express interests again normally
 */
public class AsyncTcpTransport extends Transport
{
  public AsyncTcpTransport(ScheduledExecutorService threadPool) {
    threadPool_ = threadPool;

    // This is the CompletionHandler for asyncRead().
    readCompletionHandler_ = new CompletionHandler<Integer, Void>() {
      public void completed(Integer bytesRead, Void attachment) {
        // Need to catch and log exceptions at this async entry point.
        try {
          if (bytesRead > 0) {
            inputBuffer_.flip();
            elementReader_.onReceivedData(inputBuffer_);
          }

          // Repeatedly do async read.
          asyncRead();
        } catch (Throwable ex) {
          logger_.log(Level.SEVERE, null, ex);
        }
      }

      public void failed(Throwable ex, Void attachment) {
        logger_.log(Level.SEVERE, "Failed to read from transport", ex);
        if(connectionInfo_.shouldAttemptReconnection() && acquireReconnectLock()) {
          scheduleReconnect();
        }
      }
    };

    // This is the CompletionHandler for send().
    writeCompletionHandler_ = new CompletionHandler<Integer, ByteBuffer>() {
      public void completed(Integer bytesRead, ByteBuffer data) {
        // Need to catch and log exceptions at this async entry point.
        try {
          if (data.hasRemaining()) {
            channel_.write(data, data, writeCompletionHandler_);
          } else {
            writeLock_.release();
          }
        } catch (Throwable ex) {
          logger_.log(Level.SEVERE, null, ex);
        }
      }

      public void failed(Throwable ex, ByteBuffer data) {
        logger_.log(Level.SEVERE, "Failed to write to transport", ex);
        writeLock_.release();
        if(connectionInfo_.shouldAttemptReconnection() && acquireReconnectLock()) {
          scheduleReconnect();
        }
      }
    };
  }

  /**
   * AsyncTcpTransport.ConnectionInfo extends Transport.ConnectionInfo to hold
   * the host and port info for the TCP connection. The reconnection logic is
   * disabled by default.
   */
  public static class ConnectionInfo extends Transport.ConnectionInfo {
    /**
     * Create a ConnectionInfo with the given host and port.
     * @param host The host for the connection.
     * @param port The port number for the connection.
     * @param attemptReconnection if true, drop packets until reconnected within {@link #DEFAULT_RECONNECT_TRY_DELAY_MS}
     */
    public ConnectionInfo(String host, int port, boolean attemptReconnection) {
      host_ = host;
      port_ = port;
      attemptReconnection_ = attemptReconnection;
    }

    /**
     * Create a ConnectionInfo with the given host and port.
     * @param host The host for the connection.
     * @param port The port number for the connection.
     */
    public ConnectionInfo(String host, int port) {
      this(host, port, false);
    }

    /**
     * Create a ConnectionInfo with the given host and default port 6363
     * @param host The host for the connection.
     */
    public ConnectionInfo(String host) {
      this(host, 6363, false);
    }

    /**
     * Get the host given to the constructor.
     * @return The host.
     */
    public final String
    getHost() {
      return host_;
    }

    /**
     * Get the port given to the constructor.
     * @return The port number.
     */
    public final int
    getPort() {
      return port_;
    }

    /**
     * Get attemptReconnection flag; if true, drop packets until reconnected within {@link #DEFAULT_RECONNECT_TRY_DELAY_MS}
     * @return true if blockForReconnect
     */
    public final boolean
    shouldAttemptReconnection() {
      return attemptReconnection_;
    }

    private final String host_;
    private final int port_;
    private final boolean attemptReconnection_;
  }

  /**
   * Determine whether this transport connecting according to connectionInfo is
   * to a node on the current machine; results are cached. According to
   * http://redmine.named-data.net/projects/nfd/wiki/ScopeControl#local-face,
   * TCP transports with a loopback address are local. If connectionInfo
   * contains a host name, InetAddress will do a blocking DNS lookup; otherwise
   * it will parse the IP address and examine the first octet to determine if
   * it is a loopback address (e.g. first octet == 127).
   * @param connectionInfo An AsyncTcpTransport.ConnectionInfo with the host to
   * check.
   * @return True if the host is local, false if not.
   * @throws java.io.IOException
   */
  public boolean
  isLocal(Transport.ConnectionInfo connectionInfo) throws IOException {
    synchronized (isLocalLock_) {
      if (connectionInfo_ == null || !((ConnectionInfo) connectionInfo).getHost()
          .equals(connectionInfo_.getHost())) {
        isLocal_ = TcpTransport.getIsLocal
            (((ConnectionInfo) connectionInfo).getHost());
        connectionInfo_ = (ConnectionInfo) connectionInfo;
      }

      return isLocal_;
    }
  }

  /**
   * Override to return true since connect needs to use the onConnected callback.
   * @return True.
   */
  public boolean
  isAsync() {
    return true;
  }

  /**
   * Connect according to the info in ConnectionInfo, and use elementListener.
   * @param connectionInfo An AsyncTcpTransport.ConnectionInfo.
   * @param elementListener The ElementListener must remain valid during the
   * life of this object.
   * @param onConnected This calls onConnected.run() when the connection is
   * established. This is needed since connect is async.
   * @throws IOException For I/O error.
   */
  public void
  connect
  (Transport.ConnectionInfo connectionInfo, ElementListener elementListener,
   final Runnable onConnected)
      throws IOException {
    logger_.log(Level.FINE, "Connecting...");
    // TODO: Close a previous connection.

    channelGroup_ = AsynchronousChannelGroup.withThreadPool(threadPool_);
    channel_ = AsynchronousSocketChannel.open(channelGroup_);

    //store other info for reconnect
    this.connectionInfo_ = (ConnectionInfo) connectionInfo;
    this.elementListener_ = elementListener;
    this.onConnected_ = onConnected;

    // connect is already async, so no need to dispatch.
    channel_.connect
        (new InetSocketAddress
                (((ConnectionInfo) connectionInfo).getHost(),
                    ((ConnectionInfo) connectionInfo).getPort()),
            null,
            new CompletionHandler<Void, Void>() {
              public void completed(Void dummy, Void attachment) {
                logger_.log(Level.FINE, "Connected");
                // Need to catch and log exceptions at this async entry point.
                try {
                  if (onConnected != null)
                    onConnected.run();
                  asyncRead();
                } catch (Throwable ex) {
                  logger_.log(Level.SEVERE, null, ex);
                }
              }

              public void failed(Throwable ex, Void attachment) {
                logger_.log(Level.SEVERE, "Failed to connect", ex);
                if(connectionInfo_.shouldAttemptReconnection()){
                  scheduleReconnect();
                }
              }
            });

    elementReader_ = new ElementReader(elementListener);
  }

  /**
   * Attempt to reconnect to the NFD. If successful, the reconnect lock will
   * be released so that IO can continue; if the attempt fails, it will
   * schedule another reconnect attempt in the future.
   */
  private void
  reconnect() throws IOException {
    logger_.log(Level.FINE, "Reconnecting...");
    channel_ = AsynchronousSocketChannel.open(channelGroup_);

    // connect is already async, so no need to dispatch.
    channel_.connect
        (new InetSocketAddress
                (connectionInfo_.getHost(),
                    connectionInfo_.getPort()),
            null,
            new CompletionHandler<Void, Void>() {
              public void completed(Void dummy, Void attachment) {
                // Need to catch and log exceptions at this async entry point.
                reconnectLock_.release();
                try {
                  if (onConnected_ != null)
                    onConnected_.run();
                  asyncRead();
                } catch (Throwable ex) {
                  logger_.log(Level.SEVERE, null, ex);
                }
              }

              public void failed(Throwable ex, Void attachment) {
                logger_.log(Level.SEVERE, null, ex);
                scheduleReconnect();
              }
            });

    elementReader_ = new ElementReader(elementListener_);
  }

  /**
   * Helper method for acquiring the reconnect lock; any method attempting to
   * schedule a reconnect must acquire this lock
   *
   * @return true if the lock is acquired, false otherwise
   */
  private boolean
  acquireReconnectLock() {
    try {
      return reconnectLock_.tryAcquire(0, TimeUnit.MICROSECONDS);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return false;
    }
  }

  /**
   * On failure, this method is called to schedule a {@link #reconnect()} for some
   * configurable time in the future; any access to this method must be protected
   * by the reconnect so that only one reconnect is ever scheduled at a time.
   */
  private void
  scheduleReconnect() {
    logger_.log(Level.INFO, "Scheduled to reconnect in " + DEFAULT_RECONNECT_TRY_DELAY_MS + "ms");
    threadPool_.schedule(new Runnable() {
      public void run() {
        try {
          reconnect();
        } catch (IOException e) {
          logger_.log(Level.WARNING, null, e);
        }
      }
    }, DEFAULT_RECONNECT_TRY_DELAY_MS, TimeUnit.MILLISECONDS);
  }

  private void
  asyncRead() {
    inputBuffer_.limit(inputBuffer_.capacity());
    inputBuffer_.position(0);
    // We only call asyncRead after a previous call, so no need to dispatch.
    channel_.read(inputBuffer_, null, readCompletionHandler_);
  }

  /**
   * Send data to the host.
   * @param data The buffer of data to send.  This reads from position() to
   * limit(), but does not change the position.
   * @throws IOException For I/O error.
   */
  public void
  send(ByteBuffer data) throws IOException {
    if (reconnectLock_.availablePermits() < 1) {
      throw new IOException("Cannot send while the socket is reconnecting...");
    }

    if (!getIsConnected()) {
      throw new IOException("Cannot send because the socket is not open.  Use connect.");
    }

    // This does not copy the bytes, but only duplicates the position which is
    // updated by write(). We assume that the sender won't change the bytes of
    // the buffer during send, so that we can avoid a costly copy operation.
    data = data.duplicate();

    // The completion handler will call write again if needed, or will notify
    // to release the wait when finished writing.
    try {
      sendDataSequentially(data);
    } catch (InterruptedException e) {
      throw new IOException(e);
    }
  }

  /**
   * Send data buffers one-by-one; this is necessary because async IO writes
   * cannot overlap without a WritePendingException (see
   * https://docs.oracle.com/javase/7/docs/api/java/nio/channels/AsynchronousSocketChannel.html#write(java.nio.ByteBuffer))
   * @param data the buffer to send
   * @throws InterruptedException if an external agent interrupts the thread; usually this means that someone is trying
   * to close the
   * @throws IOException if the channel write fails
   */
  private void sendDataSequentially(ByteBuffer data) throws InterruptedException, IOException {
    if (!writeLock_.tryAcquire(DEFAULT_LOCK_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
      throw new IOException("Failed to acquire lock on channel to write buffer");
    }

    channel_.write(data, data, writeCompletionHandler_);
  }

  /**
   * Do nothing since AsynchronousSocketChannel checks for incoming data.
   */
  public void
  processEvents() throws IOException, EncodingException {
  }

  /**
   * Check if the transport is connected.
   * @return True if connected.
   */
  public boolean
  getIsConnected() throws IOException {
    return channel_ != null && channel_.getRemoteAddress() != null;
  }

  private AsynchronousSocketChannel channel_;
  private final CompletionHandler<Integer, Void> readCompletionHandler_;
  private final CompletionHandler<Integer, ByteBuffer> writeCompletionHandler_;
  private final ScheduledExecutorService threadPool_;
  private ByteBuffer inputBuffer_ = ByteBuffer.allocate(Common.MAX_NDN_PACKET_SIZE);
  private ElementReader elementReader_;
  private ConnectionInfo connectionInfo_;
  private boolean isLocal_;
  private final Object isLocalLock_ = new Object();
  private final Semaphore writeLock_ = new Semaphore(1);
  private static final Logger logger_ = Logger.getLogger
      (AsyncTcpTransport.class.getName());
  public static final int DEFAULT_LOCK_TIMEOUT_MS = 10000;
  public static final int DEFAULT_RECONNECT_TRY_DELAY_MS = 5000;
  private AsynchronousChannelGroup channelGroup_;
  private ElementListener elementListener_;
  private Runnable onConnected_;
  private final Semaphore reconnectLock_ = new Semaphore(1);
}