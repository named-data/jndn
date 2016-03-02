/**
 * Copyright (C) 2015-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.encoding.ElementListener;
import net.named_data.jndn.encoding.ElementReader;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.util.Common;

/**
 * AsyncTcpTransport extends Transport for async communication over TCP by
 * dispatching reads from an AsynchronousSocketChannel to a
 * ScheduledExecutorService.
 */
public class AsyncTcpTransport extends Transport {
  public AsyncTcpTransport(ScheduledExecutorService threadPool)
  {
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

          // Repeatedly do  async read.
          asyncRead();
        } catch (Throwable ex) {
          logger_.log(Level.SEVERE, null, ex);
        }
      }

      public void failed(Throwable ex, Void attachment) {
        logger_.log(Level.SEVERE, null, ex);
      }};
  }

  /**
   * AsyncTcpTransport.ConnectionInfo extends Transport.ConnectionInfo to hold
   * the host and port info for the TCP connection.
   */
  public static class ConnectionInfo extends Transport.ConnectionInfo {
    /**
     * Create a ConnectionInfo with the given host and port.
     * @param host The host for the connection.
     * @param port The port number for the connection.
     */
    public
    ConnectionInfo(String host, int port)
    {
      host_ = host;
      port_ = port;
    }

    /**
     * Create a ConnectionInfo with the given host and default port 6363.
     * @param host The host for the connection.
     */
    public
    ConnectionInfo(String host)
    {
      host_ = host;
      port_ = 6363;
    }

    /**
     * Get the host given to the constructor.
     * @return The host.
     */
    public final String
    getHost() { return host_; }

    /**
     * Get the port given to the constructor.
     * @return The port number.
     */
    public final int
    getPort() { return port_; }

    private final String host_;
    private final int port_;
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
  isLocal(Transport.ConnectionInfo connectionInfo) throws IOException
  {
    synchronized(isLocalLock_) {
      if(connectionInfo_ == null || !((ConnectionInfo)connectionInfo).getHost()
        .equals(connectionInfo_.getHost()))
      {
        isLocal_ = TcpTransport.getIsLocal
          (((ConnectionInfo)connectionInfo).getHost());
        connectionInfo_ = (ConnectionInfo)connectionInfo;
      }

      return isLocal_;
    }
  }

  /**
   * Override to return true since connect needs to use the onConnected callback.
   * @return True.
   */
  public boolean
  isAsync() { return true; }

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
    throws IOException
  {
    // TODO: Close a previous connection.

    channel_ = AsynchronousSocketChannel.open
      (AsynchronousChannelGroup.withThreadPool(threadPool_));
    // connect is already async, so no need to dispatch.
    channel_.connect
      (new InetSocketAddress
         (((ConnectionInfo)connectionInfo).getHost(),
          ((ConnectionInfo)connectionInfo).getPort()),
       null,
       new CompletionHandler<Void, Void>() {
         public void completed(Void dummy, Void attachment) {
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
           logger_.log(Level.SEVERE, null, ex);
         }});

    elementReader_ = new ElementReader(elementListener);
  }

  private void
  asyncRead()
  {
    inputBuffer_.limit(inputBuffer_.capacity());
    inputBuffer_.position(0);
    // read is already async, so no need to dispatch.
    channel_.read(inputBuffer_, null, readCompletionHandler_);
  }

  /**
   * Send data to the host.
   * @param data The buffer of data to send.  This reads from position() to
   * limit(), but does not change the position.
   * @throws IOException For I/O error.
   */
  public void
  send(ByteBuffer data) throws IOException
  {
    if (!getIsConnected())
      throw new IOException
        ("Cannot send because the socket is not open.  Use connect.");

    // Save and restore the position.
    // TODO: Copy the buffer so that the sending thread doesn't change it?
    int savePosition = data.position();
    try {
      while (data.hasRemaining())
        // write is already async, so no need to dispatch.
        // TODO: The CompletionHandler should write remaining bytes.
        channel_.write(data);
    }
    finally {
      data.position(savePosition);
    }
  }

  /**
   * Do nothing since AsynchronousSocketChannel checks for incoming data.
   */
  public void
  processEvents() throws IOException, EncodingException
  {
  }

  /**
   * Check if the transport is connected.
   * @return True if connected.
   */
  public boolean
  getIsConnected() throws IOException
  {
    if (channel_ == null)
      return false;

    return channel_.getRemoteAddress() != null;
  }

  private AsynchronousSocketChannel channel_;
  private final CompletionHandler<Integer, Void> readCompletionHandler_;
  private final ScheduledExecutorService threadPool_;
  private ByteBuffer inputBuffer_ = ByteBuffer.allocate(Common.MAX_NDN_PACKET_SIZE);
  private ElementReader elementReader_;
  private ConnectionInfo connectionInfo_;
  private boolean isLocal_;
  private final Object isLocalLock_ = new Object();
  private static final Logger logger_ = Logger.getLogger
    (AsyncTcpTransport.class.getName());
}
