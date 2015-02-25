/**
 * Copyright (C) 2013-2015 Regents of the University of California.
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

import java.nio.channels.SocketChannel;
import java.net.InetSocketAddress;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import net.named_data.jndn.encoding.ElementListener;
import net.named_data.jndn.encoding.ElementReader;
import net.named_data.jndn.encoding.EncodingException;

public class TcpTransport extends Transport {
  /**
   * A TcpTransport.ConnectionInfo extends Transport.ConnectionInfo to hold
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
   * Determine whether the current transport is to a node on the current
   * machine; results are cached. According to
   * http://redmine.named-data.net/projects/nfd/wiki/ScopeControl#local-face,
   * TCP transports with a loopback address are local. If connectionInfo 
   * contains a host name, InetAddress will do a blocking DNS lookup; otherwise
   * it will parse the IP address and examine the first octet to determine if
   * it is a loopback address (e.g. first octet == 127).
   *
   * @param connectionInfo
   * @return 
   * @throws java.io.IOException 
   */
  public boolean isLocal(Transport.ConnectionInfo connectionInfo) 
    throws IOException
  {
    if(connectionInfo != connectionInfo_){
      connectionInfo_ = (ConnectionInfo) connectionInfo;
      InetAddress address = InetAddress.getByName(connectionInfo_.getHost());
      isLocal_ = address.isLoopbackAddress();
    }
    return isLocal_;
  }

  /**
   * Connect according to the info in ConnectionInfo, and use elementListener.
   * @param connectionInfo A TcpTransport.ConnectionInfo.
   * @param elementListener The ElementListener must remain valid during the
   * life of this object.
   * @throws IOException For I/O error.
   */
  public void
  connect
    (Transport.ConnectionInfo connectionInfo, ElementListener elementListener)
    throws IOException
  {
    close();

    channel_ = SocketChannel.open
      (new InetSocketAddress(((ConnectionInfo)connectionInfo).getHost(),
       ((ConnectionInfo)connectionInfo).getPort()));
    channel_.configureBlocking(false);

    elementReader_ = new ElementReader(elementListener);
  }

  /**
   * Set data to the host
   * @param data The buffer of data to send.  This reads from position() to
   * limit(), but does not change the position.
   * @throws IOException For I/O error.
   */
  public void
  send(ByteBuffer data) throws IOException
  {
    if (channel_ == null)
      throw new IOException
        ("Cannot send because the socket is not open.  Use connect.");

    // Save and restore the position.
    int savePosition = data.position();
    try {
      while(data.hasRemaining())
        channel_.write(data);
    }
    finally {
      data.position(savePosition);
    }
  }

  /**
   * Process any data to receive.  For each element received, call
   * elementListener.onReceivedElement.
   * This is non-blocking and will return immediately if there is no data to
   * receive. You should normally not call this directly since it is called by
   * Face.processEvents.
   * If you call this from an main event loop, you may want to catch and
   * log/disregard all exceptions.
   * @throws IOException For I/O error.
   * @throws EncodingException For invalid encoding.
   */
  public void
  processEvents() throws IOException, EncodingException
  {
    if (!getIsConnected())
      return;

    while (true) {
      inputBuffer_.limit(inputBuffer_.capacity());
      inputBuffer_.position(0);
      int bytesRead = channel_.read(inputBuffer_);
      if (bytesRead <= 0)
        return;

      inputBuffer_.flip();
      elementReader_.onReceivedData(inputBuffer_);
    }
  }

  /**
   * Check if the transport is connected.
   * @return True if connected.
   */
  public boolean
  getIsConnected()
  {
    if (channel_ == null)
      return false;

    return channel_.isConnected();
  }

  /**
   * Close the connection.  If not connected, this does nothing.
   * @throws IOException For I/O error.
   */
  public void
  close() throws IOException
  {
    if (channel_ != null) {
      if (channel_.isConnected())
        channel_.close();
      channel_ = null;
    }
  }

  SocketChannel channel_;
  ByteBuffer inputBuffer_ = ByteBuffer.allocate(8000);
  // TODO: This belongs in the socket listener.
  private ElementReader elementReader_;
  private ConnectionInfo connectionInfo_;
  private boolean isLocal_;
}
