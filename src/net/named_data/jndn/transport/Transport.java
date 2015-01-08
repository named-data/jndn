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

import java.io.IOException;
import java.nio.ByteBuffer;
import net.named_data.jndn.encoding.ElementListener;
import net.named_data.jndn.encoding.EncodingException;

public abstract class Transport {
  /**
   * A Transport.ConnectionInfo is a base class for connection information used
   * by subclasses of Transport.
   */
  public static class ConnectionInfo {
  }

  /**
   * Connect according to the info in ConnectionInfo, and use elementListener.
   * @param connectionInfo An object of a subclass of ConnectionInfo.
   * @param elementListener The ElementListener must remain valid during the
   * life of this object.
   * @throws IOException For I/O error.
   */
  public void
  connect
    (Transport.ConnectionInfo connectionInfo, ElementListener elementListener)
    throws IOException
  {
    throw new UnsupportedOperationException("connect is not implemented");
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
    throw new UnsupportedOperationException("send is not implemented");
  }

  /**
   * Process any data to receive.  For each element received, call
   * elementListener.onReceivedElement.
   * This is non-blocking and will silently time out after a brief period if
   * there is no data to receive.
   * You should repeatedly call this from an event loop.
   * You should normally not call this directly since it is called by
   * Face.processEvents.
   * If you call this from an main event loop, you may want to catch and
   * log/disregard all exceptions.
   * @throws IOException For I/O error.
   * @throws EncodingException For invalid encoding.
   */
  public abstract void
  processEvents() throws IOException, EncodingException;

  /**
   * Check if the transport is connected.
   * @return True if connected.
   */
  public boolean
  getIsConnected()
  {
    throw new UnsupportedOperationException
      ("getIsConnected is not implemented");
  }

  /**
   * Close the connection.  This base class implementation does nothing, but
   * your derived class can override.
   * @throws IOException For I/O error.
   */
  public void
  close() throws IOException
  {
  }
}
