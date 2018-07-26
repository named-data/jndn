/**
 * Copyright (C) 2014-2018 Regents of the University of California.
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

package net.named_data.jndn;

import java.io.IOException;
import java.nio.ByteBuffer;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.transport.TcpTransport;
import net.named_data.jndn.transport.Transport;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

/**
 * The Face class provides the main methods for NDN communication.
 */
public class Face {
  /**
   * Create a new Face for communication with an NDN hub with the given
   * Transport object and connectionInfo.
   * @param transport A Transport object used for communication.
   * @param connectionInfo A Transport.ConnectionInfo to be used to connect to
   * the transport.
   */
  public Face(Transport transport, Transport.ConnectionInfo connectionInfo)
  {
    node_ = new Node(transport, connectionInfo);
  }

  /**
   * Create a new Face for communication with an NDN hub at host:port using the
   * default TcpTransport.
   * @param host The host of the NDN hub.
   * @param port The port of the NDN hub.
   */
  public Face(String host, int port)
  {
    node_ = new Node
      (new TcpTransport(), new TcpTransport.ConnectionInfo(host, port));
  }

  /**
   * Create a new Face for communication with an NDN hub at host using the
   * default port 6363 and the default TcpTransport.
   * @param host The host of the NDN hub.
   */
  public Face(String host)
  {
    node_ = new Node
      (new TcpTransport(), new TcpTransport.ConnectionInfo(host, 6363));
  }

  /**
   * Create a new Face for communication with an NDN hub at "localhost" using the
   * default port 6363 and the default TcpTransport.
   */
  public Face()
  {
    node_ = new Node
      (new TcpTransport(), new TcpTransport.ConnectionInfo("localhost", 6363));
  }

  /**
   * Send the Interest through the transport, read the entire response and call
   * onData, onTimeout or onNetworkNack as described below.
   * @param interest The Interest to send.  This copies the Interest.
   * @param onData  When a matching data packet is received, this calls
   * onData.onData(interest, data) where interest is the interest given to
   * expressInterest and data is the received Data object. NOTE: You must not
   * change the interest object - if you need to change it then make a copy.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onTimeout If the interest times out according to the interest
   * lifetime, this calls onTimeout.onTimeout(interest) where interest is the
   * interest given to expressInterest. If onTimeout is null, this does not use
   * it.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onNetworkNack When a network Nack packet for the interest is
   * received and onNetworkNack is not null, this calls
   * onNetworkNack.onNetworkNack(interest, networkNack) and does not call
   * onTimeout. However, if a network Nack is received and onNetworkNack is null,
   * do nothing and wait for the interest to time out. (Therefore, an
   * application which does not yet process a network Nack reason treats a
   * Nack the same as a timeout.)
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param wireFormat A WireFormat object used to encode the message.
   * @return The pending interest ID which can be used with
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
   * @throws Error If the encoded interest size exceeds getMaxNdnPacketSize().
   */
  public long
  expressInterest
    (Interest interest, OnData onData, OnTimeout onTimeout,
     OnNetworkNack onNetworkNack, WireFormat wireFormat) throws IOException
  {
    long pendingInterestId = node_.getNextEntryId();

    // This copies the interest as required by Node.expressInterest.
    node_.expressInterest
      (pendingInterestId, interest, onData, onTimeout, onNetworkNack,
       wireFormat, this);

    return pendingInterestId;
  }

  /**
   * Send the Interest through the transport, read the entire response and call
   * onData, onTimeout or onNetworkNack as described below.
   * This uses the default WireFormat.getDefaultWireFormat().
   * @param interest The Interest to send.  This copies the Interest.
   * @param onData  When a matching data packet is received, this calls
   * onData.onData(interest, data) where interest is the interest given to
   * expressInterest and data is the received Data object. NOTE: You must not
   * change the interest object - if you need to change it then make a copy.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onTimeout If the interest times out according to the interest
   * lifetime, this calls onTimeout.onTimeout(interest) where interest is the
   * interest given to expressInterest. If onTimeout is null, this does not use
   * it.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onNetworkNack When a network Nack packet for the interest is
   * received and onNetworkNack is not null, this calls
   * onNetworkNack.onNetworkNack(interest, networkNack) and does not call
   * onTimeout. However, if a network Nack is received and onNetworkNack is null,
   * do nothing and wait for the interest to time out. (Therefore, an
   * application which does not yet process a network Nack reason treats a
   * Nack the same as a timeout.)
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @return The pending interest ID which can be used with
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
   * @throws Error If the encoded interest size exceeds getMaxNdnPacketSize().
   */
  public long
  expressInterest
    (Interest interest, OnData onData, OnTimeout onTimeout,
     OnNetworkNack onNetworkNack) throws IOException
  {
    return expressInterest
      (interest, onData, onTimeout, onNetworkNack,
       WireFormat.getDefaultWireFormat());
  }

  /**
   * Send the Interest through the transport, read the entire response and call
   * onData or onTimeout as described below.
   * @param interest The Interest to send.  This copies the Interest.
   * @param onData  When a matching data packet is received, this calls
   * onData.onData(interest, data) where interest is the interest given to
   * expressInterest and data is the received Data object. NOTE: You must not
   * change the interest object - if you need to change it then make a copy.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onTimeout If the interest times out according to the interest
   * lifetime, this calls onTimeout.onTimeout(interest) where interest is the
   * interest given to expressInterest. If onTimeout is null, this does not use
   * it.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param wireFormat A WireFormat object used to encode the message.
   * @return The pending interest ID which can be used with
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
   * @throws Error If the encoded interest size exceeds getMaxNdnPacketSize().
   */
  public long
  expressInterest
    (Interest interest, OnData onData, OnTimeout onTimeout,
     WireFormat wireFormat) throws IOException
  {
    return expressInterest(interest, onData, onTimeout, null, wireFormat);
  }

  /**
   * Send the Interest through the transport, read the entire response and call
   * onData or onTimeout as described below.
   * This uses the default WireFormat.getDefaultWireFormat().
   * @param interest The Interest to send.  This copies the Interest.
   * @param onData  When a matching data packet is received, this calls
   * onData.onData(interest, data) where interest is the interest given to
   * expressInterest and data is the received Data object. NOTE: You must not
   * change the interest object - if you need to change it then make a copy.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onTimeout If the interest times out according to the interest
   * lifetime, this calls onTimeout.onTimeout(interest) where interest is the
   * interest given to expressInterest. If onTimeout is null, this does not use
   * it.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @return The pending interest ID which can be used with
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
   * @throws Error If the encoded interest size exceeds getMaxNdnPacketSize().
   */
  public long
  expressInterest
    (Interest interest, OnData onData, OnTimeout onTimeout) throws IOException
  {
    return expressInterest
      (interest, onData, onTimeout, WireFormat.getDefaultWireFormat());
  }

  /**
   * Send the Interest through the transport, read the entire response and call
   * onData as described below.
   * Ignore if the interest times out.
   * @param interest The Interest to send.  This copies the Interest.
   * @param onData  When a matching data packet is received, this calls
   * onData.onData(interest, data) where interest is the interest given to
   * expressInterest and data is the received Data object. NOTE: You must not
   * change the interest object - if you need to change it then make a copy.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param wireFormat A WireFormat object used to encode the message.
   * @return The pending interest ID which can be used with
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
   * @throws Error If the encoded interest size exceeds getMaxNdnPacketSize().
   */
  public long
  expressInterest
    (Interest interest, OnData onData, WireFormat wireFormat) throws IOException
  {
    return expressInterest(interest, onData, null, wireFormat);
  }

  /**
   * Send the Interest through the transport, read the entire response and call
   * onData as described below.
   * Ignore if the interest times out.
   * This uses the default WireFormat.getDefaultWireFormat().
   * @param interest The Interest to send.  This copies the Interest.
   * @param onData  When a matching data packet is received, this calls
   * onData.onData(interest, data) where interest is the interest given to
   * expressInterest and data is the received Data object. NOTE: You must not
   * change the interest object - if you need to change it then make a copy.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @return The pending interest ID which can be used with
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
   * @throws Error If the encoded interest size exceeds getMaxNdnPacketSize().
   */
  public long
  expressInterest(Interest interest, OnData onData) throws IOException
  {
    return expressInterest
      (interest, onData, null, WireFormat.getDefaultWireFormat());
  }

  /**
   * Encode name as an Interest. If interestTemplate is not null, use its
   * interest selectors.
   * Send the Interest through the transport, read the entire response and call
   * onData, onTimeout or onNetworkNack as described below.
   * @param name A Name for the interest. This copies the Name.
   * @param interestTemplate If not null, copy interest selectors from the
   * template. This does not keep a pointer to the Interest object.
   * @param onData  When a matching data packet is received, this calls
   * onData.onData(interest, data) where interest is the interest given to
   * expressInterest and data is the received Data object. NOTE: You must not
   * change the interest object - if you need to change it then make a copy.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onTimeout If the interest times out according to the interest
   * lifetime, this calls onTimeout.onTimeout(interest) where interest is the
   * interest given to expressInterest. If onTimeout is null, this does not use
   * it.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onNetworkNack When a network Nack packet for the interest is
   * received and onNetworkNack is not null, this calls
   * onNetworkNack.onNetworkNack(interest, networkNack) and does not call
   * onTimeout. However, if a network Nack is received and onNetworkNack is null,
   * do nothing and wait for the interest to time out. (Therefore, an
   * application which does not yet process a network Nack reason treats a
   * Nack the same as a timeout.)
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param wireFormat A WireFormat object used to encode the message.
   * @return The pending interest ID which can be used with
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
   * @throws Error If the encoded interest size exceeds getMaxNdnPacketSize().
   */
  public long
  expressInterest
    (Name name, Interest interestTemplate, OnData onData, OnTimeout onTimeout,
     OnNetworkNack onNetworkNack, WireFormat wireFormat) throws IOException
  {
    long pendingInterestId = node_.getNextEntryId();

    // This copies the name object as required by Node.expressInterest.
    node_.expressInterest
      (pendingInterestId, getInterestCopy(name, interestTemplate), onData,
       onTimeout, onNetworkNack, wireFormat, this);

    return pendingInterestId;
  }

  /**
   * Encode name as an Interest. If interestTemplate is not null, use its
   * interest selectors.
   * Send the Interest through the transport, read the entire response and call
   * onData, onTimeout or onNetworkNack as described below.
   * This uses the default WireFormat.getDefaultWireFormat().
   * @param name A Name for the interest. This copies the Name.
   * @param interestTemplate If not null, copy interest selectors from the
   * template. This does not keep a pointer to the Interest object.
   * @param onData  When a matching data packet is received, this calls
   * onData.onData(interest, data) where interest is the interest given to
   * expressInterest and data is the received Data object. NOTE: You must not
   * change the interest object - if you need to change it then make a copy.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onTimeout If the interest times out according to the interest
   * lifetime, this calls onTimeout.onTimeout(interest) where interest is the
   * interest given to expressInterest. If onTimeout is null, this does not use
   * it.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onNetworkNack When a network Nack packet for the interest is
   * received and onNetworkNack is not null, this calls
   * onNetworkNack.onNetworkNack(interest, networkNack) and does not call
   * onTimeout. However, if a network Nack is received and onNetworkNack is null,
   * do nothing and wait for the interest to time out. (Therefore, an
   * application which does not yet process a network Nack reason treats a
   * Nack the same as a timeout.)
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @return The pending interest ID which can be used with
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
   * @throws Error If the encoded interest size exceeds getMaxNdnPacketSize().
   */
  public long
  expressInterest
    (Name name, Interest interestTemplate, OnData onData, OnTimeout onTimeout,
     OnNetworkNack onNetworkNack) throws IOException
  {
    return expressInterest
      (name, interestTemplate, onData, onTimeout, onNetworkNack,
       WireFormat.getDefaultWireFormat());
  }

  /**
   * Encode name as an Interest, using a default interest lifetime.
   * Send the Interest through the transport, read the entire response and call
   * onData, onTimeout or onNetworkNack as described below.
   * @param name A Name for the interest. This copies the Name.
   * @param onData  When a matching data packet is received, this calls
   * onData.onData(interest, data) where interest is the interest given to
   * expressInterest and data is the received Data object. NOTE: You must not
   * change the interest object - if you need to change it then make a copy.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onTimeout If the interest times out according to the interest
   * lifetime, this calls onTimeout.onTimeout(interest) where interest is the
   * interest given to expressInterest. If onTimeout is null, this does not use
   * it.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onNetworkNack When a network Nack packet for the interest is
   * received and onNetworkNack is not null, this calls
   * onNetworkNack.onNetworkNack(interest, networkNack) and does not call
   * onTimeout. However, if a network Nack is received and onNetworkNack is null,
   * do nothing and wait for the interest to time out. (Therefore, an
   * application which does not yet process a network Nack reason treats a
   * Nack the same as a timeout.)
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param wireFormat A WireFormat object used to encode the message.
   * @return The pending interest ID which can be used with
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
   * @throws Error If the encoded interest size exceeds getMaxNdnPacketSize().
   */
  public long
  expressInterest
    (Name name, OnData onData, OnTimeout onTimeout, OnNetworkNack onNetworkNack,
     WireFormat wireFormat) throws IOException
  {
    return expressInterest
      (name, null, onData, onTimeout, onNetworkNack, wireFormat);
  }

  /**
   * Encode name as an Interest, using a default interest lifetime.
   * Send the Interest through the transport, read the entire response and call
   * onData, onTimeout or onNetworkNack as described below.
   * This uses the default WireFormat.getDefaultWireFormat().
   * @param name A Name for the interest. This copies the Name.
   * @param onData  When a matching data packet is received, this calls
   * onData.onData(interest, data) where interest is the interest given to
   * expressInterest and data is the received Data object. NOTE: You must not
   * change the interest object - if you need to change it then make a copy.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onTimeout If the interest times out according to the interest
   * lifetime, this calls onTimeout.onTimeout(interest) where interest is the
   * interest given to expressInterest. If onTimeout is null, this does not use
   * it.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onNetworkNack When a network Nack packet for the interest is
   * received and onNetworkNack is not null, this calls
   * onNetworkNack.onNetworkNack(interest, networkNack) and does not call
   * onTimeout. However, if a network Nack is received and onNetworkNack is null,
   * do nothing and wait for the interest to time out. (Therefore, an
   * application which does not yet process a network Nack reason treats a
   * Nack the same as a timeout.)
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @return The pending interest ID which can be used with
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
   * @throws Error If the encoded interest size exceeds getMaxNdnPacketSize().
   */
  public long
  expressInterest
    (Name name, OnData onData, OnTimeout onTimeout, OnNetworkNack onNetworkNack)
      throws IOException
  {
    return expressInterest
      (name, null, onData, onTimeout, onNetworkNack,
       WireFormat.getDefaultWireFormat());
  }

  /**
   * Encode name as an Interest. If interestTemplate is not null, use its
   * interest selectors.
   * Send the Interest through the transport, read the entire response and call
   * onData or onTimeout as described below.
   * @param name A Name for the interest. This copies the Name.
   * @param interestTemplate If not null, copy interest selectors from the
   * template. This does not keep a pointer to the Interest object.
   * @param onData  When a matching data packet is received, this calls
   * onData.onData(interest, data) where interest is the interest given to
   * expressInterest and data is the received Data object. NOTE: You must not
   * change the interest object - if you need to change it then make a copy.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onTimeout If the interest times out according to the interest
   * lifetime, this calls onTimeout.onTimeout(interest) where interest is the
   * interest given to expressInterest. If onTimeout is null, this does not use
   * it.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param wireFormat A WireFormat object used to encode the message.
   * @return The pending interest ID which can be used with
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
   * @throws Error If the encoded interest size exceeds getMaxNdnPacketSize().
   */
  public long
  expressInterest
    (Name name, Interest interestTemplate, OnData onData, OnTimeout onTimeout,
     WireFormat wireFormat) throws IOException
  {
    return expressInterest
      (name, interestTemplate, onData, onTimeout, null, wireFormat);
  }

  /**
   * Encode name as an Interest, using a default interest lifetime.
   * Send the Interest through the transport, read the entire response and call
   * onData or onTimeout as described below.
   * @param name A Name for the interest. This copies the Name.
   * @param onData  When a matching data packet is received, this calls
   * onData.onData(interest, data) where interest is the interest given to
   * expressInterest and data is the received Data object. NOTE: You must not
   * change the interest object - if you need to change it then make a copy.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onTimeout If the interest times out according to the interest
   * lifetime, this calls onTimeout.onTimeout(interest) where interest is the
   * interest given to expressInterest. If onTimeout is null, this does not use
   * it.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param wireFormat A WireFormat object used to encode the message.
   * @return The pending interest ID which can be used with
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
   * @throws Error If the encoded interest size exceeds getMaxNdnPacketSize().
   */
  public long
  expressInterest
    (Name name, OnData onData, OnTimeout onTimeout,
     WireFormat wireFormat) throws IOException
  {
    return expressInterest(name, null, onData, onTimeout, wireFormat);
  }

  /**
   * Encode name as an Interest. If interestTemplate is not null, use its
   * interest selectors.
   * Send the Interest through the transport, read the entire response and call
   * onData as described below.
   * Ignore if the interest times out.
   * @param name A Name for the interest. This copies the Name.
   * @param interestTemplate If not null, copy interest selectors from the
   * template. This does not keep a pointer to the Interest object.
   * @param onData  When a matching data packet is received, this calls
   * onData.onData(interest, data) where interest is the interest given to
   * expressInterest and data is the received Data object. NOTE: You must not
   * change the interest object - if you need to change it then make a copy.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param wireFormat A WireFormat object used to encode the message.
   * @return The pending interest ID which can be used with
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
   * @throws Error If the encoded interest size exceeds getMaxNdnPacketSize().
   */
  public long
  expressInterest
    (Name name, Interest interestTemplate, OnData onData,
     WireFormat wireFormat) throws IOException
  {
    return expressInterest(name, interestTemplate, onData, null, wireFormat);
  }

  /**
   * Encode name as an Interest. If interestTemplate is not null, use its
   * interest selectors.
   * Send the Interest through the transport, read the entire response and call
   * onData or onTimeout as described below.
   * This uses the default WireFormat.getDefaultWireFormat().
   * @param name A Name for the interest. This copies the Name.
   * @param interestTemplate If not null, copy interest selectors from the
   * template. This does not keep a pointer to the Interest object.
   * @param onData  When a matching data packet is received, this calls
   * onData.onData(interest, data) where interest is the interest given to
   * expressInterest and data is the received Data object. NOTE: You must not
   * change the interest object - if you need to change it then make a copy.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onTimeout If the interest times out according to the interest
   * lifetime, this calls onTimeout.onTimeout(interest) where interest is the
   * interest given to expressInterest. If onTimeout is null, this does not use
   * it.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @return The pending interest ID which can be used with
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
   * @throws Error If the encoded interest size exceeds getMaxNdnPacketSize().
   */
  public long
  expressInterest
    (Name name, Interest interestTemplate, OnData onData,
     OnTimeout onTimeout) throws IOException
  {
    return expressInterest
      (name, interestTemplate, onData, onTimeout,
       WireFormat.getDefaultWireFormat());
  }

  /**
   * Encode name as an Interest. If interestTemplate is not null, use its
   * interest selectors.
   * Send the Interest through the transport, read the entire response and call
   * onData as described below.
   * Ignore if the interest times out.
   * This uses the default WireFormat.getDefaultWireFormat().
   * @param name A Name for the interest. This copies the Name.
   * @param interestTemplate If not null, copy interest selectors from the
   * template. This does not keep a pointer to the Interest object.
   * @param onData  When a matching data packet is received, this calls
   * onData.onData(interest, data) where interest is the interest given to
   * expressInterest and data is the received Data object. NOTE: You must not
   * change the interest object - if you need to change it then make a copy.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @return The pending interest ID which can be used with
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
   * @throws Error If the encoded interest size exceeds getMaxNdnPacketSize().
   */
  public long
  expressInterest
    (Name name, Interest interestTemplate, OnData onData) throws IOException
  {
    return expressInterest
      (name, interestTemplate, onData, null, WireFormat.getDefaultWireFormat());
  }

  /**
   * Encode name as an Interest, using a default interest lifetime.
   * Send the Interest through the transport, read the entire response and call
   * onData or onTimeout as described below.
   * This uses the default WireFormat.getDefaultWireFormat().
   * @param name A Name for the interest. This copies the Name.
   * @param onData  When a matching data packet is received, this calls
   * onData.onData(interest, data) where interest is the interest given to
   * expressInterest and data is the received Data object. NOTE: You must not
   * change the interest object - if you need to change it then make a copy.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onTimeout If the interest times out according to the interest
   * lifetime, this calls onTimeout.onTimeout(interest) where interest is the
   * interest given to expressInterest. If onTimeout is null, this does not use
   * it.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @return The pending interest ID which can be used with
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
   * @throws Error If the encoded interest size exceeds getMaxNdnPacketSize().
   */
  public long
  expressInterest
    (Name name, OnData onData, OnTimeout onTimeout) throws IOException
  {
    return expressInterest
      (name, null, onData, onTimeout, WireFormat.getDefaultWireFormat());
  }

  /**
   * Encode name as an Interest, using a default interest lifetime.
   * Send the Interest through the transport, read the entire response and call
   * onData as described below.
   * Ignore if the interest times out.
   * @param name A Name for the interest. This copies the Name.
   * @param onData  When a matching data packet is received, this calls
   * onData.onData(interest, data) where interest is the interest given to
   * expressInterest and data is the received Data object. NOTE: You must not
   * change the interest object - if you need to change it then make a copy.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param wireFormat A WireFormat object used to encode the message.
   * @return The pending interest ID which can be used with
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
   * @throws Error If the encoded interest size exceeds getMaxNdnPacketSize().
   */
  public long
  expressInterest
    (Name name, OnData onData, WireFormat wireFormat) throws IOException
  {
    return expressInterest(name, null, onData, null, wireFormat);
  }

  /**
   * Encode name as an Interest, using a default interest lifetime.
   * Send the Interest through the transport, read the entire response and call
   * onData as described below.
   * Ignore if the interest times out.
   * This uses the default WireFormat.getDefaultWireFormat().
   * @param name A Name for the interest. This copies the Name.
   * @param onData  When a matching data packet is received, this calls
   * onData.onData(interest, data) where interest is the interest given to
   * expressInterest and data is the received Data object. NOTE: You must not
   * change the interest object - if you need to change it then make a copy.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @return The pending interest ID which can be used with
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
   * @throws Error If the encoded interest size exceeds getMaxNdnPacketSize().
   */
  public long
  expressInterest(Name name, OnData onData) throws IOException
  {
    return expressInterest
      (name, null, onData, null, WireFormat.getDefaultWireFormat());
  }

  /**
   * Remove the pending interest entry with the pendingInterestId from the
   * pending interest table. This does not affect another pending interest with
   * a different pendingInterestId, even if it has the same interest name.
   * If there is no entry with the pendingInterestId, do nothing.
   * @param pendingInterestId The ID returned from expressInterest.
   */
  public void
  removePendingInterest(long pendingInterestId)
  {
    node_.removePendingInterest(pendingInterestId);
  }

  /**
   * Set the KeyChain and certificate name used to sign command interests
   * (e.g. for registerPrefix).
   * @param keyChain The KeyChain object for signing interests, which
   * must remain valid for the life of this Face. You must create the KeyChain
   * object and pass it in. You can create a default KeyChain for your
   * system with the default KeyChain constructor.
   * @param certificateName The certificate name for signing interests.
   * This makes a copy of the Name. You can get the default certificate name
   * with keyChain.getDefaultCertificateName() .
   */
  public void
  setCommandSigningInfo(KeyChain keyChain, Name certificateName)
  {
    commandKeyChain_ = keyChain;
    commandCertificateName_ = new Name(certificateName);
  }

  /**
   * Set the certificate name used to sign command interest (e.g. for
   * registerPrefix), using the KeyChain that was set with setCommandSigningInfo.
   * @param certificateName The certificate name for signing interest.
   * This makes a copy of the Name.
   */
  public void
  setCommandCertificateName(Name certificateName)
  {
    commandCertificateName_ = new Name(certificateName);
  }

  /**
   * Append a timestamp component and a random value component to interest's
   * name. Then use the keyChain and certificateName from setCommandSigningInfo
   * to sign the interest. If the interest lifetime is not set, this sets it.
   * @param interest The interest whose name is appended with components.
   * @param wireFormat A WireFormat object used to encode the SignatureInfo and
   * to encode the interest name for signing.
   * @throws SecurityException If cannot find the private key for the
   * certificateName.
   * @note This method is an experimental feature. See the API docs for more detail at
   * http://named-data.net/doc/ndn-ccl-api/face.html#face-makecommandinterest-method .
   */
  public void
  makeCommandInterest(Interest interest, WireFormat wireFormat) throws SecurityException
  {
    node_.makeCommandInterest
      (interest, commandKeyChain_, commandCertificateName_, wireFormat);
  }

  /**
   * Append a timestamp component and a random value component to interest's
   * name. Then use the keyChain and certificateName from setCommandSigningInfo
   * to sign the interest. If the interest lifetime is not set, this sets it.
   * Use the default WireFormat to encode the SignatureInfo and to encode the
   * interest name for signing.
   * @param interest The interest whose name is appended with components.
   * @throws SecurityException If cannot find the private key for the
   * certificateName.
   * @note This method is an experimental feature. See the API docs for more detail at
   * http://named-data.net/doc/ndn-ccl-api/face.html#face-makecommandinterest-method .
   */
  public void
  makeCommandInterest(Interest interest) throws SecurityException
  {
    makeCommandInterest(interest, WireFormat.getDefaultWireFormat());
  }

  /**
   * Register prefix with the connected NDN hub and call onInterest when a
   * matching interest is received. To register a prefix with NFD, you must
   * first call setCommandSigningInfo.
   * @param prefix A Name for the prefix to register. This copies the Name.
   * @param onInterest If not null, this creates an interest filter from prefix
   * so that when an Interest is received which matches the filter, this calls
   * onInterest.onInterest(prefix, interest, face, interestFilterId, filter).
   * The onInterest callback should supply the Data with face.putData().
   * NOTE: You must not change the prefix or filter objects - if you need to
   * change them then make a copy.
   * If onInterest is null, it is ignored and you must call setInterestFilter.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onRegisterFailed If register prefix fails for any reason, this
   * calls onRegisterFailed.onRegisterFailed(prefix).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onRegisterSuccess This calls
   * onRegisterSuccess.onRegisterSuccess(prefix, registeredPrefixId) when this
   * receives a success message from the forwarder. If onRegisterSuccess is null,
   * this does not use it. (The onRegisterSuccess parameter comes after
   * onRegisterFailed because it can be null or omitted, unlike onRegisterFailed.)
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param flags The flags for finer control of which interests are forwarded
   * to the application.
   * @param wireFormat A WireFormat object used to encode the message.
   * @return The registered prefix ID which can be used with
   * removeRegisteredPrefix.
   * @throws IOException For I/O error in sending the registration request.
   * @throws SecurityException If signing a command interest for NFD and cannot
   * find the private key for the certificateName.
   */
  public long
  registerPrefix
    (Name prefix, OnInterestCallback onInterest,
     OnRegisterFailed onRegisterFailed, OnRegisterSuccess onRegisterSuccess,
     ForwardingFlags flags, WireFormat wireFormat)
    throws IOException, SecurityException
  {
    // Get the registeredPrefixId now so we can return it to the caller.
    long registeredPrefixId = node_.getNextEntryId();

    node_.registerPrefix
      (registeredPrefixId, prefix, onInterest, onRegisterFailed,
       onRegisterSuccess, flags, wireFormat, commandKeyChain_,
       commandCertificateName_, this);

    return registeredPrefixId;
  }

  /**
   * @deprecated Use
   * registerPrefix(prefix, onInterest, onRegisterFailed, onRegisterSuccess, flags, wireFormat)
   * where the onRegisterSuccess parameter comes after onRegisterFailed.
   */
  public long
  registerPrefix
    (Name prefix, OnInterestCallback onInterest,
     OnRegisterSuccess onRegisterSuccess, OnRegisterFailed onRegisterFailed,
     ForwardingFlags flags, WireFormat wireFormat)
    throws IOException, SecurityException
  {
    return registerPrefix
      (prefix, onInterest, onRegisterFailed, onRegisterSuccess, flags, wireFormat);
  }

  /**
   * Register prefix with the connected NDN hub and call onInterest when a
   * matching interest is received.
   * This uses the default WireFormat.getDefaultWireFormat().
   * @param prefix A Name for the prefix to register. This copies the Name.
   * @param onInterest If not null, this creates an interest filter from prefix
   * so that when an Interest is received which matches the filter, this calls
   * onInterest.onInterest(prefix, interest, face, interestFilterId, filter).
   * The onInterest callback should supply the Data with face.putData().
   * NOTE: You must not change the prefix or filter objects - if you need to
   * change them then make a copy.
   * If onInterest is null, it is ignored and you must call setInterestFilter.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onRegisterFailed If register prefix fails for any reason, this
   * calls onRegisterFailed.onRegisterFailed(prefix).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onRegisterSuccess This calls
   * onRegisterSuccess.onRegisterSuccess(prefix, registeredPrefixId) when this
   * receives a success message from the forwarder. If onRegisterSuccess is null,
   * this does not use it. (The onRegisterSuccess parameter comes after
   * onRegisterFailed because it can be null or omitted, unlike onRegisterFailed.)
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param flags The flags for finer control of which interests are forwarded
   * to the application.
   * @return The registered prefix ID which can be used with
   * removeRegisteredPrefix.
   * @throws IOException For I/O error in sending the registration request.
   */
  public long
  registerPrefix
    (Name prefix, OnInterestCallback onInterest,
     OnRegisterFailed onRegisterFailed, OnRegisterSuccess onRegisterSuccess,
     ForwardingFlags flags) throws IOException, SecurityException
  {
    return registerPrefix
      (prefix, onInterest, onRegisterFailed, onRegisterSuccess, flags,
       WireFormat.getDefaultWireFormat());
  }

  /**
   * @deprecated Use
   * registerPrefix(prefix, onInterest, onRegisterFailed, onRegisterSuccess, flags)
   * where the onRegisterSuccess parameter comes after onRegisterFailed.
   */
  public long
  registerPrefix
    (Name prefix, OnInterestCallback onInterest,
     OnRegisterSuccess onRegisterSuccess, OnRegisterFailed onRegisterFailed,
     ForwardingFlags flags) throws IOException, SecurityException
  {
    return registerPrefix
      (prefix, onInterest, onRegisterFailed, onRegisterSuccess, flags,
       WireFormat.getDefaultWireFormat());
  }

  /**
   * Register prefix with the connected NDN hub and call onInterest when a
   * matching interest is received.
   * Use default ForwardingFlags.
   * @param prefix A Name for the prefix to register. This copies the Name.
   * @param onInterest If not null, this creates an interest filter from prefix
   * so that when an Interest is received which matches the filter, this calls
   * onInterest.onInterest(prefix, interest, face, interestFilterId, filter).
   * The onInterest callback should supply the Data with face.putData().
   * NOTE: You must not change the prefix or filter objects - if you need to
   * change them then make a copy.
   * If onInterest is null, it is ignored and you must call setInterestFilter.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onRegisterFailed If register prefix fails for any reason, this
   * calls onRegisterFailed.onRegisterFailed(prefix).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onRegisterSuccess This calls
   * onRegisterSuccess.onRegisterSuccess(prefix, registeredPrefixId) when this
   * receives a success message from the forwarder. If onRegisterSuccess is null,
   * this does not use it. (The onRegisterSuccess parameter comes after
   * onRegisterFailed because it can be null or omitted, unlike onRegisterFailed.)
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param wireFormat A WireFormat object used to encode the message.
   * @return The registered prefix ID which can be used with
   * removeRegisteredPrefix.
   * @throws IOException For I/O error in sending the registration request.
   * @throws SecurityException If signing a command interest for NFD and cannot
   * find the private key for the certificateName.
   */
  public long
  registerPrefix
    (Name prefix, OnInterestCallback onInterest,
     OnRegisterFailed onRegisterFailed, OnRegisterSuccess onRegisterSuccess,
     WireFormat wireFormat) throws IOException, SecurityException
  {
    return registerPrefix
      (prefix, onInterest, onRegisterFailed, onRegisterSuccess,
       new ForwardingFlags(), wireFormat);
  }

  /**
   * @deprecated Use
   * registerPrefix(prefix, onInterest, onRegisterFailed, onRegisterSuccess, wireFormat)
   * where the onRegisterSuccess parameter comes after onRegisterFailed.
   */
  public long
  registerPrefix
    (Name prefix, OnInterestCallback onInterest,
     OnRegisterSuccess onRegisterSuccess, OnRegisterFailed onRegisterFailed,
     WireFormat wireFormat) throws IOException, SecurityException
  {
    return registerPrefix
      (prefix, onInterest, onRegisterFailed, onRegisterSuccess,
       new ForwardingFlags(), wireFormat);
  }

  /**
   * Register prefix with the connected NDN hub and call onInterest when a
   * matching interest is received.
   * This uses the default WireFormat.getDefaultWireFormat().
   * Use default ForwardingFlags.
   * @param prefix A Name for the prefix to register. This copies the Name.
   * @param onInterest If not null, this creates an interest filter from prefix
   * so that when an Interest is received which matches the filter, this calls
   * onInterest.onInterest(prefix, interest, face, interestFilterId, filter).
   * The onInterest callback should supply the Data with face.putData().
   * NOTE: You must not change the prefix or filter objects - if you need to
   * change them then make a copy.
   * If onInterest is null, it is ignored and you must call setInterestFilter.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onRegisterFailed If register prefix fails for any reason, this
   * calls onRegisterFailed.onRegisterFailed(prefix).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onRegisterSuccess This calls
   * onRegisterSuccess.onRegisterSuccess(prefix, registeredPrefixId) when this
   * receives a success message from the forwarder. If onRegisterSuccess is null,
   * this does not use it. (The onRegisterSuccess parameter comes after
   * onRegisterFailed because it can be null or omitted, unlike onRegisterFailed.)
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @return The registered prefix ID which can be used with
   * removeRegisteredPrefix.
   * @throws IOException For I/O error in sending the registration request.
   * @throws SecurityException If signing a command interest for NFD and cannot
   * find the private key for the certificateName.
   */
  public long
  registerPrefix
    (Name prefix, OnInterestCallback onInterest,
     OnRegisterFailed onRegisterFailed, OnRegisterSuccess onRegisterSuccess)
    throws IOException, SecurityException
  {
    return registerPrefix
      (prefix, onInterest, onRegisterFailed, onRegisterSuccess,
       new ForwardingFlags(), WireFormat.getDefaultWireFormat());
  }

  /**
   * @deprecated Use
   * registerPrefix(prefix, onInterest, onRegisterFailed, onRegisterSuccess)
   * where the onRegisterSuccess parameter comes after onRegisterFailed.
   */
  public long
  registerPrefix
    (Name prefix, OnInterestCallback onInterest,
     OnRegisterSuccess onRegisterSuccess, OnRegisterFailed onRegisterFailed)
    throws IOException, SecurityException
  {
    return registerPrefix
      (prefix, onInterest, onRegisterFailed, onRegisterSuccess,
       new ForwardingFlags(), WireFormat.getDefaultWireFormat());
  }

  /**
   * Register prefix with the connected NDN hub and call onInterest when a
   * matching interest is received. To register a prefix with NFD, you must
   * first call setCommandSigningInfo.
   * @param prefix A Name for the prefix to register. This copies the Name.
   * @param onInterest If not null, this creates an interest filter from prefix
   * so that when an Interest is received which matches the filter, this calls
   * onInterest.onInterest(prefix, interest, face, interestFilterId, filter).
   * The onInterest callback should supply the Data with face.putData().
   * NOTE: You must not change the prefix or filter objects - if you need to
   * change them then make a copy.
   * If onInterest is null, it is ignored and you must call setInterestFilter.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onRegisterFailed If register prefix fails for any reason, this
   * calls onRegisterFailed.onRegisterFailed(prefix).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param flags The flags for finer control of which interests are forwarded
   * to the application.
   * @param wireFormat A WireFormat object used to encode the message.
   * @return The registered prefix ID which can be used with
   * removeRegisteredPrefix.
   * @throws IOException For I/O error in sending the registration request.
   * @throws SecurityException If signing a command interest for NFD and cannot
   * find the private key for the certificateName.
   */
  public long
  registerPrefix
    (Name prefix, OnInterestCallback onInterest,
     OnRegisterFailed onRegisterFailed, ForwardingFlags flags,
     WireFormat wireFormat) throws IOException, SecurityException
  {
    return registerPrefix
      (prefix, onInterest, onRegisterFailed, null, flags, wireFormat);
  }

  /**
   * Register prefix with the connected NDN hub and call onInterest when a
   * matching interest is received. To register a prefix with NFD, you must
   * first call setCommandSigningInfo.
   * This uses the default WireFormat.getDefaultWireFormat().
   * @param prefix A Name for the prefix to register. This copies the Name.
   * @param onInterest If not null, this creates an interest filter from prefix
   * so that when an Interest is received which matches the filter, this calls
   * onInterest.onInterest(prefix, interest, face, interestFilterId, filter).
   * The onInterest callback should supply the Data with face.putData().
   * NOTE: You must not change the prefix or filter objects - if you need to
   * change them then make a copy.
   * If onInterest is null, it is ignored and you must call setInterestFilter.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onRegisterFailed If register prefix fails for any reason, this
   * calls onRegisterFailed.onRegisterFailed(prefix).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param flags The flags for finer control of which interests are forwarded
   * to the application.
   * @return The registered prefix ID which can be used with
   * removeRegisteredPrefix.
   * @throws IOException For I/O error in sending the registration request.
   */
  public long
  registerPrefix
    (Name prefix, OnInterestCallback onInterest, OnRegisterFailed onRegisterFailed,
     ForwardingFlags flags) throws IOException, SecurityException
  {
    return registerPrefix
      (prefix, onInterest, onRegisterFailed, null, flags,
       WireFormat.getDefaultWireFormat());
  }

  /**
   * Register prefix with the connected NDN hub and call onInterest when a
   * matching interest is received. To register a prefix with NFD, you must
   * first call setCommandSigningInfo.
   * Use default ForwardingFlags.
   * @param prefix A Name for the prefix to register. This copies the Name.
   * @param onInterest If not null, this creates an interest filter from prefix
   * so that when an Interest is received which matches the filter, this calls
   * onInterest.onInterest(prefix, interest, face, interestFilterId, filter).
   * The onInterest callback should supply the Data with face.putData().
   * NOTE: You must not change the prefix or filter objects - if you need to
   * change them then make a copy.
   * If onInterest is null, it is ignored and you must call setInterestFilter.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onRegisterFailed If register prefix fails for any reason, this
   * calls onRegisterFailed.onRegisterFailed(prefix).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param wireFormat A WireFormat object used to encode the message.
   * @return The registered prefix ID which can be used with
   * removeRegisteredPrefix.
   * @throws IOException For I/O error in sending the registration request.
   * @throws SecurityException If signing a command interest for NFD and cannot
   * find the private key for the certificateName.
   */
  public long
  registerPrefix
    (Name prefix, OnInterestCallback onInterest, OnRegisterFailed onRegisterFailed,
     WireFormat wireFormat) throws IOException, SecurityException
  {
    return registerPrefix
      (prefix, onInterest, onRegisterFailed, null, new ForwardingFlags(),
       wireFormat);
  }

  /**
   * Register prefix with the connected NDN hub and call onInterest when a
   * matching interest is received. To register a prefix with NFD, you must
   * first call setCommandSigningInfo.
   * This uses the default WireFormat.getDefaultWireFormat().
   * Use default ForwardingFlags.
   * @param prefix A Name for the prefix to register. This copies the Name.
   * @param onInterest If not null, this creates an interest filter from prefix
   * so that when an Interest is received which matches the filter, this calls
   * onInterest.onInterest(prefix, interest, face, interestFilterId, filter).
   * The onInterest callback should supply the Data with face.putData().
   * NOTE: You must not change the prefix or filter objects - if you need to
   * change them then make a copy.
   * If onInterest is null, it is ignored and you must call setInterestFilter.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onRegisterFailed If register prefix fails for any reason, this
   * calls onRegisterFailed.onRegisterFailed(prefix).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @return The registered prefix ID which can be used with
   * removeRegisteredPrefix.
   * @throws IOException For I/O error in sending the registration request.
   * @throws SecurityException If signing a command interest for NFD and cannot
   * find the private key for the certificateName.
   */
  public long
  registerPrefix
    (Name prefix, OnInterestCallback onInterest,
     OnRegisterFailed onRegisterFailed) throws IOException, SecurityException
  {
    return registerPrefix
      (prefix, onInterest, onRegisterFailed, null, new ForwardingFlags(),
       WireFormat.getDefaultWireFormat());
  }

  /**
   * Remove the registered prefix entry with the registeredPrefixId from the
   * registered prefix table. This does not affect another registered prefix with
   * a different registeredPrefixId, even if it has the same prefix name. If an
   * interest filter was automatically created by registerPrefix, also remove it.
   * If there is no entry with the registeredPrefixId, do nothing.
   * @param registeredPrefixId The ID returned from registerPrefix.
   */
  public void
  removeRegisteredPrefix(long registeredPrefixId)
  {
    node_.removeRegisteredPrefix(registeredPrefixId);
  }

  /**
   * Add an entry to the local interest filter table to call the onInterest
   * callback for a matching incoming Interest. This method only modifies the
   * library's local callback table and does not register the prefix with the
   * forwarder. It will always succeed. To register a prefix with the forwarder,
   * use registerPrefix.
   * @param filter The InterestFilter with a prefix and optional regex filter
   * used to match the name of an incoming Interest. This makes a copy of filter.
   * @param onInterest When an Interest is received which matches the filter,
   * this calls
   * onInterest.onInterest(prefix, interest, face, interestFilterId, filter).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @return The interest filter ID which can be used with unsetInterestFilter.
   */
  public long
  setInterestFilter(InterestFilter filter, OnInterestCallback onInterest)
  {
    long interestFilterId = node_.getNextEntryId();

    node_.setInterestFilter(interestFilterId, filter, onInterest, this);

    return interestFilterId;
  }

  /**
   * Add an entry to the local interest filter table to call the onInterest
   * callback for a matching incoming Interest. This method only modifies the
   * library's local callback table and does not register the prefix with the
   * forwarder. It will always succeed. To register a prefix with the forwarder,
   * use registerPrefix.
   * @param prefix The Name prefix used to match the name of an incoming
   * Interest.
   * @param onInterest This creates an interest filter from prefix so that when
   * an Interest is received which matches the filter, this calls
   * onInterest.onInterest(prefix, interest, face, interestFilterId, filter).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @return The interest filter ID which can be used with unsetInterestFilter.
   */
  public long
  setInterestFilter(Name prefix, OnInterestCallback onInterest)
  {
    return setInterestFilter(new InterestFilter(prefix), onInterest);
  }

  /**
   * Remove the interest filter entry which has the interestFilterId from the
   * interest filter table. This does not affect another interest filter with
   * a different interestFilterId, even if it has the same prefix name.
   * If there is no entry with the interestFilterId, do nothing.
   * @param interestFilterId The ID returned from setInterestFilter.
   */
  public void
  unsetInterestFilter(long interestFilterId)
  {
    node_.unsetInterestFilter(interestFilterId);
  }

  /**
   * The OnInterestCallback calls this to put a Data packet which satisfies an
   * Interest.
   * @param data The Data packet which satisfies the interest.
   * @param wireFormat A WireFormat object used to encode the Data packet.
   * @throws Error If the encoded Data packet size exceeds getMaxNdnPacketSize().
   */
  public void
  putData(Data data, WireFormat wireFormat) throws IOException
  {
    node_.putData(data, wireFormat);
  }

  /**
   * The OnInterestCallback calls this to put a Data packet which satisfies an
   * Interest.
   * This uses the default WireFormat.getDefaultWireFormat() to encode data.
   * @param data The Data packet which satisfies the interest.
   * @throws Error If the encoded Data packet size exceeds getMaxNdnPacketSize().
   */
  public void
  putData(Data data) throws IOException
  {
    putData(data, WireFormat.getDefaultWireFormat());
  }

  /**
   * Send the encoded packet out through the face.
   * @param encoding The blob with the the encoded packet to send.
   * @throws Error If the encoded packet size exceeds getMaxNdnPacketSize().
   */
  public void
  send(Blob encoding) throws IOException
  {
    send(encoding.buf());
  }

  /**
   * Send the encoded packet out through the face.
   * @param encoding The array of bytes for the encoded packet to send.  This
   * reads from position() to limit(), but does not change the position.
   * @throws Error If the encoded packet size exceeds getMaxNdnPacketSize().
   */
  public void
  send(ByteBuffer encoding) throws IOException
  {
    node_.send(encoding);
  }

  /**
   * Process any packets to receive and call callbacks such as onData,
   * onInterest or onTimeout. This returns immediately if there is no data to
   * receive. This blocks while calling the callbacks. You should repeatedly
   * call this from an event loop, with calls to sleep as needed so that the
   * loop doesn’t use 100% of the CPU. Since processEvents modifies the pending
   * interest table, your application should make sure that it calls
   * processEvents in the same thread as expressInterest (which also modifies
   * the pending interest table).
   * This may throw an exception for reading data or in the callback for
   * processing the data. If you call this from an main event loop, you may want
   * to catch and log/disregard all exceptions.
   */
  public void
  processEvents() throws IOException, EncodingException
  {
    // Just call Node's processEvents.
    node_.processEvents();
  }

  /**
   * Check if the face is local based on the current connection through the
   * Transport; some Transport may cause network IO (e.g. an IP host name lookup).
   * @return True if the face is local, false if not.
   * @throws IOException
   * @note This is an experimental feature. This API may change in the future.
   */
  public boolean
  isLocal() throws IOException
  {
    return node_.isLocal();
  }

  /**
   * Shut down and disconnect this Face.
   */
  public void
  shutdown()
  {
    node_.shutdown();
  }

  /**
   * Get the practical limit of the size of a network-layer packet. If a packet
   * is larger than this, the library or application MAY drop it.
   * @return The maximum NDN packet size.
   */
  public static int
  getMaxNdnPacketSize() { return Common.MAX_NDN_PACKET_SIZE; }

  /**
   * Call callback.run() after the given delay. Even though this is public,
   * it is not part of the public API of Face. This default implementation just
   * calls Node.callLater, but a subclass can override.
   * @param delayMilliseconds The delay in milliseconds.
   * @param callback This calls callback.run() after the delay.
   */
  public void
  callLater(double delayMilliseconds, Runnable callback)
  {
    node_.callLater(delayMilliseconds, callback);
  }

  /**
   * Do the work of expressInterest to make an Interest based on name and
   * interestTemplate.
   * @param name A Name for the interest.  This copies the Name.
   * @param interestTemplate if not null, copy interest selectors from the
   * template. This does not keep a pointer to the Interest object.
   * @return The Interest, suitable for Node.expressInterest.
   */
  static protected Interest
  getInterestCopy(Name name, Interest interestTemplate)
  {
    if (interestTemplate != null) {
      // Copy the interestTemplate.
      Interest interestCopy = new Interest(interestTemplate);
      interestCopy.setName(name);
      return interestCopy;
    }
    else {
      Interest interestCopy = new Interest(name);
      interestCopy.setInterestLifetimeMilliseconds(4000.0);
      return interestCopy;
    }
  }

  protected final Node node_;
  protected KeyChain commandKeyChain_ = null;
  protected Name commandCertificateName_ = new Name();
}
