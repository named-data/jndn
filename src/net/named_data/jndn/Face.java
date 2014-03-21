/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn;

import java.io.IOException;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.transport.TcpTransport;
import net.named_data.jndn.transport.Transport;

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
    node_ =new Node(transport, connectionInfo);
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
   * Send the Interest through the transport, read the entire response and call 
   * onData(interest, data).
   * @param interest The Interest to send.  This copies the Interest.
   * @param onData  This calls onData.onData when a matching data packet is 
   * received.
   * @param onTimeout This calls onTimeout.onTimeout if the interest times out.  
   * If onTimeout is null, this does not use it.
   * @param wireFormat A WireFormat object used to encode the message.
   * @return The pending interest ID which can be used with 
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
   */
  public long 
  expressInterest
    (Interest interest, OnData onData, OnTimeout onTimeout,
     WireFormat wireFormat) throws IOException
  {
    return node_.expressInterest(interest, onData, onTimeout, wireFormat);
  }
  
  /**
   * Send the Interest through the transport, read the entire response and call 
   * onData(interest, data).
   * This uses the default WireFormat.getDefaultWireFormat().
   * @param interest The Interest to send.  This copies the Interest.
   * @param onData  This calls onData.onData when a matching data packet is 
   * received.
   * @param onTimeout This calls onTimeout.onTimeout if the interest times out.  
   * If onTimeout is null, this does not use it.
   * @return The pending interest ID which can be used with 
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
   */
  public long 
  expressInterest
    (Interest interest, OnData onData, OnTimeout onTimeout) throws IOException
  {
    return node_.expressInterest
      (interest, onData, onTimeout, WireFormat.getDefaultWireFormat());
  }
  
  /**
   * Send the Interest through the transport, read the entire response and call 
   * onData(interest, data).  Ignore if the interest times out.
   * @param interest The Interest to send.  This copies the Interest.
   * @param onData  This calls onData.onData when a matching data packet is 
   * received.
   * @param wireFormat A WireFormat object used to encode the message.
   * @return The pending interest ID which can be used with 
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
   */
  public long 
  expressInterest
    (Interest interest, OnData onData, WireFormat wireFormat) throws IOException
  {
    return node_.expressInterest(interest, onData, null, wireFormat);
  }
  
  /**
   * Send the Interest through the transport, read the entire response and call 
   * onData(interest, data).  Ignore if the interest times out.
   * This uses the default WireFormat.getDefaultWireFormat().
   * @param interest The Interest to send.  This copies the Interest.
   * @param onData  This calls onData.onData when a matching data packet is 
   * received.
   * @return The pending interest ID which can be used with 
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
   */
  public long 
  expressInterest(Interest interest, OnData onData) throws IOException
  {
    return node_.expressInterest
      (interest, onData, null, WireFormat.getDefaultWireFormat());
  }
  
  /**
   * Encode name as an Interest. If interestTemplate is not null, use its 
   * interest selectors. Send the interest through the transport, read the 
   * entire response and call onData(interest, data).
   * @param name A Name for the interest. This copies the Name.
   * @param interestTemplate If not null, copy interest selectors from the 
   * template. This does not keep a pointer to the Interest object.
   * @param onData  This calls onData.onData when a matching data packet is 
   * received.
   * @param onTimeout This calls onTimeout.onTimeout if the interest times out.  
   * If onTimeout is null, this does not use it.
   * @param wireFormat A WireFormat object used to encode the message.
   * @return The pending interest ID which can be used with 
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
   */
  public long
  expressInterest
    (Name name, Interest interestTemplate, OnData onData, OnTimeout onTimeout,
     WireFormat wireFormat) throws IOException
  {
    Interest interest = new Interest(name);
    if (interestTemplate != null) {
      interest.setMinSuffixComponents(interestTemplate.getMinSuffixComponents());
      interest.setMaxSuffixComponents(interestTemplate.getMaxSuffixComponents());
      interest.setKeyLocator(interestTemplate.getKeyLocator());
      interest.setExclude(interestTemplate.getExclude());
      interest.setChildSelector(interestTemplate.getChildSelector());
      interest.setMustBeFresh(interestTemplate.getMustBeFresh());
      interest.setScope(interestTemplate.getScope());
      interest.setInterestLifetimeMilliseconds(
        interestTemplate.getInterestLifetimeMilliseconds());
      // Don't copy the nonce.
    }
    else
      interest.setInterestLifetimeMilliseconds(4000.0);
    
    return node_.expressInterest(interest, onData, onTimeout, wireFormat);
  }
  
  /**
   * Encode name as an Interest. If interestTemplate is not null, use its 
   * interest selectors. Send the interest through the transport, read the 
   * entire response and call onData(interest, data).
   * Use a default interest lifetime.
   * @param name A Name for the interest. This copies the Name.
   * @param onData  This calls onData.onData when a matching data packet is 
   * received.
   * @param onTimeout This calls onTimeout.onTimeout if the interest times out.  
   * If onTimeout is null, this does not use it.
   * @param wireFormat A WireFormat object used to encode the message.
   * @return The pending interest ID which can be used with 
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
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
   * interest selectors. Send the interest through the transport, read the 
   * entire response and call onData(interest, data).
   * Ignore if the interest times out.
   * @param name A Name for the interest. This copies the Name.
   * @param interestTemplate If not null, copy interest selectors from the 
   * template. This does not keep a pointer to the Interest object.
   * @param onData  This calls onData.onData when a matching data packet is 
   * received.
   * @param wireFormat A WireFormat object used to encode the message.
   * @return The pending interest ID which can be used with 
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
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
   * interest selectors. Send the interest through the transport, read the 
   * entire response and call onData(interest, data).
   * This uses the default WireFormat.getDefaultWireFormat().
   * @param name A Name for the interest. This copies the Name.
   * @param interestTemplate If not null, copy interest selectors from the 
   * template. This does not keep a pointer to the Interest object.
   * @param onData  This calls onData.onData when a matching data packet is 
   * received.
   * @param onTimeout This calls onTimeout.onTimeout if the interest times out.  
   * If onTimeout is null, this does not use it.
   * @return The pending interest ID which can be used with 
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
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
   * interest selectors. Send the interest through the transport, read the 
   * entire response and call onData(interest, data).
   * Ignore if the interest times out.
   * This uses the default WireFormat.getDefaultWireFormat().
   * @param name A Name for the interest. This copies the Name.
   * @param interestTemplate If not null, copy interest selectors from the 
   * template. This does not keep a pointer to the Interest object.
   * @param onData  This calls onData.onData when a matching data packet is 
   * received.
   * @return The pending interest ID which can be used with 
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
   */
  public long
  expressInterest
    (Name name, Interest interestTemplate, OnData onData) throws IOException
  {
    return expressInterest
      (name, interestTemplate, onData, null, WireFormat.getDefaultWireFormat());
  }
  
  /**
   * Encode name as an Interest. If interestTemplate is not null, use its 
   * interest selectors. Send the interest through the transport, read the 
   * entire response and call onData(interest, data).
   * Use a default interest lifetime.
   * This uses the default WireFormat.getDefaultWireFormat().
   * @param name A Name for the interest. This copies the Name.
   * @param onData  This calls onData.onData when a matching data packet is 
   * received.
   * @param onTimeout This calls onTimeout.onTimeout if the interest times out.  
   * If onTimeout is null, this does not use it.
   * @return The pending interest ID which can be used with 
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
   */
  public long
  expressInterest
    (Name name, OnData onData, OnTimeout onTimeout) throws IOException
  {
    return expressInterest
      (name, null, onData, onTimeout, WireFormat.getDefaultWireFormat());
  }
    
  /**
   * Encode name as an Interest. If interestTemplate is not null, use its 
   * interest selectors. Send the interest through the transport, read the 
   * entire response and call onData(interest, data).
   * Use a default interest lifetime.
   * Ignore if the interest times out.
   * @param name A Name for the interest. This copies the Name.
   * @param onData  This calls onData.onData when a matching data packet is 
   * received.
   * @param wireFormat A WireFormat object used to encode the message.
   * @return The pending interest ID which can be used with 
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
   */
  public long
  expressInterest
    (Name name, OnData onData, WireFormat wireFormat) throws IOException
  {
    return expressInterest(name, null, onData, null, wireFormat);
  }
    
  /**
   * Encode name as an Interest. If interestTemplate is not null, use its 
   * interest selectors. Send the interest through the transport, read the 
   * entire response and call onData(interest, data).
   * Use a default interest lifetime.
   * Ignore if the interest times out.
   * This uses the default WireFormat.getDefaultWireFormat().
   * @param name A Name for the interest. This copies the Name.
   * @param onData  This calls onData.onData when a matching data packet is 
   * received.
   * @return The pending interest ID which can be used with 
   * removePendingInterest.
   * @throws IOException For I/O error in sending the interest.
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
   * a different pendingInterestId, even it if has the same interest name.
   * If there is no entry with the pendingInterestId, do nothing.
   * @param pendingInterestId The ID returned from expressInterest.
   */
  public void
  removePendingInterest(long pendingInterestId)
  {
    node_.removePendingInterest(pendingInterestId);
  }
  
  // TODO: registerPrefix
  
  /**
   * Remove the registered prefix entry with the registeredPrefixId from the 
   * pending interest table. This does not affect another registered prefix with 
   * a different registeredPrefixId, even it if has the same prefix name.
   * If there is no entry with the registeredPrefixId, do nothing.
   * @param registeredPrefixId The ID returned from registerPrefix.
   */
  public void
  removeRegisteredPrefix(long registeredPrefixId)
  {
    node_.removeRegisteredPrefix(registeredPrefixId);
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
   * Shut down and disconnect this Face.
   */
  public void 
  shutdown()
  {
    node_.shutdown();
  }
  
  private Node node_;
}
