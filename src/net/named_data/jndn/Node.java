/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import net.named_data.jndn.encoding.BinaryXml;
import net.named_data.jndn.encoding.BinaryXmlDecoder;
import net.named_data.jndn.encoding.BinaryXmlWireFormat;
import net.named_data.jndn.encoding.ElementListener;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.TlvWireFormat;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.encoding.tlv.Tlv;
import net.named_data.jndn.encoding.tlv.TlvDecoder;
import net.named_data.jndn.transport.Transport;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

/**
 * The Node class implements internal functionality for the Face class.
 */
public class Node implements ElementListener {
  /**
   * Create a new Node for communication with an NDN hub with the given 
   * Transport object and connectionInfo.
   * @param transport A Transport object used for communication.
   * @param connectionInfo A Transport.ConnectionInfo to be used to connect to 
   * the transport.
   */
  public Node(Transport transport, Transport.ConnectionInfo connectionInfo)
  {
    transport_ = transport;
    connectionInfo_ = connectionInfo;
    ndndIdFetcherInterest_ = new Interest
      (new Name("/%C1.M.S.localhost/%C1.M.SRV/ndnd/KEY"), 4000.0);
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
    // TODO: Properly check if we are already connected to the expected host.
    if (!transport_.getIsConnected())
      transport_.connect(connectionInfo_, this);

    long pendingInterestId = PendingInterest.getNextPendingInterestId();
    pendingInterestTable_.add(new PendingInterest
      (pendingInterestId, new Interest(interest), onData, onTimeout));

    Blob encoding = interest.wireEncode(wireFormat);  
    transport_.send(encoding.buf());

    return pendingInterestId;
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
    // Go backwards through the list so we can remove entries.
    // Remove all entries even though pendingInterestId should be unique.
    for (int i = pendingInterestTable_.size() - 1; i >= 0; --i) {
      if (((PendingInterest)pendingInterestTable_.get(i)).getPendingInterestId
           () == pendingInterestId)
        pendingInterestTable_.remove(i);
    }
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
    // Go backwards through the list so we can remove entries.
    // Remove all entries even though pendingInterestId should be unique.
    for (int i = (int)registeredPrefixTable_.size() - 1; i >= 0; --i) {
      if (((RegisteredPrefix)registeredPrefixTable_.get(i)).getRegisteredPrefixId
            () == registeredPrefixId)
        registeredPrefixTable_.remove(i);
    }
  }

  /**
   * Process any data to receive.  For each element received, call 
   * onReceivedElement. This is non-blocking and will return immediately if 
   * there is no data to receive. You should repeatedly call this from an event 
   * loop, with calls to sleep as needed so that the loop doesn't use 100% of 
   * the CPU. This may throw an exception for reading data or in the callback for 
   * processing the data. If you call this from an main event loop, you may want 
   * to catch and log/disregard all exceptions.
   */
  public void 
  processEvents() throws IOException, EncodingException
  {
    transport_.processEvents();

    // Check for PIT entry timeouts. Go backwards through the list so we can 
    //   remove entries.
    double nowMilliseconds = Common.getNowMilliseconds();
    for (int i = pendingInterestTable_.size() - 1; i >= 0; --i) {
      if (((PendingInterest)pendingInterestTable_.get(i)).isTimedOut
            (nowMilliseconds)) {
        // Save the PendingInterest and remove it from the PIT.  Then call the callback.
        PendingInterest pendingInterest = 
          (PendingInterest)pendingInterestTable_.get(i);
        pendingInterestTable_.remove(i);
        pendingInterest.callTimeout();

        // Refresh now since the timeout callback might have delayed.
        nowMilliseconds = Common.getNowMilliseconds();
      }
    }
  }
  
  public Transport
  getTransport() { return transport_; }
  
  public Transport.ConnectionInfo
  getConnectionInfo() { return connectionInfo_; }
  
  public void onReceivedElement(ByteBuffer element) throws EncodingException
  {
    // First, decode as Interest or Data.
    Interest interest = null;
    Data data = null;
    // The type codes for TLV Interest and Data packets are chosen to not
    //   conflict with the first byte of a binary XML packet, so we can
    //   just look at the first byte.
    if (element.get(0) == Tlv.Interest || element.get(0) == Tlv.Data) {
      TlvDecoder decoder = new TlvDecoder(element);  
      if (decoder.peekType(Tlv.Interest, element.remaining())) {
        interest = new Interest();
        interest.wireDecode(element, TlvWireFormat.get());
      }
      else if (decoder.peekType(Tlv.Data, element.remaining())) {
        data = new Data();
        data.wireDecode(element, TlvWireFormat.get());
      }
    }
    else {
      // Binary XML.
      BinaryXmlDecoder decoder = new BinaryXmlDecoder(element);
      if (decoder.peekDTag(BinaryXml.DTag_Interest)) {
        interest = new Interest();
        interest.wireDecode(element, BinaryXmlWireFormat.get());
      }
      else if (decoder.peekDTag(BinaryXml.DTag_ContentObject)) {
        data = new Data();
        data.wireDecode(element, BinaryXmlWireFormat.get());
      }
    }

    // Now process as Interest or Data.
    if (interest != null) {
      RegisteredPrefix entry = getEntryForRegisteredPrefix(interest.getName());
      if (entry != null)
        entry.getOnInterest().onInterest
          (entry.getPrefix(), interest, transport_, entry.getRegisteredPrefixId());
    }
    else if (data != null) {
      ArrayList pitEntries = new ArrayList();
      extractEntriesForExpressedInterest(data.getName(), pitEntries);
      for (int i = 0; i < pitEntries.size(); ++i) {
        PendingInterest pendingInterest = (PendingInterest)pitEntries.get(i);
        pendingInterest.getOnData().onData(pendingInterest.getInterest(), data);
      }
    }
  }
  
  public void 
  shutdown()
  {
    try {
      transport_.close();
    }
    catch (IOException e) {}
  }
  
  private static class PendingInterest {
    public PendingInterest
      (long pendingInterestId, Interest interest, OnData onData, 
       OnTimeout onTimeout) 
    {
      pendingInterestId_ = pendingInterestId;
      interest_ = interest;
      onData_ = onData;
      onTimeout_ = onTimeout;
      
      // Set up timeoutTime_.
      if (interest_.getInterestLifetimeMilliseconds() >= 0.0)
        timeoutTimeMilliseconds_ = Common.getNowMilliseconds() + 
          interest_.getInterestLifetimeMilliseconds();
      else
        // No timeout.
        timeoutTimeMilliseconds_ = -1.0;      
    }

    /**
     * Get the next unique pending interest ID.
     * @return The next ID.
     */
    public static long 
    getNextPendingInterestId() { return ++lastPendingInterestId_; }  
      
    /**
     * Get the pendingInterestId given to the constructor.
     * @return The pendingInterestId.
     */
    public long
    getPendingInterestId() { return pendingInterestId_; }
    
    public Interest
    getInterest() { return interest_; }
    
    public OnData
    getOnData() { return onData_; }
    
    /**
     * Check if this interest is timed out.
     * @param nowMilliseconds The current time in milliseconds from 
     * Common.getNowMilliseconds.
     * @return True if this interest timed out, otherwise false.
     */
    public boolean 
    isTimedOut(double nowMilliseconds)
    {
      return timeoutTimeMilliseconds_ >= 0.0 && 
             nowMilliseconds >= timeoutTimeMilliseconds_;
    }
    
    /**
     * Call onTimeout_ (if defined). This ignores exceptions from the 
     * onTimeout_.
     */
    public void 
    callTimeout()
    {
      if (onTimeout_ != null) {
        // Ignore all exceptions.
        try {
          onTimeout_.onTimeout(interest_);
        }
        catch (Throwable e) { }
      }
    }
        
    private Interest interest_;  
    private static long lastPendingInterestId_; /**< A class variable used to get the next unique ID. */
    private long pendingInterestId_; /**< A unique identifier for this entry so it can be deleted */
    private OnData onData_;
    private OnTimeout onTimeout_;
    private double timeoutTimeMilliseconds_; /**< The time when the interest 
     * times out in milliseconds according to Common.getNowMilliseconds, or -1 
     * for no timeout. */
  }

  private static class RegisteredPrefix {
    public RegisteredPrefix
      (long registeredPrefixId, Name prefix, OnInterest onInterest)
    {
      registeredPrefixId_ = registeredPrefixId;
      prefix_ = prefix;
      onInterest_ = onInterest;
    }

    /**
     * Get the next unique entry ID.
     * @return The next ID.
     */
    public static long 
    getNextRegisteredPrefixId() { return ++lastRegisteredPrefixId_; }
    
    /**
     * Get the registeredPrefixId given to the constructor.
     * @return The registeredPrefixId.
     */
    public long 
    getRegisteredPrefixId() { return registeredPrefixId_; }
    
    public Name
    getPrefix() { return prefix_; }
    
    public OnInterest
    getOnInterest() { return onInterest_; }

    private static long lastRegisteredPrefixId_; /**< A class variable used to get the next unique ID. */
    private long registeredPrefixId_; /**< A unique identifier for this entry so it can be deleted */
    private Name prefix_;
    private OnInterest onInterest_;
  }
  
  // TODO: private static class NdndIdFetcher
  
  // TODO: private static class RegisterResponse
  
  /**
   * Find all entries from pendingInterestTable_ where the name conforms to the 
   * entry's interest selectors, remove the entries from the table and add to
   * the entries list.
   * @param name The name to find the interest for (from the incoming data 
   * packet).
   * @param entries Add matching entries from pendingInterestTable_.  The caller
   * should pass in an empty ArrayList.
   */
  private void 
  extractEntriesForExpressedInterest(Name name, ArrayList entries)
  {
    // Go backwards through the list so we can remove entries.
    for (int i = pendingInterestTable_.size() - 1; i >= 0; --i) {
      if (((PendingInterest)pendingInterestTable_.get(i)).getInterest
          ().matchesName(name)) {
        entries.add(pendingInterestTable_.get(i));
        pendingInterestTable_.remove(i);
      }
    }
  }
  
  /**
   * Find the first entry from the registeredPrefixTable_ where the entry prefix 
   * is the longest that matches name.
   * @param name The name to find the RegisteredPrefix for (from the incoming 
   * interest packet).
   * @return The entry, or null if not found.
   */
  private RegisteredPrefix
  getEntryForRegisteredPrefix(Name name)
  {
    int iResult = -1;

    for (int i = 0; i < registeredPrefixTable_.size(); ++i) {
      RegisteredPrefix registeredPrefix = 
        (RegisteredPrefix)registeredPrefixTable_.get(i);
      if (registeredPrefix.getPrefix().match(name)) {
        if (iResult < 0 || 
            registeredPrefix.getPrefix().size() > 
            ((RegisteredPrefix)registeredPrefixTable_.get(iResult)).getPrefix().size())
          // Update to the longer match.
          iResult = i;
      }
    }

    if (iResult >= 0)
      return (RegisteredPrefix)registeredPrefixTable_.get(iResult);
    else
      return null;
  }
  
  // TODO: registerPrefixHelper
  
  private Transport transport_;
  private Transport.ConnectionInfo connectionInfo_;
  private ArrayList pendingInterestTable_ = new ArrayList();  // PendingInterest
  private ArrayList registeredPrefixTable_ = new ArrayList(); // RegisteredPrefix
  private Interest ndndIdFetcherInterest_;
  private Blob ndndId_ = new Blob();
}
