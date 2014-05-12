/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
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
import net.named_data.jndn.util.SignedBlob;

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
  public final long
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
   * a different pendingInterestId, even if it has the same interest name.
   * If there is no entry with the pendingInterestId, do nothing.
   * @param pendingInterestId The ID returned from expressInterest.
   */
  public final void
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
  
  /**
   * Register prefix with the connected NDN hub and call onInterest when a 
   * matching interest is received.
   * @param prefix A Name for the prefix to register. This copies the Name.
   * @param onInterest This calls onInterest.onInterest(prefix, interest) when 
   * a matching interest is received.
   * @param onRegisterFailed This calls onRegisterFailed.onRegisterFailed(prefix) 
   * if failed to retrieve the connected hub’s ID or failed to register the 
   * prefix.
   * @param flags The flags for finer control of which interests are forwarded 
   * to the application.
   * @param wireFormat A WireFormat object used to encode the message.
   * @return The registered prefix ID which can be used with 
   * removeRegisteredPrefix.
   * @throws IOException For I/O error in sending the registration request.
   */
  public final long 
  registerPrefix
    (Name prefix, OnInterest onInterest, OnRegisterFailed onRegisterFailed, 
     ForwardingFlags flags, WireFormat wireFormat) throws IOException
  {
    // Get the registeredPrefixId now so we can return it to the caller.
    long registeredPrefixId = RegisteredPrefix.getNextRegisteredPrefixId();

    if (ndndId_.size() == 0) {
      // First fetch the ndndId of the connected hub.
      NdndIdFetcher fetcher = new NdndIdFetcher
        (new NdndIdFetcher.Info
          (this, registeredPrefixId, prefix, onInterest, onRegisterFailed, 
           flags, wireFormat));
      // We send the interest using the given wire format so that the hub 
      //   receives (and sends) in the application's desired wire format.
      expressInterest(ndndIdFetcherInterest_, fetcher, fetcher, wireFormat);
    }
    else
      registerPrefixHelper
        (registeredPrefixId, new Name(prefix), onInterest, onRegisterFailed, 
         flags, wireFormat);

    return registeredPrefixId;
  }
  
  /**
   * Remove the registered prefix entry with the registeredPrefixId from the 
   * registered prefix table. This does not affect another registered prefix with 
   * a different registeredPrefixId, even if it has the same prefix name.
   * If there is no entry with the registeredPrefixId, do nothing.
   * @param registeredPrefixId The ID returned from registerPrefix.
   */
  public final void
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
  public final void 
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
  
  public final Transport
  getTransport() { return transport_; }
  
  public final Transport.ConnectionInfo
  getConnectionInfo() { return connectionInfo_; }
  
  public final void onReceivedElement(ByteBuffer element) throws EncodingException
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
  
  public final void 
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
  
  private static class NdndIdFetcher implements OnData, OnTimeout
  {
    public NdndIdFetcher(Info info)
    {
      info_ = info;  
    }

    /**
     * We received the ndnd ID.
     * @param interest
     * @param ndndIdData 
     */
    public void 
    onData(Interest interest, Data ndndIdData) 
    {
      // Assume that the content is a DER encoded public key of the ndnd.  
      // Do a quick check that the first byte is for DER encoding.
      if (ndndIdData.getContent().size() < 1 || 
          ndndIdData.getContent().buf().get(0) != 0x30) {
        info_.onRegisterFailed_.onRegisterFailed(info_.prefix_);
        return;
      }

      // Get the digest of the public key.
      byte[] digest = Common.digestSha256(ndndIdData.getContent().buf());

      // Set the ndndId_ and continue.
      // TODO: If there are multiple connected hubs, the NDN ID is really stored 
      //   per connected hub.
      info_.node_.ndndId_ = new Blob(digest);
      info_.node_.registerPrefixHelper
        (info_.registeredPrefixId_, info_.prefix_, info_.onInterest_, 
         info_.onRegisterFailed_, info_.flags_, info_.wireFormat_);
    }    

    /**
     * We timed out fetching the ndnd ID.
     * @param timedOutInterest 
     */
    public void 
    onTimeout(Interest timedOutInterest) 
    {
      info_.onRegisterFailed_.onRegisterFailed(info_.prefix_);
    }

    public static class Info {
      /**
       * Create a new NdndIdFetcher.Info.
       * 
       * @param node
       * @param registeredPrefixId The 
       * RegisteredPrefix.getNextRegisteredPrefixId() which registerPrefix got 
       * so it could return it to the caller.
       * @param prefix This copies the Name.
       * @param onInterest
       * @param onRegisterFailed
       * @param flags
       * @param wireFormat
       */
      public Info
        (Node node, long registeredPrefixId, Name prefix, OnInterest onInterest, 
         OnRegisterFailed onRegisterFailed, ForwardingFlags flags, 
         WireFormat wireFormat)
      {
        node_ = node;
        registeredPrefixId_ = registeredPrefixId;
        prefix_ = new Name(prefix);
        onInterest_ = onInterest;
        onRegisterFailed_ = onRegisterFailed;
        flags_ = flags;
        wireFormat_ = wireFormat;
      }
      
      public Node node_;
      public long registeredPrefixId_;
      public Name prefix_;
      public OnInterest onInterest_;
      public OnRegisterFailed onRegisterFailed_;
      public ForwardingFlags flags_;
      public WireFormat wireFormat_;
    };
    
    private Info info_;
  }
  
  private static class RegisterResponse implements OnData, OnTimeout {
    public RegisterResponse(Info info)
    {
      info_ = info;
    }

    /**
     * We received the response.
     * @param interest
     * @param responseData 
     */
    public void 
    onData(Interest interest, Data responseData) 
    {
      Name expectedName = new Name("/ndnx/.../selfreg");
      // Got a response. Do a quick check of expected name components.
      if (responseData.getName().size() < 4 ||
          !responseData.getName().get(0).equals(expectedName.get(0)) ||
          !responseData.getName().get(2).equals(expectedName.get(2))) {
        info_.onRegisterFailed_.onRegisterFailed(info_.prefix_);
        return;
      }

      // Otherwise, silently succeed.
    }

    /**
     * We timed out waiting for the response.
     * @param timedOutInterest 
     */
    public void 
    onTimeout(Interest timedOutInterest) 
    {
      info_.onRegisterFailed_.onRegisterFailed(info_.prefix_);
    }
    
    public static class Info {
      public Info(Name prefix, OnRegisterFailed onRegisterFailed)
      {      
        prefix_ = prefix;
        onRegisterFailed_ = onRegisterFailed;
      }
      
      public final Name prefix_;
      public final OnRegisterFailed onRegisterFailed_;
    }
    
    private final Info info_;
  }

  // Convert the int array to a ByteBuffer.
  private static ByteBuffer 
  toBuffer(int[] array) 
  {
    ByteBuffer result = ByteBuffer.allocate(array.length);
    for (int i = 0; i < array.length; ++i)
      result.put((byte)(array[i] & 0xff));
    
    result.flip();
    return result;
  }

  private static final ByteBuffer SELFREG_PUBLIC_KEY_DER = toBuffer(new int[] {  
    0x30, 0x81, 0x9F, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81,
    0x8D, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xE1, 0x7D, 0x30, 0xA7, 0xD8, 0x28, 0xAB, 0x1B, 0x84, 0x0B, 0x17,
    0x54, 0x2D, 0xCA, 0xF6, 0x20, 0x7A, 0xFD, 0x22, 0x1E, 0x08, 0x6B, 0x2A, 0x60, 0xD1, 0x6C, 0xB7, 0xF5, 0x44, 0x48, 0xBA,
    0x9F, 0x3F, 0x08, 0xBC, 0xD0, 0x99, 0xDB, 0x21, 0xDD, 0x16, 0x2A, 0x77, 0x9E, 0x61, 0xAA, 0x89, 0xEE, 0xE5, 0x54, 0xD3,
    0xA4, 0x7D, 0xE2, 0x30, 0xBC, 0x7A, 0xC5, 0x90, 0xD5, 0x24, 0x06, 0x7C, 0x38, 0x98, 0xBB, 0xA6, 0xF5, 0xDC, 0x43, 0x60,
    0xB8, 0x45, 0xED, 0xA4, 0x8C, 0xBD, 0x9C, 0xF1, 0x26, 0xA7, 0x23, 0x44, 0x5F, 0x0E, 0x19, 0x52, 0xD7, 0x32, 0x5A, 0x75,
    0xFA, 0xF5, 0x56, 0x14, 0x4F, 0x9A, 0x98, 0xAF, 0x71, 0x86, 0xB0, 0x27, 0x86, 0x85, 0xB8, 0xE2, 0xC0, 0x8B, 0xEA, 0x87,
    0x17, 0x1B, 0x4D, 0xEE, 0x58, 0x5C, 0x18, 0x28, 0x29, 0x5B, 0x53, 0x95, 0xEB, 0x4A, 0x17, 0x77, 0x9F, 0x02, 0x03, 0x01,
    0x00, 0x01  
  });

  private static final ByteBuffer SELFREG_PRIVATE_KEY_DER = toBuffer(new int[] {  
    0x30, 0x82, 0x02, 0x77, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    0x05, 0x00, 0x04, 0x82, 0x02, 0x61, 0x30, 0x82, 0x02, 0x5d, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0xe1, 0x7d, 0x30,
    0xa7, 0xd8, 0x28, 0xab, 0x1b, 0x84, 0x0b, 0x17, 0x54, 0x2d, 0xca, 0xf6, 0x20, 0x7a, 0xfd, 0x22, 0x1e, 0x08, 0x6b, 0x2a,
    0x60, 0xd1, 0x6c, 0xb7, 0xf5, 0x44, 0x48, 0xba, 0x9f, 0x3f, 0x08, 0xbc, 0xd0, 0x99, 0xdb, 0x21, 0xdd, 0x16, 0x2a, 0x77,
    0x9e, 0x61, 0xaa, 0x89, 0xee, 0xe5, 0x54, 0xd3, 0xa4, 0x7d, 0xe2, 0x30, 0xbc, 0x7a, 0xc5, 0x90, 0xd5, 0x24, 0x06, 0x7c,
    0x38, 0x98, 0xbb, 0xa6, 0xf5, 0xdc, 0x43, 0x60, 0xb8, 0x45, 0xed, 0xa4, 0x8c, 0xbd, 0x9c, 0xf1, 0x26, 0xa7, 0x23, 0x44,
    0x5f, 0x0e, 0x19, 0x52, 0xd7, 0x32, 0x5a, 0x75, 0xfa, 0xf5, 0x56, 0x14, 0x4f, 0x9a, 0x98, 0xaf, 0x71, 0x86, 0xb0, 0x27,
    0x86, 0x85, 0xb8, 0xe2, 0xc0, 0x8b, 0xea, 0x87, 0x17, 0x1b, 0x4d, 0xee, 0x58, 0x5c, 0x18, 0x28, 0x29, 0x5b, 0x53, 0x95,
    0xeb, 0x4a, 0x17, 0x77, 0x9f, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x81, 0x80, 0x1a, 0x4b, 0xfa, 0x4f, 0xa8, 0xc2, 0xdd,
    0x69, 0xa1, 0x15, 0x96, 0x0b, 0xe8, 0x27, 0x42, 0x5a, 0xf9, 0x5c, 0xea, 0x0c, 0xac, 0x98, 0xaa, 0xe1, 0x8d, 0xaa, 0xeb,
    0x2d, 0x3c, 0x60, 0x6a, 0xfb, 0x45, 0x63, 0xa4, 0x79, 0x83, 0x67, 0xed, 0xe4, 0x15, 0xc0, 0xb0, 0x20, 0x95, 0x6d, 0x49,
    0x16, 0xc6, 0x42, 0x05, 0x48, 0xaa, 0xb1, 0xa5, 0x53, 0x65, 0xd2, 0x02, 0x99, 0x08, 0xd1, 0x84, 0xcc, 0xf0, 0xcd, 0xea,
    0x61, 0xc9, 0x39, 0x02, 0x3f, 0x87, 0x4a, 0xe5, 0xc4, 0xd2, 0x07, 0x02, 0xe1, 0x9f, 0xa0, 0x06, 0xc2, 0xcc, 0x02, 0xe7,
    0xaa, 0x6c, 0x99, 0x8a, 0xf8, 0x49, 0x00, 0xf1, 0xa2, 0x8c, 0x0c, 0x8a, 0xb9, 0x4f, 0x6d, 0x73, 0x3b, 0x2c, 0xb7, 0x9f,
    0x8a, 0xa6, 0x7f, 0x9b, 0x9f, 0xb7, 0xa1, 0xcc, 0x74, 0x2e, 0x8f, 0xb8, 0xb0, 0x26, 0x89, 0xd2, 0xe5, 0x66, 0xe8, 0x8e,
    0xa1, 0x02, 0x41, 0x00, 0xfc, 0xe7, 0x52, 0xbc, 0x4e, 0x95, 0xb6, 0x1a, 0xb4, 0x62, 0xcc, 0xd8, 0x06, 0xe1, 0xdc, 0x7a,
    0xa2, 0xb6, 0x71, 0x01, 0xaa, 0x27, 0xfc, 0x99, 0xe5, 0xf2, 0x54, 0xbb, 0xb2, 0x85, 0xe1, 0x96, 0x54, 0x2d, 0xcb, 0xba,
    0x86, 0xfa, 0x80, 0xdf, 0xcf, 0x39, 0xe6, 0x74, 0xcb, 0x22, 0xce, 0x70, 0xaa, 0x10, 0x00, 0x73, 0x1d, 0x45, 0x0a, 0x39,
    0x51, 0x84, 0xf5, 0x15, 0x8f, 0x37, 0x76, 0x91, 0x02, 0x41, 0x00, 0xe4, 0x3f, 0xf0, 0xf4, 0xde, 0x79, 0x77, 0x48, 0x9b,
    0x9c, 0x28, 0x45, 0x26, 0x57, 0x3c, 0x71, 0x40, 0x28, 0x6a, 0xa1, 0xfe, 0xc3, 0xe5, 0x37, 0xa1, 0x03, 0xf6, 0x2d, 0xbe,
    0x80, 0x64, 0x72, 0x69, 0x2e, 0x9b, 0x4d, 0xe3, 0x2e, 0x1b, 0xfe, 0xe7, 0xf9, 0x77, 0x8c, 0x18, 0x53, 0x9f, 0xe2, 0xfe,
    0x00, 0xbb, 0x49, 0x20, 0x47, 0xdf, 0x01, 0x61, 0x87, 0xd6, 0xe3, 0x44, 0xb5, 0x03, 0x2f, 0x02, 0x40, 0x54, 0xec, 0x7c,
    0xbc, 0xdd, 0x0a, 0xaa, 0xde, 0xe6, 0xc9, 0xf2, 0x8d, 0x6c, 0x2a, 0x35, 0xf6, 0x3c, 0x63, 0x55, 0x29, 0x40, 0xf1, 0x32,
    0x82, 0x9f, 0x53, 0xb3, 0x9e, 0x5f, 0xc1, 0x53, 0x52, 0x3e, 0xac, 0x2e, 0x28, 0x51, 0xa1, 0x16, 0xdb, 0x90, 0xe3, 0x99,
    0x7e, 0x88, 0xa4, 0x04, 0x7c, 0x92, 0xae, 0xd2, 0xe7, 0xd4, 0xe1, 0x55, 0x20, 0x90, 0x3e, 0x3c, 0x6a, 0x63, 0xf0, 0x34,
    0xf1, 0x02, 0x41, 0x00, 0x84, 0x5a, 0x17, 0x6c, 0xc6, 0x3c, 0x84, 0xd0, 0x93, 0x7a, 0xff, 0x56, 0xe9, 0x9e, 0x98, 0x2b,
    0xcb, 0x5a, 0x24, 0x4a, 0xff, 0x21, 0xb4, 0x9e, 0x87, 0x3d, 0x76, 0xd8, 0x9b, 0xa8, 0x73, 0x96, 0x6c, 0x2b, 0x5c, 0x5e,
    0xd3, 0xa6, 0xff, 0x10, 0xd6, 0x8e, 0xaf, 0xa5, 0x8a, 0xcd, 0xa2, 0xde, 0xcb, 0x0e, 0xbd, 0x8a, 0xef, 0xae, 0xfd, 0x3f,
    0x1d, 0xc0, 0xd8, 0xf8, 0x3b, 0xf5, 0x02, 0x7d, 0x02, 0x41, 0x00, 0x8b, 0x26, 0xd3, 0x2c, 0x7d, 0x28, 0x38, 0x92, 0xf1,
    0xbf, 0x15, 0x16, 0x39, 0x50, 0xc8, 0x6d, 0x32, 0xec, 0x28, 0xf2, 0x8b, 0xd8, 0x70, 0xc5, 0xed, 0xe1, 0x7b, 0xff, 0x2d,
    0x66, 0x8c, 0x86, 0x77, 0x43, 0xeb, 0xb6, 0xf6, 0x50, 0x66, 0xb0, 0x40, 0x24, 0x6a, 0xaf, 0x98, 0x21, 0x45, 0x30, 0x01,
    0x59, 0xd0, 0xc3, 0xfc, 0x7b, 0xae, 0x30, 0x18, 0xeb, 0x90, 0xfb, 0x17, 0xd3, 0xce, 0xb5
  });
  
  /**
   * Set the KeyLocator using the full SELFREG_PUBLIC_KEY_DER, sign the data 
   * packet using SELFREG_PRIVATE_KEY_DER and set the signature.
   * This is a temporary function, because we expect in the future that 
   * registerPrefix will not require a signature on the packet.
   * @param data The Data packet to sign.
   * @param wireFormat The WireFormat for encoding the Data packet.
   */
  private static void
  selfregSign(Data data, WireFormat wireFormat)
  {
    data.setSignature(new Sha256WithRsaSignature());
    Sha256WithRsaSignature signature = (Sha256WithRsaSignature)data.getSignature();

    // Set the public key.
    // Since we encode the register prefix message as BinaryXml, use the full
    //   public key in the key locator to make the legacy NDNx happy.
    signature.getPublisherPublicKeyDigest().setPublisherPublicKeyDigest
      (new Blob(Common.digestSha256(SELFREG_PUBLIC_KEY_DER)));
    signature.getKeyLocator().setType(KeyLocatorType.KEY);
    signature.getKeyLocator().setKeyData(new Blob(SELFREG_PUBLIC_KEY_DER, false));
    
    // Set the private key.
    KeyFactory keyFactory = null;
    try {
      keyFactory = KeyFactory.getInstance("RSA");
    } 
    catch (NoSuchAlgorithmException exception) {
      // Don't expect this to happen.
      throw new Error
        ("KeyFactory: RSA is not supported: " + exception.getMessage());
    }
    PrivateKey privateKey;
    try {
      privateKey = keyFactory.generatePrivate
        (new PKCS8EncodedKeySpec(SELFREG_PRIVATE_KEY_DER.array()));
    }
    catch (InvalidKeySpecException exception) {
      // Don't expect this to happen.
      throw new Error
        ("KeyFactory: PKCS8EncodedKeySpec is not supported: " +
         exception.getMessage());
    }

    // Sign the fields.
    SignedBlob encoding = data.wireEncode(wireFormat);
    java.security.Signature securitySignature = null;
    try {
      securitySignature = java.security.Signature.getInstance("SHA256withRSA");
    } 
    catch (NoSuchAlgorithmException e) {
      // Don't expect this to happen.
      throw new Error("SHA256withRSA algorithm is not supported");
    }
    try {
      securitySignature.initSign(privateKey);
    }
    catch (InvalidKeyException exception) {
      throw new Error("InvalidKeyException: " + exception.getMessage());
    }
    try {
      securitySignature.update(encoding.signedBuf());
      signature.setSignature(new Blob(securitySignature.sign()));
    }
    catch (SignatureException exception) {
      throw new Error("SignatureException: " + exception.getMessage());
    }
  }
  
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
  
  /**
   * Do the work of registerPrefix once we know we are connected with an ndndId_.
   * @param registeredPrefixId The RegisteredPrefix.getNextRegisteredPrefixId()
   * which registerPrefix got so it could return it to the caller.
   * @param prefix
   * @param onInterest
   * @param onRegisterFailed
   * @param flags
   * @param wireFormat 
   */
  private void
  registerPrefixHelper
    (long registeredPrefixId, Name prefix, OnInterest onInterest, 
     OnRegisterFailed onRegisterFailed, ForwardingFlags flags, 
     WireFormat wireFormat)
  {
    // Create a ForwardingEntry.
    // Note: ndnd ignores any freshness that is larger than 3600 seconds and 
    //   sets 300 seconds instead.  To register "forever", (=2000000000 sec), 
    //   the freshness period must be omitted.
    ForwardingEntry forwardingEntry = new ForwardingEntry();
    forwardingEntry.setAction("selfreg");
    forwardingEntry.setPrefix(prefix);
    forwardingEntry.setForwardingFlags(flags);
    // Always encode as BinaryXml since the internals of ndnd expect it.
    Blob content = forwardingEntry.wireEncode(BinaryXmlWireFormat.get());

    // Set the ForwardingEntry as the content of a Data packet and sign.
    Data data = new Data();
    data.setContent(content);
    // Use the deprecated setTimestampMilliseconds because ndnd requires it.
    data.getMetaInfo().setTimestampMilliseconds(Common.getNowMilliseconds());
    // For now, self sign with an arbirary key.  In the future, we may not 
    //   require a signature to register.
    // Always encode as BinaryXml since the internals of ndnd expect it.
    selfregSign(data, BinaryXmlWireFormat.get());
    Blob encodedData = data.wireEncode(BinaryXmlWireFormat.get());

    // Create an interest where the name has the encoded Data packet.
    Name interestName = new Name().append("ndnx").append(ndndId_).append
      ("selfreg").append(encodedData);

    Interest interest = new Interest(interestName);
    interest.setInterestLifetimeMilliseconds(4000.0);
    interest.setScope(1);

    // Save the onInterest callback and send the registration interest.
    registeredPrefixTable_.add
      (new RegisteredPrefix(registeredPrefixId, prefix, onInterest));

    RegisterResponse response = new RegisterResponse
      (new RegisterResponse.Info(prefix, onRegisterFailed));
    try {
      expressInterest(interest, response, response, wireFormat);
    } 
    catch (IOException ex) {
      // Can't send the interest. Call onRegisterFailed.
      onRegisterFailed.onRegisterFailed(prefix);
    }
  }
  
  private Transport transport_;
  private Transport.ConnectionInfo connectionInfo_;
  private ArrayList pendingInterestTable_ = new ArrayList();  // PendingInterest
  private ArrayList registeredPrefixTable_ = new ArrayList(); // RegisteredPrefix
  private Interest ndndIdFetcherInterest_;
  private Blob ndndId_ = new Blob();
  private static final SecureRandom random_ = new SecureRandom();
}
