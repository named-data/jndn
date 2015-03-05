/**
 * Copyright (C) 2014-2015 Regents of the University of California.
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
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.encoding.BinaryXml;
import net.named_data.jndn.encoding.BinaryXmlDecoder;
import net.named_data.jndn.encoding.BinaryXmlWireFormat;
import net.named_data.jndn.encoding.ElementListener;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.TlvWireFormat;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.encoding.tlv.Tlv;
import net.named_data.jndn.encoding.tlv.TlvDecoder;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.transport.Transport;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.CommandInterestGenerator;
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

    // Special case: For timeoutPrefix_ we don't actually send the interest.
    if (!timeoutPrefix_.match(interest.getName())) {
      Blob encoding = interest.wireEncode(wireFormat);
      transport_.send(encoding.buf());
    }
    
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
   * Append a timestamp component and a random value component to interest's
   * name. Then use the keyChain and certificateName to sign the interest. If
   * the interest lifetime is not set, this sets it.
   * @param interest The interest whose name is append with components.
   * @param keyChain The KeyChain object for signing interests.
   * @param certificateName The certificate name for signing interests.
   * @param wireFormat A WireFormat object used to encode the SignatureInfo and
   * to encode interest name for signing.
   * @throws SecurityException If cannot find the private key for the
   * certificateName.
   */
  void
  makeCommandInterest
    (Interest interest, KeyChain keyChain, Name certificateName,
     WireFormat wireFormat) throws SecurityException
  {
    commandInterestGenerator_.generate
      (interest, keyChain, certificateName, wireFormat);
  }

  /**
   * Register prefix with the connected NDN hub and call onInterest when a
   * matching interest is received.
   * @param prefix A Name for the prefix to register. This copies the Name.
   * @param onInterest This calls onInterest.onInterest(prefix, interest) when
   * a matching interest is received.
   * @param onRegisterFailed This calls onRegisterFailed.onRegisterFailed(prefix)
   * if failed to retrieve the connected hub's ID or failed to register the
   * prefix.
   * @param flags The flags for finer control of which interests are forwarded
   * to the application.
   * @param wireFormat A WireFormat object used to encode the message.
   * @return The registered prefix ID which can be used with
   * removeRegisteredPrefix.
   * @param commandKeyChain The KeyChain object for signing interests.  If null,
   * assume we are connected to a legacy NDNx forwarder.
   * @param commandCertificateName The certificate name for signing interests.
   * @throws IOException For I/O error in sending the registration request.
   * @throws SecurityException If signing a command interest for NFD and cannot
   * find the private key for the certificateName.
   */
  public final long
  registerPrefix
    (Name prefix, OnInterest onInterest, OnRegisterFailed onRegisterFailed,
     ForwardingFlags flags, WireFormat wireFormat, KeyChain commandKeyChain,
     Name commandCertificateName) throws IOException, SecurityException
  {
    // Get the registeredPrefixId now so we can return it to the caller.
    long registeredPrefixId = RegisteredPrefix.getNextRegisteredPrefixId();

    // If we have an _ndndId, we know we already connected to NDNx.
    if (ndndId_.size() != 0 || commandKeyChain == null) {
      // Assume we are connected to a legacy NDNx server.

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
    }
    else
      // The application set the KeyChain for signing NFD interests.
      nfdRegisterPrefix
        (registeredPrefixId, new Name(prefix), onInterest,
         onRegisterFailed, flags, commandKeyChain, commandCertificateName,
         wireFormat);

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
   * loop doesn't use 100% of the CPU. Since processEvents modifies the pending
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
    LocalControlHeader localControlHeader = null;
    if (element.get(0) == Tlv.LocalControlHeader_LocalControlHeader) {
      // Decode the LocalControlHeader and replace element with the payload.
      localControlHeader = new LocalControlHeader();
      localControlHeader.wireDecode(element, TlvWireFormat.get());
      element = localControlHeader.getPayloadWireEncoding().buf();
    }

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

        if (localControlHeader != null)
          interest.setLocalControlHeader(localControlHeader);
      }
      else if (decoder.peekType(Tlv.Data, element.remaining())) {
        data = new Data();
        data.wireDecode(element, TlvWireFormat.get());

        if (localControlHeader != null)
          data.setLocalControlHeader(localControlHeader);
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
        Logger.getLogger(Node.class.getName()).log(Level.INFO,
          "Register prefix failed: The content returned when fetching the NDNx ID does not appear to be a public key");
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
      Logger.getLogger(Node.class.getName()).log(Level.INFO,
        "Register prefix failed: Timeout fetching the NDNx ID");
      info_.onRegisterFailed_.onRegisterFailed(info_.prefix_);
    }

    private static class Info {
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
      if (info_.isNfdCommand_) {
        // Decode responseData.getContent() and check for a success code.
        // TODO: Move this into the TLV code.
        TlvDecoder decoder = new TlvDecoder(responseData.getContent().buf());
        long statusCode;
        try {
          decoder.readNestedTlvsStart(Tlv.NfdCommand_ControlResponse);
          statusCode = decoder.readNonNegativeIntegerTlv
               (Tlv.NfdCommand_StatusCode);
        }
        catch (EncodingException ex) {
          Logger.getLogger(Node.class.getName()).log(Level.INFO,
            "Register prefix failed: Error decoding the NFD response: {0}", ex);
          info_.onRegisterFailed_.onRegisterFailed(info_.prefix_);
          return;
        }

        // Status code 200 is "OK".
        if (statusCode != 200) {
          Logger.getLogger(Node.class.getName()).log(Level.INFO,
            "Register prefix failed: Expected NFD status code 200, got: {0}", statusCode);
          info_.onRegisterFailed_.onRegisterFailed(info_.prefix_);
        }

        Logger.getLogger(Node.class.getName()).log(Level.INFO, 
          "Register prefix succeeded with the NFD forwarder for prefix {0}",
          info_.prefix_.toUri());
      }
      else {
        Name expectedName = new Name("/ndnx/.../selfreg");
        // Got a response. Do a quick check of expected name components.
        if (responseData.getName().size() < 4 ||
            !responseData.getName().get(0).equals(expectedName.get(0)) ||
            !responseData.getName().get(2).equals(expectedName.get(2))) {
          Logger.getLogger(Node.class.getName()).log(Level.INFO,
            "Register prefix failed: Unexpected name in NDNx response: {0}",
            responseData.getName().toUri());
          info_.onRegisterFailed_.onRegisterFailed(info_.prefix_);
          return;
        }

        Logger.getLogger(Node.class.getName()).log(Level.INFO,
          "Register prefix succeeded with the NDNx forwarder for prefix {0}",
          info_.prefix_.toUri());
      }
    }

    /**
     * We timed out waiting for the response.
     * @param timedOutInterest
     */
    public void
    onTimeout(Interest timedOutInterest)
    {
      if (info_.isNfdCommand_) {
        Logger.getLogger(Node.class.getName()).log(Level.INFO,
          "Timeout for NFD register prefix command. Attempting an NDNx command...");
        // The application set the commandKeyChain, but we may be connected to NDNx.
        if (info_.node_.ndndId_.size() == 0) {
          // First fetch the ndndId of the connected hub.
          // Pass 0 for registeredPrefixId since the entry was already added to
          //   registeredPrefixTable_ on the first try.
          NdndIdFetcher fetcher = new NdndIdFetcher
            (new NdndIdFetcher.Info
              (info_.node_, 0, info_.prefix_, info_.onInterest_,
               info_.onRegisterFailed_, info_.flags_, info_.wireFormat_));
          // We send the interest using the given wire format so that the hub
          // receives (and sends) in the application's desired wire format.
          try {
            info_.node_.expressInterest
              (info_.node_.ndndIdFetcherInterest_, fetcher, fetcher,
               info_.wireFormat_);
          }
          catch (IOException ex) {
            // We don't expect this to happen since we already sent data
            //   through the transport.
            Logger.getLogger(Node.class.getName()).log(Level.INFO,
              "Register prefix failed: Error sending the register prefix interest to the forwarder: {0}", ex);
            info_.onRegisterFailed_.onRegisterFailed(info_.prefix_);
          }
        }
        else
          // Pass 0 for registeredPrefixId since the entry was already added to
          //   registeredPrefixTable_ on the first try.
          info_.node_.registerPrefixHelper
            (0, new Name(info_.prefix_), info_.onInterest_, info_.onRegisterFailed_,
             info_.flags_, info_.wireFormat_);
      }
      else {
        // An NDNx command was sent because there is no commandKeyChain, so we
        //   can't try an NFD command. Or it was sent from this callback after
        //   trying an NFD command. Fail.

        Logger.getLogger(Node.class.getName()).log(Level.INFO,
          "Register prefix failed: Timeout waiting for the response from the register prefix interest");
        info_.onRegisterFailed_.onRegisterFailed(info_.prefix_);
      }
    }

    public static class Info {
      public Info
        (Node node, Name prefix, OnInterest onInterest,
         OnRegisterFailed onRegisterFailed, ForwardingFlags flags,
         WireFormat wireFormat, boolean isNfdCommand)
      {
        node_ = node;
        prefix_ = prefix;
        onInterest_ = onInterest;
        onRegisterFailed_ = onRegisterFailed;
        flags_ = flags;
        wireFormat_ = wireFormat;
        isNfdCommand_ = isNfdCommand;
      }

      public final Node node_;
      public final Name prefix_;
      public final OnInterest onInterest_;
      public final OnRegisterFailed onRegisterFailed_;
      public final ForwardingFlags flags_;
      public final WireFormat wireFormat_;
      public final boolean isNfdCommand_;
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
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
    0x00, 0xb8, 0x09, 0xa7, 0x59, 0x82, 0x84, 0xec, 0x4f, 0x06, 0xfa, 0x1c, 0xb2, 0xe1, 0x38, 0x93,
    0x53, 0xbb, 0x7d, 0xd4, 0xac, 0x88, 0x1a, 0xf8, 0x25, 0x11, 0xe4, 0xfa, 0x1d, 0x61, 0x24, 0x5b,
    0x82, 0xca, 0xcd, 0x72, 0xce, 0xdb, 0x66, 0xb5, 0x8d, 0x54, 0xbd, 0xfb, 0x23, 0xfd, 0xe8, 0x8e,
    0xaf, 0xa7, 0xb3, 0x79, 0xbe, 0x94, 0xb5, 0xb7, 0xba, 0x17, 0xb6, 0x05, 0xae, 0xce, 0x43, 0xbe,
    0x3b, 0xce, 0x6e, 0xea, 0x07, 0xdb, 0xbf, 0x0a, 0x7e, 0xeb, 0xbc, 0xc9, 0x7b, 0x62, 0x3c, 0xf5,
    0xe1, 0xce, 0xe1, 0xd9, 0x8d, 0x9c, 0xfe, 0x1f, 0xc7, 0xf8, 0xfb, 0x59, 0xc0, 0x94, 0x0b, 0x2c,
    0xd9, 0x7d, 0xbc, 0x96, 0xeb, 0xb8, 0x79, 0x22, 0x8a, 0x2e, 0xa0, 0x12, 0x1d, 0x42, 0x07, 0xb6,
    0x5d, 0xdb, 0xe1, 0xf6, 0xb1, 0x5d, 0x7b, 0x1f, 0x54, 0x52, 0x1c, 0xa3, 0x11, 0x9b, 0xf9, 0xeb,
    0xbe, 0xb3, 0x95, 0xca, 0xa5, 0x87, 0x3f, 0x31, 0x18, 0x1a, 0xc9, 0x99, 0x01, 0xec, 0xaa, 0x90,
    0xfd, 0x8a, 0x36, 0x35, 0x5e, 0x12, 0x81, 0xbe, 0x84, 0x88, 0xa1, 0x0d, 0x19, 0x2a, 0x4a, 0x66,
    0xc1, 0x59, 0x3c, 0x41, 0x83, 0x3d, 0x3d, 0xb8, 0xd4, 0xab, 0x34, 0x90, 0x06, 0x3e, 0x1a, 0x61,
    0x74, 0xbe, 0x04, 0xf5, 0x7a, 0x69, 0x1b, 0x9d, 0x56, 0xfc, 0x83, 0xb7, 0x60, 0xc1, 0x5e, 0x9d,
    0x85, 0x34, 0xfd, 0x02, 0x1a, 0xba, 0x2c, 0x09, 0x72, 0xa7, 0x4a, 0x5e, 0x18, 0xbf, 0xc0, 0x58,
    0xa7, 0x49, 0x34, 0x46, 0x61, 0x59, 0x0e, 0xe2, 0x6e, 0x9e, 0xd2, 0xdb, 0xfd, 0x72, 0x2f, 0x3c,
    0x47, 0xcc, 0x5f, 0x99, 0x62, 0xee, 0x0d, 0xf3, 0x1f, 0x30, 0x25, 0x20, 0x92, 0x15, 0x4b, 0x04,
    0xfe, 0x15, 0x19, 0x1d, 0xdc, 0x7e, 0x5c, 0x10, 0x21, 0x52, 0x21, 0x91, 0x54, 0x60, 0x8b, 0x92,
    0x41, 0x02, 0x03, 0x01, 0x00, 0x01
  });

  // Java uses an unencrypted PKCS #8 PrivateKeyInfo, not a PKCS #1 RSAPrivateKey.
  private static final ByteBuffer SELFREG_PRIVATE_KEY_DER = toBuffer(new int[] {
    0x30, 0x82, 0x04, 0xbf, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
    0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82, 0x04, 0xa9, 0x30, 0x82, 0x04, 0xa5, 0x02, 0x01,
    0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xb8, 0x09, 0xa7, 0x59, 0x82, 0x84, 0xec, 0x4f, 0x06, 0xfa,
    0x1c, 0xb2, 0xe1, 0x38, 0x93, 0x53, 0xbb, 0x7d, 0xd4, 0xac, 0x88, 0x1a, 0xf8, 0x25, 0x11, 0xe4,
    0xfa, 0x1d, 0x61, 0x24, 0x5b, 0x82, 0xca, 0xcd, 0x72, 0xce, 0xdb, 0x66, 0xb5, 0x8d, 0x54, 0xbd,
    0xfb, 0x23, 0xfd, 0xe8, 0x8e, 0xaf, 0xa7, 0xb3, 0x79, 0xbe, 0x94, 0xb5, 0xb7, 0xba, 0x17, 0xb6,
    0x05, 0xae, 0xce, 0x43, 0xbe, 0x3b, 0xce, 0x6e, 0xea, 0x07, 0xdb, 0xbf, 0x0a, 0x7e, 0xeb, 0xbc,
    0xc9, 0x7b, 0x62, 0x3c, 0xf5, 0xe1, 0xce, 0xe1, 0xd9, 0x8d, 0x9c, 0xfe, 0x1f, 0xc7, 0xf8, 0xfb,
    0x59, 0xc0, 0x94, 0x0b, 0x2c, 0xd9, 0x7d, 0xbc, 0x96, 0xeb, 0xb8, 0x79, 0x22, 0x8a, 0x2e, 0xa0,
    0x12, 0x1d, 0x42, 0x07, 0xb6, 0x5d, 0xdb, 0xe1, 0xf6, 0xb1, 0x5d, 0x7b, 0x1f, 0x54, 0x52, 0x1c,
    0xa3, 0x11, 0x9b, 0xf9, 0xeb, 0xbe, 0xb3, 0x95, 0xca, 0xa5, 0x87, 0x3f, 0x31, 0x18, 0x1a, 0xc9,
    0x99, 0x01, 0xec, 0xaa, 0x90, 0xfd, 0x8a, 0x36, 0x35, 0x5e, 0x12, 0x81, 0xbe, 0x84, 0x88, 0xa1,
    0x0d, 0x19, 0x2a, 0x4a, 0x66, 0xc1, 0x59, 0x3c, 0x41, 0x83, 0x3d, 0x3d, 0xb8, 0xd4, 0xab, 0x34,
    0x90, 0x06, 0x3e, 0x1a, 0x61, 0x74, 0xbe, 0x04, 0xf5, 0x7a, 0x69, 0x1b, 0x9d, 0x56, 0xfc, 0x83,
    0xb7, 0x60, 0xc1, 0x5e, 0x9d, 0x85, 0x34, 0xfd, 0x02, 0x1a, 0xba, 0x2c, 0x09, 0x72, 0xa7, 0x4a,
    0x5e, 0x18, 0xbf, 0xc0, 0x58, 0xa7, 0x49, 0x34, 0x46, 0x61, 0x59, 0x0e, 0xe2, 0x6e, 0x9e, 0xd2,
    0xdb, 0xfd, 0x72, 0x2f, 0x3c, 0x47, 0xcc, 0x5f, 0x99, 0x62, 0xee, 0x0d, 0xf3, 0x1f, 0x30, 0x25,
    0x20, 0x92, 0x15, 0x4b, 0x04, 0xfe, 0x15, 0x19, 0x1d, 0xdc, 0x7e, 0x5c, 0x10, 0x21, 0x52, 0x21,
    0x91, 0x54, 0x60, 0x8b, 0x92, 0x41, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01, 0x01, 0x00,
    0x8a, 0x05, 0xfb, 0x73, 0x7f, 0x16, 0xaf, 0x9f, 0xa9, 0x4c, 0xe5, 0x3f, 0x26, 0xf8, 0x66, 0x4d,
    0xd2, 0xfc, 0xd1, 0x06, 0xc0, 0x60, 0xf1, 0x9f, 0xe3, 0xa6, 0xc6, 0x0a, 0x48, 0xb3, 0x9a, 0xca,
    0x21, 0xcd, 0x29, 0x80, 0x88, 0x3d, 0xa4, 0x85, 0xa5, 0x7b, 0x82, 0x21, 0x81, 0x28, 0xeb, 0xf2,
    0x43, 0x24, 0xb0, 0x76, 0xc5, 0x52, 0xef, 0xc2, 0xea, 0x4b, 0x82, 0x41, 0x92, 0xc2, 0x6d, 0xa6,
    0xae, 0xf0, 0xb2, 0x26, 0x48, 0xa1, 0x23, 0x7f, 0x02, 0xcf, 0xa8, 0x90, 0x17, 0xa2, 0x3e, 0x8a,
    0x26, 0xbd, 0x6d, 0x8a, 0xee, 0xa6, 0x0c, 0x31, 0xce, 0xc2, 0xbb, 0x92, 0x59, 0xb5, 0x73, 0xe2,
    0x7d, 0x91, 0x75, 0xe2, 0xbd, 0x8c, 0x63, 0xe2, 0x1c, 0x8b, 0xc2, 0x6a, 0x1c, 0xfe, 0x69, 0xc0,
    0x44, 0xcb, 0x58, 0x57, 0xb7, 0x13, 0x42, 0xf0, 0xdb, 0x50, 0x4c, 0xe0, 0x45, 0x09, 0x8f, 0xca,
    0x45, 0x8a, 0x06, 0xfe, 0x98, 0xd1, 0x22, 0xf5, 0x5a, 0x9a, 0xdf, 0x89, 0x17, 0xca, 0x20, 0xcc,
    0x12, 0xa9, 0x09, 0x3d, 0xd5, 0xf7, 0xe3, 0xeb, 0x08, 0x4a, 0xc4, 0x12, 0xc0, 0xb9, 0x47, 0x6c,
    0x79, 0x50, 0x66, 0xa3, 0xf8, 0xaf, 0x2c, 0xfa, 0xb4, 0x6b, 0xec, 0x03, 0xad, 0xcb, 0xda, 0x24,
    0x0c, 0x52, 0x07, 0x87, 0x88, 0xc0, 0x21, 0xf3, 0x02, 0xe8, 0x24, 0x44, 0x0f, 0xcd, 0xa0, 0xad,
    0x2f, 0x1b, 0x79, 0xab, 0x6b, 0x49, 0x4a, 0xe6, 0x3b, 0xd0, 0xad, 0xc3, 0x48, 0xb9, 0xf7, 0xf1,
    0x34, 0x09, 0xeb, 0x7a, 0xc0, 0xd5, 0x0d, 0x39, 0xd8, 0x45, 0xce, 0x36, 0x7a, 0xd8, 0xde, 0x3c,
    0xb0, 0x21, 0x96, 0x97, 0x8a, 0xff, 0x8b, 0x23, 0x60, 0x4f, 0xf0, 0x3d, 0xd7, 0x8f, 0xf3, 0x2c,
    0xcb, 0x1d, 0x48, 0x3f, 0x86, 0xc4, 0xa9, 0x00, 0xf2, 0x23, 0x2d, 0x72, 0x4d, 0x66, 0xa5, 0x01,
    0x02, 0x81, 0x81, 0x00, 0xdc, 0x4f, 0x99, 0x44, 0x0d, 0x7f, 0x59, 0x46, 0x1e, 0x8f, 0xe7, 0x2d,
    0x8d, 0xdd, 0x54, 0xc0, 0xf7, 0xfa, 0x46, 0x0d, 0x9d, 0x35, 0x03, 0xf1, 0x7c, 0x12, 0xf3, 0x5a,
    0x9d, 0x83, 0xcf, 0xdd, 0x37, 0x21, 0x7c, 0xb7, 0xee, 0xc3, 0x39, 0xd2, 0x75, 0x8f, 0xb2, 0x2d,
    0x6f, 0xec, 0xc6, 0x03, 0x55, 0xd7, 0x00, 0x67, 0xd3, 0x9b, 0xa2, 0x68, 0x50, 0x6f, 0x9e, 0x28,
    0xa4, 0x76, 0x39, 0x2b, 0xb2, 0x65, 0xcc, 0x72, 0x82, 0x93, 0xa0, 0xcf, 0x10, 0x05, 0x6a, 0x75,
    0xca, 0x85, 0x35, 0x99, 0xb0, 0xa6, 0xc6, 0xef, 0x4c, 0x4d, 0x99, 0x7d, 0x2c, 0x38, 0x01, 0x21,
    0xb5, 0x31, 0xac, 0x80, 0x54, 0xc4, 0x18, 0x4b, 0xfd, 0xef, 0xb3, 0x30, 0x22, 0x51, 0x5a, 0xea,
    0x7d, 0x9b, 0xb2, 0x9d, 0xcb, 0xba, 0x3f, 0xc0, 0x1a, 0x6b, 0xcd, 0xb0, 0xe6, 0x2f, 0x04, 0x33,
    0xd7, 0x3a, 0x49, 0x71, 0x02, 0x81, 0x81, 0x00, 0xd5, 0xd9, 0xc9, 0x70, 0x1a, 0x13, 0xb3, 0x39,
    0x24, 0x02, 0xee, 0xb0, 0xbb, 0x84, 0x17, 0x12, 0xc6, 0xbd, 0x65, 0x73, 0xe9, 0x34, 0x5d, 0x43,
    0xff, 0xdc, 0xf8, 0x55, 0xaf, 0x2a, 0xb9, 0xe1, 0xfa, 0x71, 0x65, 0x4e, 0x50, 0x0f, 0xa4, 0x3b,
    0xe5, 0x68, 0xf2, 0x49, 0x71, 0xaf, 0x15, 0x88, 0xd7, 0xaf, 0xc4, 0x9d, 0x94, 0x84, 0x6b, 0x5b,
    0x10, 0xd5, 0xc0, 0xaa, 0x0c, 0x13, 0x62, 0x99, 0xc0, 0x8b, 0xfc, 0x90, 0x0f, 0x87, 0x40, 0x4d,
    0x58, 0x88, 0xbd, 0xe2, 0xba, 0x3e, 0x7e, 0x2d, 0xd7, 0x69, 0xa9, 0x3c, 0x09, 0x64, 0x31, 0xb6,
    0xcc, 0x4d, 0x1f, 0x23, 0xb6, 0x9e, 0x65, 0xd6, 0x81, 0xdc, 0x85, 0xcc, 0x1e, 0xf1, 0x0b, 0x84,
    0x38, 0xab, 0x93, 0x5f, 0x9f, 0x92, 0x4e, 0x93, 0x46, 0x95, 0x6b, 0x3e, 0xb6, 0xc3, 0x1b, 0xd7,
    0x69, 0xa1, 0x0a, 0x97, 0x37, 0x78, 0xed, 0xd1, 0x02, 0x81, 0x80, 0x33, 0x18, 0xc3, 0x13, 0x65,
    0x8e, 0x03, 0xc6, 0x9f, 0x90, 0x00, 0xae, 0x30, 0x19, 0x05, 0x6f, 0x3c, 0x14, 0x6f, 0xea, 0xf8,
    0x6b, 0x33, 0x5e, 0xee, 0xc7, 0xf6, 0x69, 0x2d, 0xdf, 0x44, 0x76, 0xaa, 0x32, 0xba, 0x1a, 0x6e,
    0xe6, 0x18, 0xa3, 0x17, 0x61, 0x1c, 0x92, 0x2d, 0x43, 0x5d, 0x29, 0xa8, 0xdf, 0x14, 0xd8, 0xff,
    0xdb, 0x38, 0xef, 0xb8, 0xb8, 0x2a, 0x96, 0x82, 0x8e, 0x68, 0xf4, 0x19, 0x8c, 0x42, 0xbe, 0xcc,
    0x4a, 0x31, 0x21, 0xd5, 0x35, 0x6c, 0x5b, 0xa5, 0x7c, 0xff, 0xd1, 0x85, 0x87, 0x28, 0xdc, 0x97,
    0x75, 0xe8, 0x03, 0x80, 0x1d, 0xfd, 0x25, 0x34, 0x41, 0x31, 0x21, 0x12, 0x87, 0xe8, 0x9a, 0xb7,
    0x6a, 0xc0, 0xc4, 0x89, 0x31, 0x15, 0x45, 0x0d, 0x9c, 0xee, 0xf0, 0x6a, 0x2f, 0xe8, 0x59, 0x45,
    0xc7, 0x7b, 0x0d, 0x6c, 0x55, 0xbb, 0x43, 0xca, 0xc7, 0x5a, 0x01, 0x02, 0x81, 0x81, 0x00, 0xab,
    0xf4, 0xd5, 0xcf, 0x78, 0x88, 0x82, 0xc2, 0xdd, 0xbc, 0x25, 0xe6, 0xa2, 0xc1, 0xd2, 0x33, 0xdc,
    0xef, 0x0a, 0x97, 0x2b, 0xdc, 0x59, 0x6a, 0x86, 0x61, 0x4e, 0xa6, 0xc7, 0x95, 0x99, 0xa6, 0xa6,
    0x55, 0x6c, 0x5a, 0x8e, 0x72, 0x25, 0x63, 0xac, 0x52, 0xb9, 0x10, 0x69, 0x83, 0x99, 0xd3, 0x51,
    0x6c, 0x1a, 0xb3, 0x83, 0x6a, 0xff, 0x50, 0x58, 0xb7, 0x28, 0x97, 0x13, 0xe2, 0xba, 0x94, 0x5b,
    0x89, 0xb4, 0xea, 0xba, 0x31, 0xcd, 0x78, 0xe4, 0x4a, 0x00, 0x36, 0x42, 0x00, 0x62, 0x41, 0xc6,
    0x47, 0x46, 0x37, 0xea, 0x6d, 0x50, 0xb4, 0x66, 0x8f, 0x55, 0x0c, 0xc8, 0x99, 0x91, 0xd5, 0xec,
    0xd2, 0x40, 0x1c, 0x24, 0x7d, 0x3a, 0xff, 0x74, 0xfa, 0x32, 0x24, 0xe0, 0x11, 0x2b, 0x71, 0xad,
    0x7e, 0x14, 0xa0, 0x77, 0x21, 0x68, 0x4f, 0xcc, 0xb6, 0x1b, 0xe8, 0x00, 0x49, 0x13, 0x21, 0x02,
    0x81, 0x81, 0x00, 0xb6, 0x18, 0x73, 0x59, 0x2c, 0x4f, 0x92, 0xac, 0xa2, 0x2e, 0x5f, 0xb6, 0xbe,
    0x78, 0x5d, 0x47, 0x71, 0x04, 0x92, 0xf0, 0xd7, 0xe8, 0xc5, 0x7a, 0x84, 0x6b, 0xb8, 0xb4, 0x30,
    0x1f, 0xd8, 0x0d, 0x58, 0xd0, 0x64, 0x80, 0xa7, 0x21, 0x1a, 0x48, 0x00, 0x37, 0xd6, 0x19, 0x71,
    0xbb, 0x91, 0x20, 0x9d, 0xe2, 0xc3, 0xec, 0xdb, 0x36, 0x1c, 0xca, 0x48, 0x7d, 0x03, 0x32, 0x74,
    0x1e, 0x65, 0x73, 0x02, 0x90, 0x73, 0xd8, 0x3f, 0xb5, 0x52, 0x35, 0x79, 0x1c, 0xee, 0x93, 0xa3,
    0x32, 0x8b, 0xed, 0x89, 0x98, 0xf1, 0x0c, 0xd8, 0x12, 0xf2, 0x89, 0x7f, 0x32, 0x23, 0xec, 0x67,
    0x66, 0x52, 0x83, 0x89, 0x99, 0x5e, 0x42, 0x2b, 0x42, 0x4b, 0x84, 0x50, 0x1b, 0x3e, 0x47, 0x6d,
    0x74, 0xfb, 0xd1, 0xa6, 0x10, 0x20, 0x6c, 0x6e, 0xbe, 0x44, 0x3f, 0xb9, 0xfe, 0xbc, 0x8d, 0xda,
    0xcb, 0xea, 0x8f
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
    catch (NoSuchAlgorithmException ex) {
      // Don't expect this to happen.
      throw new Error
        ("KeyFactory: RSA is not supported: " + ex.getMessage());
    }
    PrivateKey privateKey;
    try {
      privateKey = keyFactory.generatePrivate
        (new PKCS8EncodedKeySpec(SELFREG_PRIVATE_KEY_DER.array()));
    }
    catch (InvalidKeySpecException ex) {
      // Don't expect this to happen.
      throw new Error
        ("KeyFactory: PKCS8EncodedKeySpec is not supported: " +
         ex.getMessage());
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
    catch (InvalidKeyException ex) {
      throw new Error("InvalidKeyException: " + ex.getMessage());
    }
    try {
      securitySignature.update(encoding.signedBuf());
      signature.setSignature(new Blob(securitySignature.sign()));
    }
    catch (SignatureException ex) {
      throw new Error("SignatureException: " + ex.getMessage());
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
   * which registerPrefix got so it could return it to the caller. If this
   * is 0, then don't add to registeredPrefixTable_ (assuming it has already
   * been done).
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

    if (registeredPrefixId != 0)
      // Save the onInterest callback and send the registration interest.
      registeredPrefixTable_.add
        (new RegisteredPrefix(registeredPrefixId, prefix, onInterest));

    RegisterResponse response = new RegisterResponse
      (new RegisterResponse.Info
       (this, prefix, onInterest, onRegisterFailed, flags, wireFormat, false));
    try {
      expressInterest(interest, response, response, wireFormat);
    }
    catch (IOException ex) {
      // Can't send the interest. Call onRegisterFailed.
      Logger.getLogger(Node.class.getName()).log(Level.INFO,
        "Register prefix failed: Error sending the register prefix interest to the forwarder: {0}", ex);
      onRegisterFailed.onRegisterFailed(prefix);
    }
  }

  /**
   * Do the work of registerPrefix to register with NFD.
   * @param registeredPrefixId The RegisteredPrefix.getNextRegisteredPrefixId()
   * which registerPrefix got so it could return it to the caller. If this
   * is 0, then don't add to registeredPrefixTable_ (assuming it has already
   * been done).
   * @param prefix
   * @param onInterest
   * @param onRegisterFailed
   * @param flags
   * @param commandKeyChain
   * @param commandCertificateName
   * @param wireFormat
   * @throws SecurityException If cannot find the private key for the
   * certificateName.
   */
  private void
  nfdRegisterPrefix
    (long registeredPrefixId, Name prefix, OnInterest onInterest, 
     OnRegisterFailed onRegisterFailed, ForwardingFlags flags,
     KeyChain commandKeyChain, Name commandCertificateName,
     WireFormat wireFormat) throws SecurityException
  {
    if (commandKeyChain == null)
      throw new Error
        ("registerPrefix: The command KeyChain has not been set. You must call setCommandSigningInfo.");
    if (commandCertificateName.size() == 0)
      throw new Error
        ("registerPrefix: The command certificate name has not been set. You must call setCommandSigningInfo.");

    ControlParameters controlParameters = new ControlParameters();
    controlParameters.setName(prefix);

    Interest commandInterest = new Interest(new Name("/localhost/nfd/rib/register"));
    // NFD only accepts TlvWireFormat packets.
    commandInterest.getName().append(controlParameters.wireEncode(TlvWireFormat.get()));
    makeCommandInterest
      (commandInterest, commandKeyChain, commandCertificateName,
       TlvWireFormat.get());
    // The interest is answered by the local host, so set a short timeout.
    commandInterest.setInterestLifetimeMilliseconds(2000.0);

    if (registeredPrefixId != 0)
      // Save the onInterest callback and send the registration interest.
      registeredPrefixTable_.add
        (new RegisteredPrefix(registeredPrefixId, prefix, onInterest));

    RegisterResponse response = new RegisterResponse
      (new RegisterResponse.Info
       (this, prefix, onInterest, onRegisterFailed, flags, wireFormat, true));
    try {
      expressInterest(commandInterest, response, response, wireFormat);
    }
    catch (IOException ex) {
      // Can't send the interest. Call onRegisterFailed.
      Logger.getLogger(Node.class.getName()).log(Level.INFO,
        "Register prefix failed: Error sending the register prefix interest to the forwarder: {0}", ex);
      onRegisterFailed.onRegisterFailed(prefix);
    }
  }

  private final Transport transport_;
  private final Transport.ConnectionInfo connectionInfo_;
  // Use ArrayList without generics so it works with older Java compilers.
  private final ArrayList pendingInterestTable_ = new ArrayList();  // PendingInterest
  private final ArrayList registeredPrefixTable_ = new ArrayList(); // RegisteredPrefix
  private final Interest ndndIdFetcherInterest_;
  private Blob ndndId_ = new Blob();
  private static final SecureRandom random_ = new SecureRandom();
  private final CommandInterestGenerator commandInterestGenerator_ =
    new CommandInterestGenerator();
  private final Name timeoutPrefix_ = new Name("/local/timeout");
}
