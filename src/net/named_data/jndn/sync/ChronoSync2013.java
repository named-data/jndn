/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * Derived from ChronoChat-js by Qiuhan Ding and Wentao Shang.
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

package net.named_data.jndn.sync;

import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Data;
import net.named_data.jndn.Face;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.OnData;
import net.named_data.jndn.OnInterest;
import net.named_data.jndn.OnRegisterFailed;
import net.named_data.jndn.OnTimeout;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.transport.Transport;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;
import net.named_data.jndn.util.MemoryContentCache;

/**
 * ChronoSync2013 implements the NDN ChronoSync protocol as described in the
 * 2013 paper "Let’s ChronoSync: Decentralized Dataset State Synchronization in
 * Named Data Networking". http://named-data.net/publications/chronosync .
 * @note The support for ChronoSync is experimental and the API is not finalized.
 * See the API docs for more detail at
 * http://named-data.net/doc/ndn-ccl-api/chrono-sync2013.html .
 */
public class ChronoSync2013 implements OnInterest, OnData, OnTimeout {
  // Use a non-template ArrayList so it works with older Java compilers.
  public interface OnReceivedSyncState {
    void onReceivedSyncState(List syncStates /* of SyncState */, boolean isRecovery);
  }

  public interface OnInitialized {
    void onInitialized();
  }

    /**
   * Create a new ChronoSync2013 to communicate using the given face. Initialize
   * the digest log with a digest of "00" and and empty content. Register the
   * applicationBroadcastPrefix to receive interests for sync state messages and
   * express an interest for the initial root digest "00".
   * @note Your application must call processEvents. Since processEvents
   * modifies the internal ChronoSync data structures, your application should
   * make sure that it calls processEvents in the same thread as this
   * constructor (which also modifies the data structures).
   * @param onReceivedSyncState When ChronoSync receives a sync state message,
   * this calls onReceivedSyncState.onReceivedSyncState(syncStates, isRecovery)
   * where syncStates is the
   * list of SyncState messages and isRecovery is true if this is the initial
   * list of SyncState messages or from a recovery interest. (For example, if
   * isRecovery is true, a chat application would not want to re-display all
   * the associated chat messages.) The callback should send interests to fetch
   * the application data for the sequence numbers in the sync state.
   * @param onInitialized This calls onInitialized.onInitialized() when the
   * first sync data is received (or the interest times out because there are no
   * other publishers yet).
   * @param applicationDataPrefix The prefix used by this application instance
   * for application data. For example, "/my/local/prefix/ndnchat4/0K4wChff2v".
   * This is used when sending a sync message for a new sequence number.
   * In the sync message, this uses applicationDataPrefix.toUri().
   * @param applicationBroadcastPrefix The broadcast name prefix including the
   * application name. For example, "/ndn/broadcast/ChronoChat-0.3/ndnchat1".
   * This makes a copy of the name.
   * @param sessionNo The session number used with the applicationDataPrefix in
   * sync state messages.
   * @param face The Face for calling registerPrefix and expressInterest. The
   * Face object must remain valid for the life of this ChronoSync2013 object.
   * @param keyChain To sign a data packet containing a sync state message, this
   * calls keyChain.sign(data, certificateName).
   * @param certificateName The certificate name of the key to use for signing a
   * data packet containing a sync state message.
   * @param syncLifetime The interest lifetime in milliseconds for sending
   * sync interests.
   * @param onRegisterFailed If failed to register the prefix to receive
   * interests for the applicationBroadcastPrefix, this calls
   * onRegisterFailed(applicationBroadcastPrefix).
   */
  public ChronoSync2013
    (OnReceivedSyncState onReceivedSyncState, OnInitialized onInitialized,
     Name applicationDataPrefix, Name applicationBroadcastPrefix, long sessionNo,
     Face face, KeyChain keyChain, Name certificateName, double syncLifetime,
     OnRegisterFailed onRegisterFailed) throws IOException, SecurityException
  {
    onReceivedSyncState_ = onReceivedSyncState;
    onInitialized_ = onInitialized;
    applicationDataPrefixUri_ = applicationDataPrefix.toUri();
    applicationBroadcastPrefix_ = new Name(applicationBroadcastPrefix);
    session_ = sessionNo;
    face_ = face;
    keyChain_ = keyChain;
    certificateName_ = new Name(certificateName);
    sync_lifetime_ = syncLifetime;
    contentCache_ = new MemoryContentCache(face);

    SyncStateProto.SyncStateMsg emptyContent =
      SyncStateProto.SyncStateMsg.newBuilder().build();
    digest_log_.add(new DigestLogEntry("00", emptyContent.getSsList()));

    // Register the prefix with the contentCache_ and use our own onInterest
    //   as the onDataNotFound fallback.
    contentCache_.registerPrefix
      (applicationBroadcastPrefix_, onRegisterFailed, this);

    Interest interest = new Interest(applicationBroadcastPrefix_);
    interest.getName().append("00");
    interest.setInterestLifetimeMilliseconds(1000);
    interest.setAnswerOriginKind(Interest.ANSWER_NO_CONTENT_STORE);
    face.expressInterest(interest, this, this.new InitialTimeout());
    Logger.getLogger(ChronoSync2013.class.getName()).log(Level.FINE,
      "initial sync expressed");
    Logger.getLogger(ChronoSync2013.class.getName()).log(Level.FINE,
      interest.getName().toUri());
  }

  /**
   * A SyncState holds the values of a sync state message which is passed to the
   * onReceivedSyncState callback which was given to the ChronoSyn2013
   * constructor. Note: this has the same info as the Protobuf class
   * SyncStateProto.SyncState, but we make a separate class so that we don't need the
   * Protobuf definition in the ChronoSync API.
   */
  public static class SyncState {
    public SyncState(String dataPrefixUri, long sessionNo, long sequenceNo)
    {
      dataPrefixUri_ = dataPrefixUri;
      sessionNo_ = sessionNo;
      sequenceNo_ = sequenceNo;
    }

    /**
     * Get the application data prefix for this sync state message.
     * @return The application data prefix as a Name URI string.
     */
    public final String
    getDataPrefix() { return dataPrefixUri_; }

    /**
     * Get the session number associated with the application data prefix for
     * this sync state message.
     * @return The session number.
     */
    public final long
    getSessionNo() { return sessionNo_; }

    /**
     * Get the sequence number for this sync state message.
     * @return The sequence number.
     */
    public final long
    getSequenceNo() { return sequenceNo_; }

    private final String dataPrefixUri_;
    private final long sessionNo_;
    private final long sequenceNo_;
  }

  /**
   * Get the current sequence number in the digest tree for the given
   * producer dataPrefix and sessionNo.
   * @param dataPrefix The producer data prefix as a Name URI string.
   * @param sessionNo The producer session number.
   * @return The current producer sequence number, or -1 if the producer
   * namePrefix and sessionNo are not in the digest tree.
   */
  public final long
  getProducerSequenceNo(String dataPrefix, long sessionNo)
  {
    int index = digest_tree_.find(dataPrefix, sessionNo);
    if (index < 0)
      return -1;
    else
      return digest_tree_.get(index).getSequenceNo();
  }

  /**
   * Increment the sequence number, create a sync message with the new
   * sequence number and publish a data packet where the name is
   * the applicationBroadcastPrefix + the root digest of the current digest
   * tree. Then add the sync message to the digest tree and digest log which
   * creates a new root digest. Finally, express an interest for the next sync
   * update with the name applicationBroadcastPrefix + the new root digest.
   * After this, your application should publish the content for the new
   * sequence number. You can get the new sequence number with getSequenceNo().
   * @note Your application must call processEvents. Since processEvents
   * modifies the internal ChronoSync data structures, your application should
   * make sure that it calls processEvents in the same thread as
   * publishNextSequenceNo() (which also modifies the data structures).
   */
  public final void
  publishNextSequenceNo() throws IOException, SecurityException
  {
    ++usrseq_;

    SyncStateProto.SyncStateMsg.Builder builder =
      SyncStateProto.SyncStateMsg.newBuilder();
    builder.addSsBuilder()
      .setName(applicationDataPrefixUri_)
      .setType(SyncStateProto.SyncState.ActionType.UPDATE)
      .getSeqnoBuilder().setSeq(usrseq_)
                        .setSession(session_);
    SyncStateProto.SyncStateMsg syncMessage = builder.build();
    
    broadcastSyncState(digest_tree_.getRoot(), syncMessage);

    if (!update(syncMessage.getSsList()))
      // Since we incremented the sequence number, we expect there to be a
      //   new digest log entry.
      throw new Error
        ("ChronoSync: update did not create a new digest log entry");

    // TODO: Should we have an option to not express an interest if this is the
    //   final publish of the session?
    Interest interest = new Interest(applicationBroadcastPrefix_);
    interest.getName().append(digest_tree_.getRoot());
    interest.setInterestLifetimeMilliseconds(sync_lifetime_);
    face_.expressInterest(interest, this, this);
  }

  /**
   * Get the sequence number of the latest data published by this application
   * instance.
   * @return The sequence number.
   */
  public final long
  getSequenceNo() { return usrseq_; }

  private static class DigestLogEntry {
    public DigestLogEntry(String digest, List data)
    {
      digest_ = digest;
      // Copy.
      data_ = new ArrayList(data);
    }

    public final String
    getDigest() { return digest_; }

    /**
     * Get the data.
     * @return The data as a list of SyncStateProto.SyncState.
     */
    List // of SyncStateProto.SyncState
    getData() { return data_; }

    private final String digest_;
    // Use a non-template ArrayList so it works with older Java compilers.
    List data_; // of SyncStateProto.SyncState
  }

  /**
   * Unregister callbacks so that this does not respond to interests anymore.
   * If you will discard this ChronoSync2013 object while your application is
   * still running, you should call shutdown() first.  After calling this, you
   * should not call publishNextSequenceNo() again since the behavior will be
   * undefined.
   * @note Because this modifies internal ChronoSync data structures, your
   * application should make sure that it calls processEvents in the same
   * thread as shutdown() (which also modifies the data structures).
   */
  public final void
  shutdown()
  {
    enabled_ = false;
    contentCache_.unregisterAll();
  }

  /**
   * A PendingInterest holds an interest which onInterest received but could
   * not satisfy. When we add a new data packet to the contentCache_, we will
   * also check if it satisfies a pending interest.
   */
  private static class PendingInterest {
    /**
     * Create a new PendingInterest and set the timeoutTime_ based on the current
     * time and the interest lifetime.
     * @param interest The interest.
     * @param transport The transport from the onInterest callback. If the
     * interest is satisfied later by a new data packet, we will send the data
     * packet to the transport.
     */
    public PendingInterest(Interest interest, Transport transport)
    {
      interest_ = interest;
      transport_ = transport;

      // Set up timeoutTime_.
      if (interest_.getInterestLifetimeMilliseconds() >= 0.0)
        timeoutTimeMilliseconds_ = Common.getNowMilliseconds() +
          interest_.getInterestLifetimeMilliseconds();
      else
        // No timeout.
        timeoutTimeMilliseconds_ = -1.0;
    }

    /**
     * Return the interest given to the constructor.
     */
    public final Interest
    getInterest() { return interest_; }

    /**
     * Return the transport given to the constructor.
     */
    public final Transport
    getTransport() { return transport_; }

    /**
     * Check if this interest is timed out.
     * @param nowMilliseconds The current time in milliseconds from Common.getNowMilliseconds.
     * @return true if this interest timed out, otherwise false.
     */
    public final boolean
    isTimedOut(double nowMilliseconds)
    {
      return timeoutTimeMilliseconds_ >= 0.0 && nowMilliseconds >= timeoutTimeMilliseconds_;
    }

    private final Interest interest_;
    private final Transport transport_;
    private final double timeoutTimeMilliseconds_; /**< The time when the
      * interest times out in milliseconds according to ndn_getNowMilliseconds,
      * or -1 for no timeout. */
  }

  /**
   * Make a data packet with the syncMessage and with name
   * applicationBroadcastPrefix_ + digest. Sign and send.
   * @param digest The root digest as a hex string for the data packet name.
   * @param syncMessage The SyncStateMsg which updates the digest tree state
   * with the given digest.
   */
  private void
  broadcastSyncState(String digest, SyncStateProto.SyncStateMsg syncMessage)
    throws SecurityException
  {
    Data data = new Data(applicationBroadcastPrefix_);
    data.getName().append(digest);
    data.setContent(new Blob(syncMessage.toByteArray()));
    keyChain_.sign(data, certificateName_);
    contentCacheAdd(data);
  }

  /**
   * Update the digest tree with the messages in content. If the digest tree
   * root is not in the digest log, also add a log entry with the content.
   * @param content The list of SyncStateProto.SyncState.
   * @return True if added a digest log entry (because the updated digest
   * tree root was not in the log), false if didn't add a log entry.
   */
  private boolean
  update(List content)
  {
    for (int i = 0; i < content.size(); ++i) {
      SyncStateProto.SyncState syncState = (SyncStateProto.SyncState)content.get(i);

      if (syncState.getType().equals
           (SyncStateProto.SyncState.ActionType.UPDATE)) {
        if (digest_tree_.update
            (syncState.getName(), syncState.getSeqno().getSession(),
             syncState.getSeqno().getSeq())) {
          // The digest tree was updated.
          if (applicationDataPrefixUri_.equals(syncState.getName()))
            usrseq_ = syncState.getSeqno().getSeq();
        }
      }
    }

    if (logfind(digest_tree_.getRoot()) == -1) {
      digest_log_.add(new DigestLogEntry(digest_tree_.getRoot(), content));
      return true;
    }
    else
      return false;
  }

  // Search the digest log by digest.
  private int
  logfind(String digest)
  {
    for (int i = 0; i < digest_log_.size(); ++i) {
      if (digest.equals(((DigestLogEntry)digest_log_.get(i)).getDigest()))
        return i;
    }

    return -1;
  }

  /**
   * Process the sync interest from the applicationBroadcastPrefix. If we can't
   * satisfy the interest, add it to the pendingInterestTable_ so that a
   * future call to contentCacheAdd may satisfy it.
   * (Do not call this. It is only public to implement the interface.)
   */
  public final void
  onInterest
    (Name prefix, Interest inst, Transport transport, long registerPrefixId)
  {
    if (!enabled_)
      // Ignore callbacks after the application calls shutdown().
      return;

    // Search if the digest already exists in the digest log.
    Logger.getLogger(ChronoSync2013.class.getName()).log(Level.FINE,
      "Sync Interest received in callback.");
    Logger.getLogger(ChronoSync2013.class.getName()).log(Level.FINE,
      inst.getName().toUri());

    String syncdigest = inst.getName().get
      (applicationBroadcastPrefix_.size()).toEscapedString();
    if (inst.getName().size() == applicationBroadcastPrefix_.size() + 2)
      // Assume this is a recovery interest.
      syncdigest = inst.getName().get
        (applicationBroadcastPrefix_.size() + 1).toEscapedString();
    Logger.getLogger(ChronoSync2013.class.getName()).log(Level.FINE, 
      "syncdigest: {0}", syncdigest);
    if (inst.getName().size() == applicationBroadcastPrefix_.size() + 2 ||
        syncdigest.equals("00"))
      // Recovery interest or newcomer interest.
      processRecoveryInst(inst, syncdigest, transport);
    else {
      // Save the unanswered interest in our local pending interest table.
      pendingInterestTable_.add(new PendingInterest(inst, transport));

      if (!syncdigest.equals(digest_tree_.getRoot())) {
        int index = logfind(syncdigest);
        if (index == -1) {
          // To see whether there is any data packet coming back, wait 2 seconds
          // using the Interest timeout mechanism.
          // TODO: Are we sure using a "/local/timeout" interest is the best future call approach?
          Interest timeout = new Interest(new Name("/local/timeout"));
          timeout.setInterestLifetimeMilliseconds(2000);
          try {
            face_.expressInterest
              (timeout, DummyOnData.onData_,
               this.new JudgeRecovery(syncdigest, transport));
          } catch (IOException ex) {
            Logger.getLogger(ChronoSync2013.class.getName()).log(Level.SEVERE, null, ex);
            return;
          }
          Logger.getLogger(ChronoSync2013.class.getName()).log(Level.FINE,
            "set timer recover");
        }
        else {
          try {
            // common interest processing
            processSyncInst(index, syncdigest, transport);
          } catch (SecurityException ex) {
            Logger.getLogger(ChronoSync2013.class.getName()).log(Level.SEVERE, null, ex);
          }
        }
      }
    }
  }

  // Process Sync Data.
  // (Do not call this. It is only public to implement the interface.)
  public final void
  onData(Interest inst, Data co)
  {
    if (!enabled_)
      // Ignore callbacks after the application calls shutdown().
      return;

    Logger.getLogger(ChronoSync2013.class.getName()).log(Level.FINE,
      "Sync ContentObject received in callback");
    Logger.getLogger(ChronoSync2013.class.getName()).log(Level.FINE,
      "name: {0}", co.getName().toUri());
    SyncStateProto.SyncStateMsg content_t;
    try {
      content_t = SyncStateProto.SyncStateMsg.parseFrom(co.getContent().getImmutableArray());
    } catch (InvalidProtocolBufferException ex) {
      Logger.getLogger(ChronoSync2013.class.getName()).log(Level.SEVERE, null, ex);
      return;
    }
    List content = content_t.getSsList();
    boolean isRecovery;
    if (digest_tree_.getRoot().equals("00")) {
      isRecovery = true;
      try {
        //processing initial sync data
        initialOndata(content);
      } catch (SecurityException ex) {
        Logger.getLogger(ChronoSync2013.class.getName()).log(Level.SEVERE, null, ex);
        return;
      }
    }
    else {
      update(content);
      if (inst.getName().size() == applicationBroadcastPrefix_.size() + 2)
        // Assume this is a recovery interest.
        isRecovery = true;
      else
        isRecovery = false;
    }

    // Send the interests to fetch the application data.
    ArrayList syncStates = new ArrayList();
    for (int i = 0; i < content.size(); ++i) {
      SyncStateProto.SyncState syncState = (SyncStateProto.SyncState)content.get(i);

      // Only report UPDATE sync states.
      if (syncState.getType().equals
           (SyncStateProto.SyncState.ActionType.UPDATE))
        syncStates.add(new SyncState
          (syncState.getName(), syncState.getSeqno().getSession(),
           syncState.getSeqno().getSeq()));
    }
    onReceivedSyncState_.onReceivedSyncState(syncStates, isRecovery);

    Name n = new Name(applicationBroadcastPrefix_);
    n.append(digest_tree_.getRoot());
    Interest interest = new Interest(n);
    interest.setInterestLifetimeMilliseconds(sync_lifetime_);
    try {
      face_.expressInterest(interest, this, this);
    } catch (IOException ex) {
      Logger.getLogger(ChronoSync2013.class.getName()).log(Level.SEVERE, null, ex);
      return;
    }
    Logger.getLogger(ChronoSync2013.class.getName()).log(Level.FINE,
      "Syncinterest expressed:");
    Logger.getLogger(ChronoSync2013.class.getName()).log(Level.FINE,
      n.toUri());
  }

  // Initial sync interest timeout, which means there are no other publishers yet.
  // We make this an inner class because onTimeout is already used for syncTimeout.
  private class InitialTimeout implements OnTimeout {
    public final void
    onTimeout(Interest interest)
    {
      if (!enabled_)
        // Ignore callbacks after the application calls shutdown().
        return;

      Logger.getLogger(ChronoSync2013.class.getName()).log(Level.FINE,
        "initial sync timeout");
      Logger.getLogger(ChronoSync2013.class.getName()).log(Level.FINE,
        "no other people");
      ++usrseq_;
      if (usrseq_ != 0)
        // Since there were no other users, we expect sequence no 0.
        throw new Error
          ("ChronoSync: usrseq_ is not the expected value of 0 for first use.");

      SyncStateProto.SyncStateMsg.Builder builder =
        SyncStateProto.SyncStateMsg.newBuilder();
      builder.addSsBuilder()
        .setName(applicationDataPrefixUri_)
        .setType(SyncStateProto.SyncState.ActionType.UPDATE)
        .getSeqnoBuilder().setSeq(usrseq_)
                          .setSession(session_);
      SyncStateProto.SyncStateMsg content_t = builder.build();
      update(content_t.getSsList());

      onInitialized_.onInitialized();

      Name n = new Name(applicationBroadcastPrefix_);
      n.append(digest_tree_.getRoot());
      Interest retryInterest = new Interest(n);
      retryInterest.setInterestLifetimeMilliseconds(sync_lifetime_);
      try {
        face_.expressInterest(retryInterest, ChronoSync2013.this, ChronoSync2013.this);
      } catch (IOException ex) {
        Logger.getLogger(ChronoSync2013.class.getName()).log(Level.SEVERE, null, ex);
        return;
      }
      Logger.getLogger(ChronoSync2013.class.getName()).log(Level.FINE,
        "Syncinterest expressed:");
      Logger.getLogger(ChronoSync2013.class.getName()).log(Level.FINE,
        n.toUri());
    }
  }

  private void
  processRecoveryInst(Interest inst, String syncdigest, Transport transport)
  {
    Logger.getLogger(ChronoSync2013.class.getName()).log(Level.FINE,
      "processRecoveryInst");
    if (logfind(syncdigest) != -1) {
      SyncStateProto.SyncStateMsg.Builder builder =
        SyncStateProto.SyncStateMsg.newBuilder();
      for (int i = 0; i < digest_tree_.size(); ++i) {
        builder.addSsBuilder()
          .setName(digest_tree_.get(i).getDataPrefix())
          .setType(SyncStateProto.SyncState.ActionType.UPDATE)
          .getSeqnoBuilder().setSeq(digest_tree_.get(i).getSequenceNo())
                            .setSession(digest_tree_.get(i).getSessionNo());
      }
      SyncStateProto.SyncStateMsg content_t = builder.build();

      if (content_t.getSsCount() != 0) {
        byte[] array = content_t.toByteArray();
        Data co = new Data(inst.getName());
        co.setContent(new Blob(array));
        try {
          keyChain_.sign(co, certificateName_);
        } catch (SecurityException ex) {
          Logger.getLogger(ChronoSync2013.class.getName()).log(Level.SEVERE, null, ex);
          return;
        }
        try {
          transport.send(co.wireEncode().buf());
        } catch (IOException ex) {
          Logger.getLogger(ChronoSync2013.class.getName()).log(Level.SEVERE,
            ex.getMessage());
          return;
        }
        Logger.getLogger(ChronoSync2013.class.getName()).log(Level.FINE,
          "send recovery data back");
        Logger.getLogger(ChronoSync2013.class.getName()).log(Level.FINE,
          inst.getName().toUri());
      }
    }
  }

  /**
   * Common interest processing, using digest log to find the difference after
   * syncdigest_t. Return true if sent a data packet to satisfy the interest,
   * otherwise false.
   */
  private boolean
  processSyncInst(int index, String syncdigest_t, Transport transport) throws SecurityException
  {
    ArrayList data_name = new ArrayList(); // of String
    ArrayList data_seq = new ArrayList();  // of long
    ArrayList data_session = new ArrayList(); // of long
    for (int j = index + 1; j < digest_log_.size(); ++j) {
      List temp = ((DigestLogEntry)digest_log_.get(j)).getData(); // of SyncStateProto.SyncState.
      for (int i = 0; i < temp.size(); ++i) {
        SyncStateProto.SyncState syncState = (SyncStateProto.SyncState)temp.get(i);
        if (!syncState.getType().equals
             (SyncStateProto.SyncState.ActionType.UPDATE))
          continue;

        if (digest_tree_.find
            (syncState.getName(), syncState.getSeqno().getSession()) != -1) {
          int n = -1;
          for (int k = 0; k < data_name.size(); ++k) {
            if (((String)data_name.get(k)).equals(syncState.getName())) {
              n = k;
              break;
            }
          }
          if (n == -1) {
            data_name.add(syncState.getName());
            data_seq.add(syncState.getSeqno().getSeq());
            data_session.add(syncState.getSeqno().getSession());
          }
          else {
            data_seq.set(n, syncState.getSeqno().getSeq());
            data_session.set(n, syncState.getSeqno().getSession());
          }
        }
      }
    }

    SyncStateProto.SyncStateMsg.Builder builder =
      SyncStateProto.SyncStateMsg.newBuilder();
    for (int i = 0; i < data_name.size(); ++i) {
      builder.addSsBuilder()
        .setName((String)data_name.get(i))
        .setType(SyncStateProto.SyncState.ActionType.UPDATE)
        .getSeqnoBuilder().setSeq((long)data_seq.get(i))
                          .setSession((long)data_session.get(i));
    }
    SyncStateProto.SyncStateMsg content_t = builder.build();

    boolean sent = false;
    if (content_t.getSsCount() != 0) {
      Name n = new Name(applicationBroadcastPrefix_);
      n.append(syncdigest_t);
      byte[] array = content_t.toByteArray();
      Data co = new Data(n);
      co.setContent(new Blob(array));
      keyChain_.sign(co, certificateName_);

      try {
        transport.send(co.wireEncode().buf());
      } catch (IOException ex) {
        Logger.getLogger(ChronoSync2013.class.getName()).log(Level.SEVERE,
          ex.getMessage());
        return false;
      }

      sent = true;
      Logger.getLogger(ChronoSync2013.class.getName()).log(Level.FINE,
        "Sync Data send");
      Logger.getLogger(ChronoSync2013.class.getName()).log(Level.FINE,
        n.toUri());
    }

    return sent;
  }

  // Send Recovery Interest.
  private void
  sendRecovery(String syncdigest_t) throws IOException
  {
    Logger.getLogger(ChronoSync2013.class.getName()).log(Level.FINE,
      "unknown digest: ");
    Name n = new Name(applicationBroadcastPrefix_);
    n.append("recovery").append(syncdigest_t);
    Interest interest = new Interest(n);
    interest.setInterestLifetimeMilliseconds(sync_lifetime_);
    face_.expressInterest(interest, this, this);
    Logger.getLogger(ChronoSync2013.class.getName()).log(Level.FINE,
      "Recovery Syncinterest expressed:");
    Logger.getLogger(ChronoSync2013.class.getName()).log(Level.FINE,
      n.toUri());
  }

  // This is called by onInterest after a timeout to check if a recovery is needed.
  // We make this an inner class because onTimeout is already used for syncTimeout.
  private class JudgeRecovery implements OnTimeout {
    public JudgeRecovery(String syncdigest_t, Transport transport)
    {
      syncdigest_t_ = syncdigest_t;
      transport_ = transport;
    }

    public final void
    onTimeout(Interest interest)
    {
      if (!enabled_)
        // Ignore callbacks after the application calls shutdown().
        return;

      int index2 = logfind(syncdigest_t_);
      if (index2 != -1) {
        if (!syncdigest_t_.equals(digest_tree_.getRoot()))
          try {
            processSyncInst(index2, syncdigest_t_, transport_);
        } catch (SecurityException ex) {
          Logger.getLogger(ChronoSync2013.class.getName()).log(Level.SEVERE, null, ex);
          return;
        }
      }
      else {
        try {
          sendRecovery(syncdigest_t_);
        } catch (IOException ex) {
          Logger.getLogger(ChronoSync2013.class.getName()).log(Level.SEVERE, null, ex);
          return;
        }
      }
    }

    private final String syncdigest_t_;
    private final Transport transport_;
  }

  // Sync interest time out, if the interest is the static one send again.
  // This is called "syncTimeout" in NDN-CPP, etc. but here it is "onTimeout"
  // so that we can make ChronoSync2013 implement OnTimeout.
  // (Do not call this. It is only public to implement the interface.)
  public void
  onTimeout(Interest interest)
  {
    if (!enabled_)
      // Ignore callbacks after the application calls shutdown().
      return;

    Logger.getLogger(ChronoSync2013.class.getName()).log(Level.FINE,
      "Sync Interest time out.");
    Logger.getLogger(ChronoSync2013.class.getName()).log(Level.FINE,
      "Sync Interest name: {0}", interest.getName().toUri());
    String component = interest.getName().get(4).toEscapedString();
    if (component.equals(digest_tree_.getRoot())) {
      Name n = new Name(interest.getName());
      Interest retryInterest = new Interest(interest.getName());
      retryInterest.setInterestLifetimeMilliseconds(sync_lifetime_);
       try {
         face_.expressInterest(retryInterest, this, this);
       } catch (IOException ex) {
         Logger.getLogger(ChronoSync2013.class.getName()).log(Level.SEVERE, null, ex);
         return;
       }
      Logger.getLogger(ChronoSync2013.class.getName()).log(Level.FINE,
        "Syncinterest expressed:");
      Logger.getLogger(ChronoSync2013.class.getName()).log(Level.FINE,
       n.toUri());
    }
  }

  // Process initial data which usually includes all other publisher's info, and
  // send back the new comer's own info.
  private void
  initialOndata(List content) throws SecurityException
  {
    // The user is a new comer and receive data of all other people in the group.
    update(content);
    String digest_t = digest_tree_.getRoot();
    for (int i = 0; i < content.size(); ++i) {
      SyncStateProto.SyncState syncState =
        (SyncStateProto.SyncState)content.get(i);
      if (syncState.getName().equals(applicationDataPrefixUri_) &&
          syncState.getSeqno().getSession() == session_) {
        // If the user was an old comer, after add the static log he needs to
        // increase his seqno by 1.
        SyncStateProto.SyncStateMsg.Builder builder =
          SyncStateProto.SyncStateMsg.newBuilder();
        builder.addSsBuilder()
          .setName(applicationDataPrefixUri_)
          .setType(SyncStateProto.SyncState.ActionType.UPDATE)
          .getSeqnoBuilder().setSeq(syncState.getSeqno().getSeq() + 1)
                            .setSession(session_);
        SyncStateProto.SyncStateMsg content_t = builder.build();

        if (update(content_t.getSsList()))
          onInitialized_.onInitialized();
      }
    }

    SyncStateProto.SyncStateMsg content2_t;
    if (usrseq_ >= 0) {
      // Send the data packet with the new seqno back.
      SyncStateProto.SyncStateMsg.Builder builder =
        SyncStateProto.SyncStateMsg.newBuilder();
      builder.addSsBuilder()
        .setName(applicationDataPrefixUri_)
        .setType(SyncStateProto.SyncState.ActionType.UPDATE)
        .getSeqnoBuilder().setSeq(usrseq_)
                          .setSession(session_);
      content2_t = builder.build();
    }
    else {
      SyncStateProto.SyncStateMsg.Builder builder =
        SyncStateProto.SyncStateMsg.newBuilder();
      builder.addSsBuilder()
        .setName(applicationDataPrefixUri_)
        .setType(SyncStateProto.SyncState.ActionType.UPDATE)
        .getSeqnoBuilder().setSeq(0)
                          .setSession(session_);
      content2_t = builder.build();
    }

    broadcastSyncState(digest_t, content2_t);

    if (digest_tree_.find(applicationDataPrefixUri_, session_) == -1) {
      // the user hasn't put himself in the digest tree.
      Logger.getLogger(ChronoSync2013.class.getName()).log(Level.FINE,
        "initial state");
      ++usrseq_;
      SyncStateProto.SyncStateMsg.Builder builder =
        SyncStateProto.SyncStateMsg.newBuilder();
      builder.addSsBuilder()
        .setName(applicationDataPrefixUri_)
        .setType(SyncStateProto.SyncState.ActionType.UPDATE)
        .getSeqnoBuilder().setSeq(usrseq_)
                          .setSession(session_);
      SyncStateProto.SyncStateMsg content_t = builder.build();

      if (update(content_t.getSsList()))
        onInitialized_.onInitialized();
    }
  }

  /**
   * Add the data packet to the contentCache_. Remove timed-out entries
   * from pendingInterestTable_. If the data packet satisfies any pending
   * interest, then send the data packet to the pending interest's transport
   * and remove from the pendingInterestTable_.
   * @param data
   */
  private void
  contentCacheAdd(Data data)
  {
    contentCache_.add(data);

    // Remove timed-out interests and check if the data packet matches any pending
    // interest.
    // Go backwards through the list so we can erase entries.
    double nowMilliseconds = Common.getNowMilliseconds();
    for (int i = pendingInterestTable_.size() - 1; i >= 0; --i) {
      PendingInterest pendingInterest =
        (PendingInterest)pendingInterestTable_.get(i);
      if (pendingInterest.isTimedOut(nowMilliseconds)) {
        pendingInterestTable_.remove(i);
        continue;
      }

      if (pendingInterest.getInterest().matchesName(data.getName())) {
        try {
          // Send to the same transport from the original call to onInterest.
          // wireEncode returns the cached encoding if available.
          pendingInterest.getTransport().send(data.wireEncode().buf());
        } catch (IOException ex) {
          Logger.getLogger(ChronoSync2013.class.getName()).log(Level.SEVERE,
            ex.getMessage());
          return;
        }

        // The pending interest is satisfied, so remove it.
        pendingInterestTable_.remove(i);
      }
    }
  }

  // This is a do-nothing onData for using expressInterest for timeouts.
  // This should never be called.
  private static class DummyOnData implements OnData {
    public final void
    onData(Interest interest, Data data) {}

    public final static OnData onData_ = new DummyOnData();
  }

  Face face_;
  KeyChain keyChain_;
  Name certificateName_;
  double sync_lifetime_;
  OnReceivedSyncState onReceivedSyncState_;
  OnInitialized onInitialized_;
  // Use a non-template ArrayList so it works with older Java compilers.
  ArrayList digest_log_ = new ArrayList(); // of DigestLogEntry
  DigestTree digest_tree_ = new DigestTree();
  String applicationDataPrefixUri_;
  Name applicationBroadcastPrefix_;
  long session_;
  long usrseq_ = -1;
  MemoryContentCache contentCache_;
  ArrayList pendingInterestTable_ = new ArrayList(); // of PendingInterest
  boolean enabled_ = true;
}
