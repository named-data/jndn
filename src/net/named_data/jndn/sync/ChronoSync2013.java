/**
 * Copyright (C) 2014-2016 Regents of the University of California.
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
import net.named_data.jndn.InterestFilter;
import net.named_data.jndn.Name;
import net.named_data.jndn.OnData;
import net.named_data.jndn.OnInterestCallback;
import net.named_data.jndn.OnRegisterFailed;
import net.named_data.jndn.OnTimeout;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.MemoryContentCache;

/**
 * ChronoSync2013 implements the NDN ChronoSync protocol as described in the
 * 2013 paper "Let's ChronoSync: Decentralized Dataset State Synchronization in
 * Named Data Networking". http://named-data.net/publications/chronosync .
 * @note The support for ChronoSync is experimental and the API is not finalized.
 * See the API docs for more detail at
 * http://named-data.net/doc/ndn-ccl-api/chrono-sync2013.html .
 */
public class ChronoSync2013 implements OnInterestCallback, OnData, OnTimeout {
  // Use ArrayList without generics so it works with older Java compilers.
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
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onInitialized This calls onInitialized.onInitialized() when the
   * first sync data is received (or the interest times out because there are no
   * other publishers yet).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
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
   * onRegisterFailed.onRegisterFailed(applicationBroadcastPrefix).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
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
    sessionNo_ = sessionNo;
    face_ = face;
    keyChain_ = keyChain;
    certificateName_ = new Name(certificateName);
    syncLifetime_ = syncLifetime;
    contentCache_ = new MemoryContentCache(face);

    SyncStateProto.SyncStateMsg emptyContent =
      SyncStateProto.SyncStateMsg.newBuilder().build();
    digestLog_.add(new DigestLogEntry("00", emptyContent.getSsList()));

    // Register the prefix with the contentCache_ and use our own onInterest
    //   as the onDataNotFound fallback.
    contentCache_.registerPrefix
      (applicationBroadcastPrefix_, onRegisterFailed, this);

    Interest interest = new Interest(applicationBroadcastPrefix_);
    interest.getName().append("00");
    interest.setInterestLifetimeMilliseconds(1000);
    face.expressInterest(interest, this, this.new InitialTimeout());
    logger_.log(Level.FINE, "initial sync expressed");
    logger_.log(Level.FINE, interest.getName().toUri());
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
    int index = digestTree_.find(dataPrefix, sessionNo);
    if (index < 0)
      return -1;
    else
      return digestTree_.get(index).getSequenceNo();
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
    ++sequenceNo_;

    SyncStateProto.SyncStateMsg.Builder builder =
      SyncStateProto.SyncStateMsg.newBuilder();
    builder.addSsBuilder()
      .setName(applicationDataPrefixUri_)
      .setType(SyncStateProto.SyncState.ActionType.UPDATE)
      .getSeqnoBuilder().setSeq(sequenceNo_)
                        .setSession(sessionNo_);
    SyncStateProto.SyncStateMsg syncMessage = builder.build();

    broadcastSyncState(digestTree_.getRoot(), syncMessage);

    if (!update(syncMessage.getSsList()))
      // Since we incremented the sequence number, we expect there to be a
      //   new digest log entry.
      throw new Error
        ("ChronoSync: update did not create a new digest log entry");

    // TODO: Should we have an option to not express an interest if this is the
    //   final publish of the session?
    Interest interest = new Interest(applicationBroadcastPrefix_);
    interest.getName().append(digestTree_.getRoot());
    interest.setInterestLifetimeMilliseconds(syncLifetime_);
    face_.expressInterest(interest, this, this);
  }

  /**
   * Get the sequence number of the latest data published by this application
   * instance.
   * @return The sequence number.
   */
  public final long
  getSequenceNo() { return sequenceNo_; }

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
  // Use List without generics so it works with older Java compilers.
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
    data.setContent(new Blob(syncMessage.toByteArray(), false));
    keyChain_.sign(data, certificateName_);
    contentCache_.add(data);
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
        if (digestTree_.update
            (syncState.getName(), syncState.getSeqno().getSession(),
             syncState.getSeqno().getSeq())) {
          // The digest tree was updated.
          if (applicationDataPrefixUri_.equals(syncState.getName()))
            sequenceNo_ = syncState.getSeqno().getSeq();
        }
      }
    }

    if (logFind(digestTree_.getRoot()) == -1) {
      digestLog_.add(new DigestLogEntry(digestTree_.getRoot(), content));
      return true;
    }
    else
      return false;
  }

  // Search the digest log by digest.
  private int
  logFind(String digest)
  {
    for (int i = 0; i < digestLog_.size(); ++i) {
      if (digest.equals(((DigestLogEntry)digestLog_.get(i)).getDigest()))
        return i;
    }

    return -1;
  }

  /**
   * Process the sync interest from the applicationBroadcastPrefix. If we can't
   * satisfy the interest, add it to the pending interest table in the
   * contentCache_ so that a future call to add may satisfy it.
   * (Do not call this. It is only public to implement the interface.)
   */
  public final void
  onInterest
    (Name prefix, Interest interest, Face face, long interestFilterId,
     InterestFilter filter)
  {
    if (!enabled_)
      // Ignore callbacks after the application calls shutdown().
      return;

    // Search if the digest already exists in the digest log.
    logger_.log(Level.FINE, "Sync Interest received in callback.");
    logger_.log(Level.FINE, interest.getName().toUri());

    String syncDigest = interest.getName().get
      (applicationBroadcastPrefix_.size()).toEscapedString();
    if (interest.getName().size() == applicationBroadcastPrefix_.size() + 2)
      // Assume this is a recovery interest.
      syncDigest = interest.getName().get
        (applicationBroadcastPrefix_.size() + 1).toEscapedString();
    logger_.log(Level.FINE, "syncDigest: {0}", syncDigest);
    if (interest.getName().size() == applicationBroadcastPrefix_.size() + 2 ||
        syncDigest.equals("00"))
      // Recovery interest or newcomer interest.
      processRecoveryInterest(interest, syncDigest, face);
    else {
      contentCache_.storePendingInterest(interest, face);

      if (!syncDigest.equals(digestTree_.getRoot())) {
        int index = logFind(syncDigest);
        if (index == -1) {
          // To see whether there is any data packet coming back, wait 2 seconds
          // using the Interest timeout mechanism.
          // TODO: Are we sure using a "/local/timeout" interest is the best future call approach?
          Interest timeout = new Interest(new Name("/local/timeout"));
          timeout.setInterestLifetimeMilliseconds(2000);
          try {
            face_.expressInterest
              (timeout, DummyOnData.onData_,
               this.new JudgeRecovery(syncDigest, face));
          } catch (IOException ex) {
            logger_.log(Level.SEVERE, null, ex);
            return;
          }
          logger_.log(Level.FINE, "set timer recover");
        }
        else {
          try {
            // common interest processing
            processSyncInterest(index, syncDigest, face);
          } catch (SecurityException ex) {
            logger_.log(Level.SEVERE, null, ex);
          }
        }
      }
    }
  }

  // Process Sync Data.
  // (Do not call this. It is only public to implement the interface.)
  public final void
  onData(Interest interest, Data data)
  {
    if (!enabled_)
      // Ignore callbacks after the application calls shutdown().
      return;

    logger_.log(Level.FINE, "Sync ContentObject received in callback");
    logger_.log(Level.FINE, "name: {0}", data.getName().toUri());
    SyncStateProto.SyncStateMsg tempContent;
    try {
      tempContent = SyncStateProto.SyncStateMsg.parseFrom(data.getContent().getImmutableArray());
    } catch (InvalidProtocolBufferException ex) {
      logger_.log(Level.SEVERE, null, ex);
      return;
    }
    List content = tempContent.getSsList();
    boolean isRecovery;
    if (digestTree_.getRoot().equals("00")) {
      isRecovery = true;
      try {
        //processing initial sync data
        initialOndata(content);
      } catch (SecurityException ex) {
        logger_.log(Level.SEVERE, null, ex);
        return;
      }
    }
    else {
      update(content);
      if (interest.getName().size() == applicationBroadcastPrefix_.size() + 2)
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
    try {
      onReceivedSyncState_.onReceivedSyncState(syncStates, isRecovery);
    } catch (Throwable ex) {
      logger_.log(Level.SEVERE, "Error in onReceivedSyncState", ex);
    }

    Name name = new Name(applicationBroadcastPrefix_);
    name.append(digestTree_.getRoot());
    Interest syncInterest = new Interest(name);
    syncInterest.setInterestLifetimeMilliseconds(syncLifetime_);
    try {
      face_.expressInterest(syncInterest, this, this);
    } catch (IOException ex) {
      logger_.log(Level.SEVERE, null, ex);
      return;
    }
    logger_.log(Level.FINE, "Syncinterest expressed:");
    logger_.log(Level.FINE, name.toUri());
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

      logger_.log(Level.FINE, "initial sync timeout");
      logger_.log(Level.FINE, "no other people");
      ++sequenceNo_;
      if (sequenceNo_ != 0)
        // Since there were no other users, we expect sequence no 0.
        throw new Error
          ("ChronoSync: sequenceNo_ is not the expected value of 0 for first use.");

      SyncStateProto.SyncStateMsg.Builder builder =
        SyncStateProto.SyncStateMsg.newBuilder();
      builder.addSsBuilder()
        .setName(applicationDataPrefixUri_)
        .setType(SyncStateProto.SyncState.ActionType.UPDATE)
        .getSeqnoBuilder().setSeq(sequenceNo_)
                          .setSession(sessionNo_);
      SyncStateProto.SyncStateMsg tempContent = builder.build();
      update(tempContent.getSsList());

      try {
        onInitialized_.onInitialized();
      } catch (Throwable ex) {
        logger_.log(Level.SEVERE, null, ex);
      }

      Name name = new Name(applicationBroadcastPrefix_);
      name.append(digestTree_.getRoot());
      Interest retryInterest = new Interest(name);
      retryInterest.setInterestLifetimeMilliseconds(syncLifetime_);
      try {
        face_.expressInterest(retryInterest, ChronoSync2013.this, ChronoSync2013.this);
      } catch (IOException ex) {
        logger_.log(Level.SEVERE, null, ex);
        return;
      }
      logger_.log(Level.FINE, "Syncinterest expressed:");
      logger_.log(Level.FINE, name.toUri());
    }
  }

  private void
  processRecoveryInterest(Interest interest, String syncDigest, Face face)
  {
    logger_.log(Level.FINE, "processRecoveryInterest");
    if (logFind(syncDigest) != -1) {
      SyncStateProto.SyncStateMsg.Builder builder =
        SyncStateProto.SyncStateMsg.newBuilder();
      for (int i = 0; i < digestTree_.size(); ++i) {
        builder.addSsBuilder()
          .setName(digestTree_.get(i).getDataPrefix())
          .setType(SyncStateProto.SyncState.ActionType.UPDATE)
          .getSeqnoBuilder().setSeq(digestTree_.get(i).getSequenceNo())
                            .setSession(digestTree_.get(i).getSessionNo());
      }
      SyncStateProto.SyncStateMsg tempContent = builder.build();

      if (tempContent.getSsCount() != 0) {
        byte[] array = tempContent.toByteArray();
        Data data = new Data(interest.getName());
        data.setContent(new Blob(array, false));
        if (interest.getName().get(-1).toEscapedString().equals("00"))
          // Limit the lifetime of replies to interest for "00" since they can be different.
          data.getMetaInfo().setFreshnessPeriod(1000);

        try {
          keyChain_.sign(data, certificateName_);
        } catch (SecurityException ex) {
          logger_.log(Level.SEVERE, null, ex);
          return;
        }
        try {
          face.putData(data);
        } catch (IOException ex) {
          logger_.log(Level.SEVERE, ex.getMessage());
          return;
        }
        logger_.log(Level.FINE, "send recovery data back");
        logger_.log(Level.FINE, interest.getName().toUri());
      }
    }
  }

  /**
   * Common interest processing, using digest log to find the difference after
   * syncDigest. Return true if sent a data packet to satisfy the interest,
   * otherwise false.
   */
  private boolean
  processSyncInterest(int index, String syncDigest, Face face) throws SecurityException
  {
    ArrayList nameList = new ArrayList(); // of String
    ArrayList sequenceNoList = new ArrayList();  // of long
    ArrayList sessionNoList = new ArrayList(); // of long
    for (int j = index + 1; j < digestLog_.size(); ++j) {
      List temp = ((DigestLogEntry)digestLog_.get(j)).getData(); // of SyncStateProto.SyncState.
      for (int i = 0; i < temp.size(); ++i) {
        SyncStateProto.SyncState syncState = (SyncStateProto.SyncState)temp.get(i);
        if (!syncState.getType().equals
             (SyncStateProto.SyncState.ActionType.UPDATE))
          continue;

        if (digestTree_.find
            (syncState.getName(), syncState.getSeqno().getSession()) != -1) {
          int n = -1;
          for (int k = 0; k < nameList.size(); ++k) {
            if (((String)nameList.get(k)).equals(syncState.getName())) {
              n = k;
              break;
            }
          }
          if (n == -1) {
            nameList.add(syncState.getName());
            sequenceNoList.add(syncState.getSeqno().getSeq());
            sessionNoList.add(syncState.getSeqno().getSession());
          }
          else {
            sequenceNoList.set(n, syncState.getSeqno().getSeq());
            sessionNoList.set(n, syncState.getSeqno().getSession());
          }
        }
      }
    }

    SyncStateProto.SyncStateMsg.Builder builder =
      SyncStateProto.SyncStateMsg.newBuilder();
    for (int i = 0; i < nameList.size(); ++i) {
      builder.addSsBuilder()
        .setName((String)nameList.get(i))
        .setType(SyncStateProto.SyncState.ActionType.UPDATE)
        .getSeqnoBuilder().setSeq((long)(Long)sequenceNoList.get(i))
                          .setSession((long)(Long)sessionNoList.get(i));
    }
    SyncStateProto.SyncStateMsg tempContent = builder.build();

    boolean sent = false;
    if (tempContent.getSsCount() != 0) {
      Name name = new Name(applicationBroadcastPrefix_);
      name.append(syncDigest);
      byte[] array = tempContent.toByteArray();
      Data data = new Data(name);
      data.setContent(new Blob(array, false));
      keyChain_.sign(data, certificateName_);

      try {
        face.putData(data);
      } catch (IOException ex) {
        logger_.log(Level.SEVERE, ex.getMessage());
        return false;
      }

      sent = true;
      logger_.log(Level.FINE, "Sync Data send");
      logger_.log(Level.FINE, name.toUri());
    }

    return sent;
  }

  // Send Recovery Interest.
  private void
  sendRecovery(String syncDigest) throws IOException
  {
    logger_.log(Level.FINE, "unknown digest: ");
    Name name = new Name(applicationBroadcastPrefix_);
    name.append("recovery").append(syncDigest);
    Interest interest = new Interest(name);
    interest.setInterestLifetimeMilliseconds(syncLifetime_);
    face_.expressInterest(interest, this, this);
    logger_.log(Level.FINE, "Recovery Syncinterest expressed:");
    logger_.log(Level.FINE, name.toUri());
  }

  // This is called by onInterest after a timeout to check if a recovery is needed.
  // We make this an inner class because onTimeout is already used for syncTimeout.
  private class JudgeRecovery implements OnTimeout {
    public JudgeRecovery(String syncDigest, Face face)
    {
      syncDigest_ = syncDigest;
      face_ = face;
    }

    public final void
    onTimeout(Interest interest)
    {
      if (!enabled_)
        // Ignore callbacks after the application calls shutdown().
        return;

      int index2 = logFind(syncDigest_);
      if (index2 != -1) {
        if (!syncDigest_.equals(digestTree_.getRoot())) {
          try {
            processSyncInterest(index2, syncDigest_, face_);
          } catch (SecurityException ex) {
            logger_.log(Level.SEVERE, null, ex);
            return;
          }
        }
      }
      else {
        try {
          sendRecovery(syncDigest_);
        } catch (IOException ex) {
          logger_.log(Level.SEVERE, null, ex);
          return;
        }
      }
    }

    private final String syncDigest_;
    private final Face face_;
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

    logger_.log(Level.FINE, "Sync Interest time out.");
    logger_.log(Level.FINE, "Sync Interest name: {0}", interest.getName().toUri());
    String component = interest.getName().get(4).toEscapedString();
    if (component.equals(digestTree_.getRoot())) {
      Name name = new Name(interest.getName());
      Interest retryInterest = new Interest(interest.getName());
      retryInterest.setInterestLifetimeMilliseconds(syncLifetime_);
      try {
        face_.expressInterest(retryInterest, this, this);
      } catch (IOException ex) {
        logger_.log(Level.SEVERE, null, ex);
        return;
      }
      logger_.log(Level.FINE, "Syncinterest expressed:");
      logger_.log(Level.FINE, name.toUri());
    }
  }

  // Process initial data which usually includes all other publisher's info, and
  // send back the new comer's own info.
  private void
  initialOndata(List content) throws SecurityException
  {
    // The user is a new comer and receive data of all other people in the group.
    update(content);
    String digest = digestTree_.getRoot();
    for (int i = 0; i < content.size(); ++i) {
      SyncStateProto.SyncState syncState =
        (SyncStateProto.SyncState)content.get(i);
      if (syncState.getName().equals(applicationDataPrefixUri_) &&
          syncState.getSeqno().getSession() == sessionNo_) {
        // If the user was an old comer, after add the static log he needs to
        // increase his sequence number by 1.
        SyncStateProto.SyncStateMsg.Builder builder =
          SyncStateProto.SyncStateMsg.newBuilder();
        builder.addSsBuilder()
          .setName(applicationDataPrefixUri_)
          .setType(SyncStateProto.SyncState.ActionType.UPDATE)
          .getSeqnoBuilder().setSeq(syncState.getSeqno().getSeq() + 1)
                            .setSession(sessionNo_);
        SyncStateProto.SyncStateMsg tempContent = builder.build();

        if (update(tempContent.getSsList())) {
          try {
            onInitialized_.onInitialized();
          } catch (Throwable ex) {
            logger_.log(Level.SEVERE, null, ex);
          }
        }
      }
    }

    SyncStateProto.SyncStateMsg tempContent2;
    if (sequenceNo_ >= 0) {
      // Send the data packet with the new sequence number back.
      SyncStateProto.SyncStateMsg.Builder builder =
        SyncStateProto.SyncStateMsg.newBuilder();
      builder.addSsBuilder()
        .setName(applicationDataPrefixUri_)
        .setType(SyncStateProto.SyncState.ActionType.UPDATE)
        .getSeqnoBuilder().setSeq(sequenceNo_)
                          .setSession(sessionNo_);
      tempContent2 = builder.build();
    }
    else {
      SyncStateProto.SyncStateMsg.Builder builder =
        SyncStateProto.SyncStateMsg.newBuilder();
      builder.addSsBuilder()
        .setName(applicationDataPrefixUri_)
        .setType(SyncStateProto.SyncState.ActionType.UPDATE)
        .getSeqnoBuilder().setSeq(0)
                          .setSession(sessionNo_);
      tempContent2 = builder.build();
    }

    broadcastSyncState(digest, tempContent2);

    if (digestTree_.find(applicationDataPrefixUri_, sessionNo_) == -1) {
      // the user hasn't put himself in the digest tree.
      logger_.log(Level.FINE, "initial state");
      ++sequenceNo_;
      SyncStateProto.SyncStateMsg.Builder builder =
        SyncStateProto.SyncStateMsg.newBuilder();
      builder.addSsBuilder()
        .setName(applicationDataPrefixUri_)
        .setType(SyncStateProto.SyncState.ActionType.UPDATE)
        .getSeqnoBuilder().setSeq(sequenceNo_)
                          .setSession(sessionNo_);
      SyncStateProto.SyncStateMsg tempContent = builder.build();

      if (update(tempContent.getSsList())) {
        try {
          onInitialized_.onInitialized();
        } catch (Throwable ex) {
          logger_.log(Level.SEVERE, null, ex);
        }
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
  double syncLifetime_;
  OnReceivedSyncState onReceivedSyncState_;
  OnInitialized onInitialized_;
  // Use ArrayList without generics so it works with older Java compilers.
  ArrayList digestLog_ = new ArrayList(); // of DigestLogEntry
  DigestTree digestTree_ = new DigestTree();
  String applicationDataPrefixUri_;
  Name applicationBroadcastPrefix_;
  long sessionNo_;
  long sequenceNo_ = -1;
  MemoryContentCache contentCache_;
  boolean enabled_ = true;
  private static final Logger logger_ = Logger.getLogger(ChronoSync2013.class.getName());
}
