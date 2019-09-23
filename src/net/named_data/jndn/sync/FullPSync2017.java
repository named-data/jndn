/**
 * Copyright (C) 2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From the PSync library https://github.com/named-data/PSync/blob/master/PSync/full-producer-arbitrary.cpp
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

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Face;
import net.named_data.jndn.Interest;
import net.named_data.jndn.InterestFilter;
import net.named_data.jndn.Name;
import net.named_data.jndn.OnInterestCallback;
import net.named_data.jndn.OnRegisterFailed;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.SigningInfo;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.security.tpm.TpmBackEnd;
import net.named_data.jndn.security.v2.Validator;
import net.named_data.jndn.sync.detail.InvertibleBloomLookupTable;
import net.named_data.jndn.sync.detail.PSyncSegmentPublisher;
import net.named_data.jndn.sync.detail.PSyncState;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.SegmentFetcher;

/**
 * FullPSync2017 implements the full sync logic of PSync to synchronize with
 * other nodes, where all nodes want to sync all the names. The application
 * should call publishName whenever it wants to let consumers know that a new name
 * is available. Currently, fetching and publishing the data given by the
 * announced name needs to be handled by the application. The Full PSync
 * protocol is described in Section G "Full-Data Synchronization" of:
 * https://named-data.net/wp-content/uploads/2017/05/scalable_name-based_data_synchronization.pdf
 * (Note: In the PSync library, this class is called FullProducerArbitrary. But
 * because the class actually handles both producing and consuming, we omit
 * "producer" in the name to avoid confusion.)
 */
public class FullPSync2017 extends PSyncProducerBase
    implements SegmentFetcher.OnError {
  public interface OnNamesUpdate {
    void onNamesUpdate(ArrayList<Name> updates);
  }
  public interface CanAddToSyncData {
    boolean canAddToSyncData(Name name, HashSet<Long> negative);
  }
  public interface CanAddReceivedName {
    boolean canAddReceivedName(Name name);
  }

  /**
   * Create a FullPSync2017.
   * @param expectedNEntries The expected number of entries in the IBLT.
   * @param face The application's Face.
   * @param syncPrefix The prefix Name of the sync group, which is copied.
   * @param onNamesUpdate When there are new names, this calls
   * onNamesUpdate.onNamesUpdate(names) where names is a list of Names. However,
   * see the canAddReceivedName callback which can control which names are added.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param keyChain The KeyChain for signing Data packets.
   * @param syncInterestLifetime The Interest lifetime for the sync Interests,
   * in milliseconds.
   * @param syncReplyFreshnessPeriod The freshness period of the sync Data
   * packet, in milliseconds.
   * @param signingInfo The SigningInfo for signing Data packets, which is
   * copied.
   * @param canAddToSyncData When a new IBLT is received in a sync
   * Interest, this calls canAddToSyncData.canAddToSyncData(name, negative)
   * where Name is the candidate Name to add to the response Data packet of
   * Names, and negative is the set of names that the other's user's Name set,
   * but not in our own Name set. If the callback returns false, then this does
   * not report the Name to the other user. However, if canAddToSyncData is
   * null, then each name is reported.
   * @param canAddReceivedName When new names are received, this calls
   * canAddReceivedName.canAddReceivedName(name) for each name. If the callback
   * returns false, then this does not add to the IBLT or report to the
   * application with onNamesUpdate. However, if canAddReceivedName is null,
   * then each name is added.
   */
  public FullPSync2017
    (int expectedNEntries, Face face, Name syncPrefix,
     OnNamesUpdate onNamesUpdate, KeyChain keyChain, double syncInterestLifetime,
     double syncReplyFreshnessPeriod, SigningInfo signingInfo,
     CanAddToSyncData canAddToSyncData, CanAddReceivedName canAddReceivedName)
      throws IOException, SecurityException
  {
    super(expectedNEntries, syncPrefix, syncReplyFreshnessPeriod);
    construct
      (face, onNamesUpdate, keyChain, syncInterestLifetime, signingInfo,
       canAddToSyncData, canAddReceivedName);
  }

  /**
   * Create a FullPSync2017.
   * @param expectedNEntries The expected number of entries in the IBLT.
   * @param face The application's Face.
   * @param syncPrefix The prefix Name of the sync group, which is copied.
   * @param onNamesUpdate When there are new names, this calls
   * onNamesUpdate.onNamesUpdate(names) where names is a list of Names. However,
   * see the canAddReceivedName callback which can control which names are added.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param keyChain The KeyChain for signing Data packets.
   * @param syncInterestLifetime The Interest lifetime for the sync Interests,
   * in milliseconds.
   * @param syncReplyFreshnessPeriod The freshness period of the sync Data
   * packet, in milliseconds.
   * @param signingInfo The SigningInfo for signing Data packets, which is
   * copied.
   */
  public FullPSync2017
    (int expectedNEntries, Face face, Name syncPrefix,
     OnNamesUpdate onNamesUpdate, KeyChain keyChain, double syncInterestLifetime,
     double syncReplyFreshnessPeriod, SigningInfo signingInfo)
      throws IOException, SecurityException
  {
    super(expectedNEntries, syncPrefix, syncReplyFreshnessPeriod);
    construct
      (face, onNamesUpdate, keyChain, syncInterestLifetime, signingInfo,
       null, null);
  }

  /**
   * Create a FullPSync2017, where signingInfo is the default SigningInfo().
   * @param expectedNEntries The expected number of entries in the IBLT.
   * @param face The application's Face.
   * @param syncPrefix The prefix Name of the sync group, which is copied.
   * @param onNamesUpdate When there are new names, this calls
   * onNamesUpdate.onNamesUpdate(names) where names is a list of Names. However,
   * see the canAddReceivedName callback which can control which names are added.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param keyChain The KeyChain for signing Data packets.
   * @param syncInterestLifetime The Interest lifetime for the sync Interests,
   * in milliseconds.
   * @param syncReplyFreshnessPeriod The freshness period of the sync Data
   * packet, in milliseconds.
   */
  public FullPSync2017
    (int expectedNEntries, Face face, Name syncPrefix,
     OnNamesUpdate onNamesUpdate, KeyChain keyChain, double syncInterestLifetime,
     double syncReplyFreshnessPeriod)
      throws IOException, SecurityException
  {
    super(expectedNEntries, syncPrefix, syncReplyFreshnessPeriod);
    construct
      (face, onNamesUpdate, keyChain, syncInterestLifetime,
       new SigningInfo(), null, null);
  }

  /**
   * Create a FullPSync2017, where syncInterestLifetime is
   * DEFAULT_SYNC_INTEREST_LIFETIME, syncReplyFreshnessPeriod is
   * DEFAULT_SYNC_REPLY_FRESHNESS_PERIOD and signingInfo is the default
   * SigningInfo().
   * @param expectedNEntries The expected number of entries in the IBLT.
   * @param face The application's Face.
   * @param syncPrefix The prefix Name of the sync group, which is copied.
   * @param onNamesUpdate When there are new names, this calls
   * onNamesUpdate.onNamesUpdate(names) where names is a list of Names. However,
   * see the canAddReceivedName callback which can control which names are added.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param keyChain The KeyChain for signing Data packets.
   */
  public FullPSync2017
    (int expectedNEntries, Face face, Name syncPrefix,
     OnNamesUpdate onNamesUpdate, KeyChain keyChain)
      throws IOException, SecurityException
  {
    super(expectedNEntries, syncPrefix, DEFAULT_SYNC_REPLY_FRESHNESS_PERIOD);
    construct
      (face, onNamesUpdate, keyChain, DEFAULT_SYNC_INTEREST_LIFETIME,
       new SigningInfo(), null, null);
  }

  private void
  construct
    (Face face, OnNamesUpdate onNamesUpdate, KeyChain keyChain,
     double syncInterestLifetime, SigningInfo signingInfo,
     CanAddToSyncData canAddToSyncData, CanAddReceivedName canAddReceivedName)
       throws IOException, SecurityException
  {
    face_ = face;
    keyChain_ = keyChain;
    syncInterestLifetime_ = syncInterestLifetime;
    signingInfo_ = new SigningInfo(signingInfo);
    onNamesUpdate_ = onNamesUpdate;
    canAddToSyncData_ = canAddToSyncData;
    canAddReceivedName_ = canAddReceivedName;
    segmentPublisher_ = new PSyncSegmentPublisher(face_, keyChain_);

    registeredPrefix_ = face_.registerPrefix
      (syncPrefix_,
       new OnInterestCallback() {
         public void onInterest(Name prefix, Interest interest, Face face,
                                long interestFilterId, InterestFilter filter) {
           onSyncInterest(prefix, interest, face, interestFilterId, filter);
         }
       },
       new OnRegisterFailed() {
         public void onRegisterFailed(Name prefix) {
           PSyncProducerBase.onRegisterFailed(prefix);
         }
       });

    // TODO: Should we do this after the registerPrefix onSuccess callback?
    sendSyncInterest();
  }

  /**
   * Publish the Name to inform the others. However, if the Name has already
   * been published, do nothing.
   * @param name The Name to publish.
   */
  public final void
  publishName(Name name)
  {
    if (nameToHash_.containsKey(name)) {
      logger_.log(Level.FINE, "Already published, ignoring: {0}", name);
      return;
    }

    logger_.log(Level.INFO, "Publish: {0}", name);
    insertIntoIblt(name);
    satisfyPendingInterests();
  }

  /**
   * Remove the Name from the IBLT so that it won't be announced to other users.
   * @param name The Name to remove.
   */
  void
  removeName(Name name)
  {
    removeFromIblt(name);
  }

  public static final double DEFAULT_SYNC_INTEREST_LIFETIME = 1000;
  public static final double DEFAULT_SYNC_REPLY_FRESHNESS_PERIOD = 1000;

  public class PendingEntryInfoFull {
    public PendingEntryInfoFull(InvertibleBloomLookupTable iblt)
    {
      iblt_ = iblt;
    }

    public final InvertibleBloomLookupTable iblt_;
    public boolean isRemoved_ = false;
  };

  /**
   * Send the sync interest for full synchronization. This forms the interest
   * name: /<sync-prefix>/<own-IBLT>. This cancels any pending sync interest
   * we sent earlier on the face.
   */
  private void
  sendSyncInterest()
  {
/** Debug: Implement stopping an ongoing fetch.
    // If we send two sync interest one after the other
    // since there is no new data in the network yet,
    // when data is available it may satisfy both of them
    if (fetcher_) {
      fetcher_->stop();
    }
*/

    // Sync Interest format for full sync: /<sync-prefix>/<ourLatestIBF>
    Name syncInterestName = new Name(syncPrefix_);

    // Append our latest IBLT.
    Blob encodedIblt;
    try {
      encodedIblt = iblt_.encode();
    } catch (IOException ex) {
      // We don't expect this error.
      logger_.log(Level.INFO, "sendSyncInterest: Error in IBLT encode", ex);
      return;
    }
    syncInterestName.append(encodedIblt);

    outstandingInterestName_ = syncInterestName;

    // random1 is from 0.0 to 1.0.
    // random1 is from 0.0 to 1.0.
    double random1 = random_.nextDouble();
    // Get a jitter of +/- syncInterestLifetime_ * 0.2 .
    double jitter = (random1 - 0.5) * (syncInterestLifetime_ * 0.2);

    face_.callLater
      (syncInterestLifetime_ / 2 + jitter,
       new Runnable() {
         public void run() { 
           sendSyncInterest();
         }
       });

    final Interest syncInterest = new Interest(syncInterestName);
    syncInterest.setInterestLifetimeMilliseconds(syncInterestLifetime_);
    syncInterest.setNonce(new Blob(new byte[4], false));
    syncInterest.refreshNonce();

    SegmentFetcher.fetch
      (face_, syncInterest, SegmentFetcher.DontVerifySegment,
       new SegmentFetcher.OnComplete() {
         public void onComplete(Blob content) {
           onSyncData(content, syncInterest);
         }
       },
       this);

    logger_.log(Level.FINE, "sendFullSyncInterest, nonce: " +
      syncInterest.getNonce().toHex() + ", hash: " + syncInterestName.hashCode());
  }

  /**
   * Process a sync interest received from another party.
   * This gets the difference between our IBLT and the IBLT in the other sync
   * interest. If we cannot get the difference successfully, then send an
   * application Nack. If we have some things in our IBLT that the other side
   * does not have, then reply with the content. Or, if the number of
   * different items is greater than threshold or equals zero, then send a
   * Nack. Otherwise add the sync interest into the pendingEntries_ map with
   * the interest name as the key and a PendingEntryInfoFull as the value.
   * @param prefixName The prefix Name for the sync group which we registered.
   * @param interest The the received Interest.
   */
  private void
  onSyncInterest
    (Name prefixName, final Interest interest, Face face, long interestFilterId,
     InterestFilter filter)
  {
    try {
      if (segmentPublisher_.replyFromStore(interest.getName()))
        return;
    } catch (IOException ex) {
      logger_.log(Level.INFO, "onSyncInterest: Error in replyFromStore", ex);
      return;
    }

    Name nameWithoutSyncPrefix = interest.getName().getSubName(prefixName.size());
    Name interestName;

    if (nameWithoutSyncPrefix.size() == 1)
      // Get /<prefix>/IBLT from /<prefix>/IBLT
      interestName = interest.getName();
    else if (nameWithoutSyncPrefix.size() == 3)
      // Get /<prefix>/IBLT from /<prefix>/IBLT/<version>/<segment-no>
      interestName = interest.getName().getPrefix(-2);
    else
      return;

    Name.Component ibltName = interestName.get(-1);

    logger_.log(Level.FINE, "Full Sync Interest received, nonce: " +
      interest.getNonce().toHex() + ", hash:" + interestName.hashCode());

    InvertibleBloomLookupTable iblt = new InvertibleBloomLookupTable
      (new InvertibleBloomLookupTable(expectedNEntries_));
    try {
      iblt.initialize(ibltName.getValue());
    } catch (Exception ex) {
      logger_.log(Level.INFO, "onSyncInterest: Error in IBLT decode", ex);
      return;
    }

    InvertibleBloomLookupTable difference = iblt_.difference(iblt);

      HashSet<Long> positive = new HashSet<Long>();
      HashSet<Long> negative = new HashSet<Long>();

    if (!difference.listEntries(positive, negative)) {
      logger_.log(Level.INFO, "Cannot decode differences, positive: " +
        positive.size() + " negative: " + negative.size() + " threshold: " +
        threshold_);

      // Send all data if greater than the threshold, or if there are neither
      // positive nor negative differences. Otherwise, continue below and send
      // the positive as usual.
      if (positive.size() + negative.size() >= threshold_ ||
          (positive.size() == 0 && negative.size() == 0)) {
        PSyncState state1 = new PSyncState();
        for (Name name : nameToHash_.keySet())
          state1.addContent(name);

        if (state1.getContent().size() > 0) {
          try {
            segmentPublisher_.publish
              (interest.getName(), interest.getName(), state1.wireEncode(),
               syncReplyFreshnessPeriod_, signingInfo_);
          } catch (Exception ex) {
            logger_.log(Level.INFO, "onSyncInterest: Error in publish", ex);
            return;
          }
        }

        return;
      }
    }

    PSyncState state = new PSyncState();
    for (Long hash : positive) {
      Name name = hashToName_.get(hash);

      if (nameToHash_.containsKey(name)) {
        if (canAddToSyncData_ == null ||
            canAddToSyncData_.canAddToSyncData(name, negative))
          state.addContent(name);
      }
    }

    if (state.getContent().size() > 0) {
      logger_.log(Level.FINE, "Sending sync content: " + state);
      try {
        sendSyncData(interestName, state.wireEncode());
      } catch (Exception ex) {
        logger_.log(Level.INFO, "onSyncInterest: Error in sendSyncData", ex);
      }
      
      return;
    }

    final PendingEntryInfoFull entry = new PendingEntryInfoFull(iblt);
    pendingEntries_.put(interestName, entry);
    face_.callLater
      (interest.getInterestLifetimeMilliseconds(),
       new Runnable() {
         public void run() {
           delayedRemovePendingEntry(interest.getName(), entry, interest.getNonce());
         }
       });
  }

  public final void onError
    (SegmentFetcher.ErrorCode errorCode, String message)
  {
    logger_.log(Level.INFO, "Cannot fetch sync data, error: " + errorCode +
      " message: " + message);
  }

  /**
   * Send the sync Data. Check if the data will satisfy our own pending
   * Interest. If it does, then remove it and then renew the sync interest.
   * Otherwise, just send the Data.
   * @param name The basis to use for the Data name.
   * @param content The content of the Data.
   */
  private void
  sendSyncData(Name name, Blob content) 
    throws IOException, EncodingException, TpmBackEnd.Error, PibImpl.Error,
      KeyChain.Error
  {
    logger_.log(Level.FINE, 
      "Checking if the Data will satisfy our own pending interest");

    Name nameWithIblt = new Name();
    nameWithIblt.append(iblt_.encode());

    // Append the hash of our IBLT so that the Data name should be different for
    // each node.
    Name dataName = new Name(name).appendNumber(nameWithIblt.hashCode());

    // Check if our own Interest got satisfied.
    if (outstandingInterestName_.equals(name)) {
      logger_.log(Level.FINE, "Satisfies our own pending Interest");
      // remove outstanding interest
/** Debug: Implement stopping an ongoing fetch.
      if (fetcher_) {
        _LOG_DEBUG("Removing our pending interest from the Face (stopping fetcher)");
        fetcher_->stop();
        outstandingInterestName_ = Name();
      }
**/
      outstandingInterestName_ = new Name();

      logger_.log(Level.FINE, "Sending sync Data");

      // Send Data after removing the pending sync interest on the Face.
      segmentPublisher_.publish
        (name, dataName, content, syncReplyFreshnessPeriod_, signingInfo_);

      logger_.log(Level.FINE, "sendSyncData: Renewing sync interest");
      sendSyncInterest();
    }
    else {
      logger_.log(Level.FINE, "Sending Sync Data for not our own Interest");
      segmentPublisher_.publish
        (name, dataName, content, syncReplyFreshnessPeriod_, signingInfo_);
    }
  }

  /**
   * Process the sync data after the content is assembled by the
   * SegmentFetcher. Call deletePendingInterests to delete any pending sync
   * Interest with the Interest name, which would have been satisfied by the
   * forwarder once it got the data. For each name in the data content, check
   * that we don't already have the name, and call _canAddReceivedName (which
   * may process the name as a prefix/sequenceNo). Call onUpdate_ to notify
   * the application about the updates. Call sendSyncInterest because the last
   * one was satisfied by the incoming data.
   * @param encodedContent The encoded sync data content that was assembled by
   * the SegmentFetcher.
   * @param interest The Interest for which we got the data.
   */
  private void
  onSyncData(Blob encodedContent, Interest interest)
  {
    deletePendingInterests(interest.getName());

    PSyncState state;
    try {
      state = new PSyncState(encodedContent);
    } catch (EncodingException ex) {
      logger_.log(Level.INFO, "onSyncData: Error in PSyncState decode", ex);
      return;
    }
    ArrayList<Name> names = new ArrayList<Name>();

    logger_.log(Level.INFO, "Sync Data Received: {0}", state);

    ArrayList<Name> content = state.getContent();
    for (Name contentName : content) {
      if (!nameToHash_.containsKey(contentName)) {
        logger_.log(Level.FINE, "Checking whether to add {0}", contentName);
        if (canAddReceivedName_ == null ||
            canAddReceivedName_.canAddReceivedName(contentName)) {
          logger_.log(Level.FINE, "Adding name {0}", contentName);
          names.add(contentName);
          insertIntoIblt(contentName);
        }
        // We should not call satisfyPendingSyncInterests here because we just
        // got data and deleted pending interests by calling deletePendingInterests.
        // But we might have interests which don't match this interest that might
        // not have been deleted from the pending sync interests.
      }
    }

    // We just got the data, so send a new sync Interest.
    if (names.size() > 0) {
      try {
        onNamesUpdate_.onNamesUpdate(names);
      } catch (Throwable ex) {
        logger_.log(Level.SEVERE, "Error in onNamesUpdate", ex);
      }

      logger_.log(Level.FINE, "onSyncData: Renewing sync interest");
      sendSyncInterest();
    } else {
      logger_.log(Level.FINE, "No new update, interest nonce: " +
        interest.getNonce().toHex() + " , hash: " + interest.getName().hashCode());
    }
  }


  /**
   * Satisfy pending sync Interests. For a pending sync interests, if the
   * IBLT of the sync Interest has any difference from our own IBLT, then
   * send a Data back. If we can't decode the difference from the stored IBLT,
   * then delete it.
   */
  private void
  satisfyPendingInterests()
  {
    logger_.log(Level.FINE, "Satisfying full sync Interest: " + pendingEntries_.size());

    // First copy the keys, to not change the HashMap while iterating.
    HashSet<Name> keys = new HashSet<Name>();
    for (Name key : pendingEntries_.keySet())
      keys.add(key);

    for (Name keyName : keys) {
      PendingEntryInfoFull pendingEntry = pendingEntries_.get(keyName);

      InvertibleBloomLookupTable entryIblt = pendingEntry.iblt_;
      InvertibleBloomLookupTable difference = iblt_.difference(entryIblt);
      HashSet<Long> positive = new HashSet<Long>();
      HashSet<Long> negative = new HashSet<Long>();

      if (!difference.listEntries(positive, negative)) {
        logger_.log(Level.INFO, "Decode failed for pending interest");
        if (positive.size() + negative.size() >= threshold_ ||
            (positive.size() == 0 && negative.size() == 0)) {
          logger_.log(Level.INFO,
            "positive + negative > threshold or no difference can be found. Erase pending interest.");
          // Prevent delayedRemovePendingEntry from removing a new entry with the same Name.
          pendingEntry.isRemoved_ = true;
          pendingEntries_.remove(keyName);
          continue;
        }
      }

      PSyncState state = new PSyncState();
      for (Long hash : positive) {
        Name name = hashToName_.get(hash);

        if (nameToHash_.containsKey(name))
          state.addContent(name);
      }

      if (state.getContent().size() > 0) {
        logger_.log(Level.FINE, "Satisfying sync content: {0}", state);
        try {
          sendSyncData(keyName, state.wireEncode());
        } catch (Exception ex) {
          logger_.log(Level.INFO, "satisfyPendingInterests: Error in sendSyncData", ex);
        }
        // Prevent delayedRemovePendingEntry from removing a new entry with the same Name.
        pendingEntry.isRemoved_ = true;
        pendingEntries_.remove(keyName);
      }
    }
  }

  /**
   * Delete pending sync Interests that match the given name.
   */
  private void
  deletePendingInterests(Name interestName)
  {
    PendingEntryInfoFull entry = pendingEntries_.get(interestName);
    if (entry == null)
      return;

    logger_.log(Level.INFO, "Delete pending interest: {0}", interestName);
    // Prevent delayedRemovePendingEntry from removing a new entry with the same Name.
    entry.isRemoved_ = true;
    pendingEntries_.remove(interestName);
  }

  /**
   * Remove the entry from pendingEntries_ which has the name. However, if
   * entry.isRemoved_ is true, do nothing. Therefore, if an entry is
   * directly removed from pendingEntries_, it should set isRemoved_.
   * @param name The key in the pendingEntries_ map for the entry to remove.
   * @param entry A (possibly earlier and removed) entry from when it was
   * inserted into the pendingEntries_ map.
   * @param nonce This is only used for the log message.
   */
  private void
  delayedRemovePendingEntry(Name name, PendingEntryInfoFull entry, Blob nonce)
  {
    if (entry.isRemoved_)
      // A previous operation already removed this entry, so don't try again to
      // remove the entry with the Name in case it is a new entry.
      return;

    logger_.log(Level.FINE, "Remove Pending Interest {0}", nonce.toHex());
    entry.isRemoved_ = true;
    pendingEntries_.remove(name);
  }

  private Face face_;
  private KeyChain keyChain_;
  private SigningInfo signingInfo_;
  private PSyncSegmentPublisher segmentPublisher_;
  private final HashMap<Name, PendingEntryInfoFull> pendingEntries_ =
    new HashMap<Name, PendingEntryInfoFull>();
  private double syncInterestLifetime_;
  private OnNamesUpdate onNamesUpdate_;
  private CanAddToSyncData canAddToSyncData_;
  private CanAddReceivedName canAddReceivedName_;
  private Name outstandingInterestName_ = new Name();
  private long registeredPrefix_;
  private static final Random random_ = new Random();
  private static final Logger logger_ = Logger.getLogger(FullPSync2017.class.getName());
}
