/**
 * Copyright (C) 2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From the PSync library https://github.com/named-data/PSync/blob/master/PSync/full-producer.cpp
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
import java.util.HashSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Face;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.SigningInfo;
import net.named_data.jndn.sync.detail.InvertibleBloomLookupTable;
import net.named_data.jndn.sync.detail.PSyncUserPrefixes;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

/**
 * FullPSync2017WithUsers uses FullPSync2017 to implement the full sync logic of
 * PSync to synchronize with other nodes, where all nodes want to sync the
 * sequence number of all users based on their user prefix. The application
 * should call publishName whenever it wants to let consumers know that new data
 * with a new sequence number is available for the user prefix. Multiple user
 * prefixes can be added by using addUserNode. Currently, fetching and
 * publishing the data (named by the user prefix plus the sequence number) needs
 * to be handled by the application. See FullPSync2017 for details on the
 * Full PSync protocol. The Full PSync
 * protocol is described in Section G "Full-Data Synchronization" of:
 * https://named-data.net/wp-content/uploads/2017/05/scalable_name-based_data_synchronization.pdf
 * (Note: In the PSync library, this class is called FullProducer. But because
 * the class actually handles both producing and consuming, we omit "producer"
 * in the name to avoid confusion.)
 */
public class FullPSync2017WithUsers 
    implements FullPSync2017.OnNamesUpdate, FullPSync2017.CanAddToSyncData,
      FullPSync2017.CanAddReceivedName {
  public interface OnUpdate {
    void onUpdate(ArrayList<PSyncMissingDataInfo> updates);
  }

  /**
   * Create a FullPSync2017WithUsers.
   * @param expectedNEntries The expected number of entries in the IBLT.
   * @param face The application's Face.
   * @param syncPrefix The prefix Name of the sync group, which is copied.
   * @param userPrefix The prefix Name of the first user in the group, which is
   * copied. However, if this Name is empty, it is not added and you must call
   * addUserNode.
   * @param onUpdate When there is new data, this calls onUdate.onUdate(updates)
   * where updates is a list of PSyncMissingDataInfo.
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
  public FullPSync2017WithUsers
    (int expectedNEntries, Face face, Name syncPrefix, Name userPrefix,
     OnUpdate onUpdate, KeyChain keyChain, double syncInterestLifetime,
     double syncReplyFreshnessPeriod, SigningInfo signingInfo)
    throws IOException, SecurityException
  {
    onUpdate_ = onUpdate;
    fullPSync_ = new FullPSync2017
      (expectedNEntries, face, syncPrefix, this,
       keyChain, syncInterestLifetime, syncReplyFreshnessPeriod, signingInfo,
       this, this);

    if (userPrefix != null && userPrefix.size() > 0)
      addUserNode(userPrefix);
  }

  /**
   * Create a FullPSync2017WithUsers, where signingInfo is the default
   * SigningInfo().
   * @param expectedNEntries The expected number of entries in the IBLT.
   * @param face The application's Face.
   * @param syncPrefix The prefix Name of the sync group, which is copied.
   * @param userPrefix The prefix Name of the first user in the group, which is
   * copied. However, if this Name is empty, it is not added and you must call
   * addUserNode.
   * @param onUpdate When there is new data, this calls onUdate.onUdate(updates)
   * where updates is a list of PSyncMissingDataInfo.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param keyChain The KeyChain for signing Data packets.
   * @param syncInterestLifetime The Interest lifetime for the sync Interests,
   * in milliseconds.
   * @param syncReplyFreshnessPeriod The freshness period of the sync Data
   * packet, in milliseconds.
   */
  public FullPSync2017WithUsers
    (int expectedNEntries, Face face, Name syncPrefix, Name userPrefix,
     OnUpdate onUpdate, KeyChain keyChain, double syncInterestLifetime,
     double syncReplyFreshnessPeriod)
    throws IOException, SecurityException
  {
    onUpdate_ = onUpdate;
    fullPSync_ = new FullPSync2017
      (expectedNEntries, face, syncPrefix, this,
       keyChain, syncInterestLifetime, syncReplyFreshnessPeriod, new SigningInfo(),
       this, this);

    if (userPrefix != null && userPrefix.size() > 0)
      addUserNode(userPrefix);
  }

  /**
   * Create a FullPSync2017WithUsers, where syncInterestLifetime is
   * FullPSync2017.DEFAULT_SYNC_INTEREST_LIFETIME, syncReplyFreshnessPeriod is
   * FullPSync2017.DEFAULT_SYNC_REPLY_FRESHNESS_PERIOD, and signingInfo is the
   * default SigningInfo().
   * @param expectedNEntries The expected number of entries in the IBLT.
   * @param face The application's Face.
   * @param syncPrefix The prefix Name of the sync group, which is copied.
   * @param userPrefix The prefix Name of the first user in the group, which is
   * copied. However, if this Name is empty, it is not added and you must call
   * addUserNode.
   * @param onUpdate When there is new data, this calls onUdate.onUdate(updates)
   * where updates is a list of PSyncMissingDataInfo.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param keyChain The KeyChain for signing Data packets.
   */
  public FullPSync2017WithUsers
    (int expectedNEntries, Face face, Name syncPrefix, Name userPrefix,
     OnUpdate onUpdate, KeyChain keyChain)
    throws IOException, SecurityException
  {
    onUpdate_ = onUpdate;
    fullPSync_ = new FullPSync2017
      (expectedNEntries, face, syncPrefix, this,
       keyChain, FullPSync2017.DEFAULT_SYNC_INTEREST_LIFETIME,
       FullPSync2017.DEFAULT_SYNC_REPLY_FRESHNESS_PERIOD, new SigningInfo(),
       this, this);

    if (userPrefix != null && userPrefix.size() > 0)
      addUserNode(userPrefix);
  }

  /**
   * Return the current sequence number of the given user prefix.
   * @param prefix The user prefix for the sequence number.
   * @return The sequence number for the user prefix, or -1 if not found.
   */
  public final int
  getSequenceNo(Name prefix) { return prefixes_.getSequenceNo(prefix); }

  /**
   * Add a user node for synchronization based on the prefix Name, and
   * initialize the sequence number to zero. However, if the prefix Name already
   * exists, then do nothing and return false. This does not add sequence number
   * zero to the IBLT because, if a large number of user nodes are added, then
   * decoding the difference between our own IBLT and the other IBLT will not be
   * possible.
   * @param prefix The prefix Name of the user node to be added.
   * @return True if the user node with the prefix Name was added, false if the
   * prefix Name already exists.
   */
  public final boolean
  addUserNode(Name prefix) { return prefixes_.addUserNode(prefix); }

  /**
   * Remove the user node from the synchronization. This erases the prefix from
   * the IBLT and other tables.
   * @param prefix The prefix Name of the user node to be removed. If there is
   * no user node with this prefix, do nothing.
   */
  public final void
  removeUserNode(Name prefix)
  {
    if (prefixes_.isUserNode(prefix)) {
      int sequenceNo = (int)prefixes_.prefixes_.get(prefix);
      prefixes_.removeUserNode(prefix);
      fullPSync_.removeName(new Name(prefix).appendNumber(sequenceNo));
    }
  }

  /**
   * Publish the sequence number for the prefix Name to inform the others.
   * (addUserNode needs to be called before this to add the prefix, if it was
   * not already added via the constructor.)
   * @param prefix the prefix Name to be updated.
   * @param sequenceNo The sequence number of the user prefix to be
   * set in the IBLT. However, if sequenceNo is -1, then the existing sequence
   * number is incremented by 1.
   */
  public final void
  publishName(Name prefix, int sequenceNo)
  {
    if (!prefixes_.isUserNode(prefix)) {
      logger_.log(Level.WARNING, "Prefix not added: {0}" + prefix);
      return;
    }

    int newSequenceNo =
      sequenceNo >= 0 ? sequenceNo : prefixes_.getSequenceNoOrZero(prefix) + 1;

    logger_.log(Level.INFO, "Publish: " + prefix.toUri() + "/" + newSequenceNo);
    if (updateSequenceNo(prefix, newSequenceNo))
      // Insert the new sequence number.
      fullPSync_.publishName(new Name(prefix).appendNumber(newSequenceNo));
  }

  /**
   * Publish the sequence number for the prefix Name to inform the others, where
   * the existing sequence number is incremented by 1.
   * (addUserNode needs to be called before this to add the prefix, if it was
   * not already added via the constructor.)
   * @param prefix the prefix Name to be updated.
   */
  public final void
  publishName(Name prefix)
  {
    publishName(prefix, -1);
  }

  /**
   * This is called when new names are received to check if the name can be
   * added to the IBLT.
   * @param name The Name to check.
   * @return True if the received name can be added.
   */
  public final boolean
  canAddReceivedName(Name name) {
    Name prefix = name.getPrefix(-1);
    long sequenceNo = name.get(-1).toNumber();

    boolean havePrefix = prefixes_.isUserNode(prefix);
    if (!havePrefix || (int)prefixes_.prefixes_.get(prefix) < sequenceNo) {
      if (havePrefix) {
        int oldSequenceNo = prefixes_.getSequenceNoOrZero(prefix);
        if (oldSequenceNo != 0)
          // Remove the old sequence number from the IBLT before the caller adds
          // the new one.
          fullPSync_.removeName(new Name(prefix).appendNumber(oldSequenceNo));
      }

      return true;
    }
    else
      return false;
  }

  /**
   * This is called when new names are received. Update prefixes_, create the
   * list of PSyncMissingDataInfo and call the onUpdate_ callback.
   * @param names The new received names.
   */
  public final void
  onNamesUpdate(ArrayList<Name> names) {
    ArrayList<PSyncMissingDataInfo> updates = new ArrayList<PSyncMissingDataInfo>();

    for (Name name : names) {
      Name prefix = name.getPrefix(-1);
      long sequenceNo = name.get(-1).toNumber();

      updates.add(new PSyncMissingDataInfo
        (prefix, prefixes_.getSequenceNoOrZero(prefix) + 1, (int)sequenceNo));

      // canAddReceivedName already made sure that the new sequenceNo is greater
      // than the old one, and removed the old one from the IBLT.
      prefixes_.prefixes_.put(prefix, (int)sequenceNo);
    }

    try {
      onUpdate_.onUpdate(updates);
    } catch (Throwable ex) {
      logger_.log(Level.SEVERE, "Error in onUpdate", ex);
    }
  }

  /**
   * Get the prefix from the name and check if hash(prefix + 1) is in the
   * negative set, i.e. "isNotFutureHash" (Sometimes the Interest from the other
   * side gets to us before the Data.)
   * @return True if hash(prefix + 1) is NOT in the negative set (meaning that
   * it is not a future hash), or false if it IS in the negative set.
   */
  public final boolean
  canAddToSyncData(Name name, HashSet<Long> negative) {
    Name prefix = name.getPrefix(-1);

    String uri = new Name(prefix).appendNumber
      (prefixes_.getSequenceNoOrZero(prefix) + 1).toUri();
    long nextHash = Common.murmurHash3
      (InvertibleBloomLookupTable.N_HASHCHECK, new Blob(uri).getImmutableArray());

    for (Long negativeHash : negative) {
      if (negativeHash == nextHash)
        return false;
    }

    return true;
  }

  /**
   * Update prefixes_ and iblt_ with the given prefix and sequence number.
   * Whoever calls this needs to make sure that prefix is in prefixes_.
   * We remove an already-existing prefix/sequence number from iblt_ (unless
   * sequenceNo is zero because we don't insert a zero sequence number into the
   * IBLT.) Then we update prefixes_. If this returns true, the caller should
   * update  nameToHash_, hashToName_ and iblt_ .
   * @param prefix The prefix of the sequence number to update.
   * @param sequenceNumber The new sequence number.
   * @return True if the prefixes_ were updated, false if not.
   */
  private boolean
  updateSequenceNo(Name prefix, int sequenceNo)
  {
    int[] oldSequenceNo = new int[1];
    if (!prefixes_.updateSequenceNo(prefix, sequenceNo, oldSequenceNo))
      return false;

    // Delete the old sequence number from the IBLT. If oldSequenceNo is zero, we
    // don't need to delete it, because we don't insert a prefix with sequence
    // number zero in the IBLT.
    if (oldSequenceNo[0] != 0)
      fullPSync_.removeName(new Name(prefix).appendNumber(oldSequenceNo[0]));

    return true;
  }

  private final OnUpdate onUpdate_;
  private final FullPSync2017 fullPSync_;
  private final PSyncUserPrefixes prefixes_ = new PSyncUserPrefixes();
  private static final Logger logger_ = Logger.getLogger(FullPSync2017WithUsers.class.getName());
}
