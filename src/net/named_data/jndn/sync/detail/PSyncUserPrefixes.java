/**
 * Copyright (C) 2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From the PSync library https://github.com/named-data/PSync/blob/master/PSync/detail/user-prefixes.cpp
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

package net.named_data.jndn.sync.detail;

import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Name;
import net.named_data.jndn.util.Common;

/**
 * PSyncUserPrefixes holds the prefixes_ map from prefix to sequence number,
 * used by PSyncPartialProducer and FullPSync2017WithUsers.
 */
public class PSyncUserPrefixes {
  /**
   * Check if the prefix is in prefixes_.
   *
   * @param prefix The prefix to check.
   * @return True if the prefix is in prefixes_.
   */
  public final boolean
  isUserNode(Name prefix)
  {
    return prefixes_.containsKey(prefix);
  }

  /**
   * Return the current sequence number of the given prefix.
   * @param prefix The prefix for the sequence number.
   * @return The sequence number for the prefix, or -1 if not found.
   */
  public final int
  getSequenceNo(Name prefix)
  {
    Object sequenceNo = prefixes_.get(prefix);
    if (sequenceNo == null)
      return -1;

    return (int)sequenceNo;
  }

  /**
   * Return the current sequence number of the given prefix, or zero if not found.
   * @param prefix The prefix for the sequence number.
   * @return The sequence number for the prefix, or 0 if not found.
   */
  public final int
  getSequenceNoOrZero(Name prefix)
  {
    Object sequenceNo = prefixes_.get(prefix);
    if (sequenceNo == null)
      return 0;

    return (int)sequenceNo;
  }

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
  addUserNode(Name prefix)
  {
    if (!isUserNode(prefix)) {
      prefixes_.put(prefix, 0);
      return true;
    }
    else
      return false;
  }

  /**
   * Remove the user node from synchronization. If the prefix is not in
   * prefixes_, then do nothing.
   * The caller should first check isUserNode(prefix) and erase the prefix from
   * the IBLT and other maps if needed.
   * @param prefix The prefix Name of the user node to be removed.
   */
  public final void
  removeUserNode(Name prefix)
  {
    prefixes_.remove(prefix);
  }

  /**
   * Update prefixes_ with the given prefix and sequence number. This does not
   * update the IBLT. This logs a message for the update.
   * Whoever calls this needs to make sure that isUserNode(prefix) is true.
   * @param prefix The prefix of the update.
   * @param sequenceNo The sequence number of the update.
   * @param oldSequenceNo This sets oldSequenceNo[0] to the old sequence number
   * for the prefix. If this method returns true and oldSequenceNo[0] is not
   * zero, the caller can remove the old prefix from the IBLT.
   * @return True if the sequence number was updated, false if the prefix was
   * not in prefixes_, or if the sequenceNo is less than or equal to the old
   * sequence number. If this returns false, the caller should not update the
   * IBLT.
   */
  public final boolean
  updateSequenceNo(Name prefix, int sequenceNo, int[] oldSequenceNo)
  {
    oldSequenceNo[0] = 0;
    logger_.log(Level.FINE, "updateSequenceNo: {0} " + sequenceNo, prefix);

    Object entrySequenceNo = prefixes_.get(prefix);
    if (entrySequenceNo != null)
      oldSequenceNo[0] = (int)entrySequenceNo;
    else {
      logger_.log(Level.INFO, "The prefix was not found in prefixes_");
      return false;
    }

    if (oldSequenceNo[0] >= sequenceNo) {
      logger_.log(Level.INFO,
        "The update has a lower/equal sequence number for the prefix. Doing nothing!");
      return false;
    }

    // Insert the new sequence number.
    prefixes_.put(prefix, sequenceNo);
    return true;
  }

  // The key is the prefix Name. The value is the sequence number for the prefix.
  public final HashMap<Name, Object> prefixes_ = new HashMap<Name, Object>();
  private static final Logger logger_ = Logger.getLogger(PSyncUserPrefixes.class.getName());
  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
