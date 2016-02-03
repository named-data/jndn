/**
 * Copyright (C) 2015-2016 Regents of the University of California.
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

package net.named_data.jndn.impl;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.OnData;
import net.named_data.jndn.OnTimeout;

/**
 * A PendingInterestTable is an internal class to hold a list of pending
 * interests with their callbacks.
 */
public class PendingInterestTable {
  /**
   * Entry holds the callbacks and other fields for an entry in the pending
   * interest table.
   */
  public static class Entry {
    /**
     * Create a new Entry with the given fields. Note: You should not call this
     * directly but call PendingInterestTable.add.
     */
    public Entry
      (long pendingInterestId, Interest interest, OnData onData,
       OnTimeout onTimeout)
    {
      pendingInterestId_ = pendingInterestId;
      interest_ = interest;
      onData_ = onData;
      onTimeout_ = onTimeout;
    }

    /**
     * Get the pendingInterestId given to the constructor.
     * @return The pendingInterestId.
     */
    public final long
    getPendingInterestId() { return pendingInterestId_; }

    /**
     * Get the interest given to the constructor (from Face.expressInterest).
     * @return The interest. NOTE: You must not change the interest object - if
     * you need to change it then make a copy.
     */
    public final Interest
    getInterest() { return interest_; }

    /**
     * Get the OnData callback given to the constructor.
     * @return The OnData callback.
     */
    public final OnData
    getOnData() { return onData_; }

    /**
     * Set the isRemoved flag which is returned by getIsRemoved().
     */
    public final void
    setIsRemoved() { isRemoved_ = true; }

    /**
     * Check if setIsRemoved() was called.
     * @return True if setIsRemoved() was called.
     */
    public final boolean
    getIsRemoved() { return isRemoved_; }

    /**
     * Call onTimeout_ (if defined). This ignores exceptions from the
     * onTimeout_.
     */
    public final void
    callTimeout()
    {
      if (onTimeout_ != null) {
        try {
          onTimeout_.onTimeout(interest_);
        } catch (Throwable ex) {
          logger_.log(Level.SEVERE, null, ex);
        }
      }
    }

    private final Interest interest_;
    private final long pendingInterestId_; /**< A unique identifier for this entry so it can be deleted */
    private final OnData onData_;
    private final OnTimeout onTimeout_;
    private boolean isRemoved_ = false;
  }

  /**
   * Add a new entry to the pending interest table.
   * @param pendingInterestId The getNextEntryId() for the pending interest ID
   * which Face got so it could return it to the caller.
   * @param interestCopy The Interest to send, which has already been copied by
   * expressInterest.
   * @param onData  This calls onData.onData when a matching data packet is
   * received.
   * @param onTimeout This calls onTimeout.onTimeout if the interest times out.
   * If onTimeout is null, this does not use it.
   * @return The new PendingInterestTable.Entry.
   */
  public synchronized final Entry
  add(long pendingInterestId, Interest interestCopy, OnData onData,
       OnTimeout onTimeout)
  {
    Entry entry = new Entry(pendingInterestId, interestCopy, onData, onTimeout);
    table_.add(entry);
    return entry;
  }

  /**
   * Find all entries from the pending interest table where the name conforms to
   * the entry's interest selectors, remove the entries from the table, set each
   * entry's isRemoved flag, and add to the entries list.
   * @param name The name to find the interest for (from the incoming data
   * packet).
   * @param entries Add matching PendingInterestTable.Entry from the pending
   * interest table.  The caller should pass in an empty ArrayList.
   */
  public synchronized final void
  extractEntriesForExpressedInterest(Name name, ArrayList entries)
  {
    // Go backwards through the list so we can remove entries.
    for (int i = table_.size() - 1; i >= 0; --i) {
      Entry pendingInterest = (Entry)table_.get(i);

      if (pendingInterest.getInterest().matchesName(name)) {
        entries.add(table_.get(i));
        // We let the callback from callLater call _processInterestTimeout, but
        // for efficiency, mark this as removed so that it returns right away.
        table_.remove(i);
        pendingInterest.setIsRemoved();
      }
    }
  }

  /**
   * Remove the pending interest entry with the pendingInterestId from the
   * pending interest table and set its isRemoved flag. This does not affect
   * another pending interest with a different pendingInterestId, even if it has
   * the same interest name. If there is no entry with the pendingInterestId, do
   * nothing.
   * @param pendingInterestId The ID returned from expressInterest.
   */
  public synchronized final void
  removePendingInterest(long pendingInterestId)
  {
    int count = 0;
    // Go backwards through the list so we can remove entries.
    // Remove all entries even though pendingInterestId should be unique.
    for (int i = table_.size() - 1; i >= 0; --i) {
      if (((Entry)table_.get(i)).getPendingInterestId() == pendingInterestId) {
        ++count;
        // For efficiency, mark this as removed so that
        // processInterestTimeout doesn't look for it.
        ((Entry)table_.get(i)).setIsRemoved();
        table_.remove(i);
      }
    }

    if (count == 0)
      logger_.log
        (Level.WARNING, "removePendingInterest: Didn't find pendingInterestId {0}",
         pendingInterestId);
  }

  /**
   * Remove the specific pendingInterest entry from the table and set its
   * isRemoved flag. However, if the pendingInterest isRemoved flag is already
   * true or the entry is not in the pending interest table then do nothing.
   * @param pendingInterest The Entry from the pending interest table.
   * @return True if the entry was removed, false if not.
   */
  public synchronized final boolean
  removeEntry(Entry pendingInterest)
  {
    if (pendingInterest.getIsRemoved())
      // extractEntriesForExpressedInterest or removePendingInterest has
      // removed pendingInterest from the table, so we don't need to look for it.
      // Do nothing.
      return false;

    if (table_.remove(pendingInterest)) {
      pendingInterest.setIsRemoved();
      return true;
    }
    else
      return false;
  }

  // Use ArrayList without generics so it works with older Java compilers.
  private final List table_ = new ArrayList();  // Entry
  private static final Logger logger_ = Logger.getLogger
    (PendingInterestTable.class.getName());
}
