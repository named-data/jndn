/**
 * Copyright (C) 2015-2018 Regents of the University of California.
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
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Face;
import net.named_data.jndn.Interest;
import net.named_data.jndn.InterestFilter;
import net.named_data.jndn.OnInterestCallback;
import net.named_data.jndn.util.Common;

/**
 * An InterestFilterTable is an internal class to hold a list of entries with
 * an interest Filter and its OnInterestCallback.
 */
public class InterestFilterTable {
  /**
   * An Entry holds an interestFilterId, an InterestFilter and the
   * OnInterestCallback with its related Face.
   */
  public static class Entry {
    /**
     * Create a new Entry with the given values.
     * @param interestFilterId The ID from Node.getNextEntryId().
     * @param filter The InterestFilter for this entry.
     * @param onInterest The callback to call.
     * @param face The face on which was called registerPrefix or
     * setInterestFilter which is passed to the onInterest callback.
     */
    public Entry
      (long interestFilterId, InterestFilter filter,
       OnInterestCallback onInterest, Face face)
    {
      interestFilterId_ = interestFilterId;
      filter_ = filter;
      onInterest_ = onInterest;
      face_ = face;
    }

    /**
     * Get the interestFilterId given to the constructor.
     * @return The interestFilterId.
     */
    public final long
    getInterestFilterId() { return interestFilterId_; }

    /**
     * Get the InterestFilter given to the constructor.
     * @return The InterestFilter.
     */
    public final InterestFilter
    getFilter() { return filter_; }

    /**
     * Get the OnInterestCallback given to the constructor.
     * @return The OnInterestCallback.
     */
    public final OnInterestCallback
    getOnInterest() { return onInterest_; }

    /**
     * Get the Face given to the constructor.
     * @return The Face.
     */
    public final Face
    getFace() { return face_; }

    private final long interestFilterId_; /**< A unique identifier for this entry so it can be deleted */
    private final InterestFilter filter_;
    private final OnInterestCallback onInterest_;
    private final Face face_;
  }

  /**
   * Add a new entry to the table.
   * @param interestFilterId The ID from Node.getNextEntryId().
   * @param filter The InterestFilter for this entry.
   * @param onInterest The callback to call.
   * @param face The face on which was called registerPrefix or
   * setInterestFilter which is passed to the onInterest callback.
   */
  public synchronized final void
  setInterestFilter(long interestFilterId, InterestFilter filter,
       OnInterestCallback onInterest, Face face)
  {
    table_.add(new Entry(interestFilterId, filter, onInterest, face));
  }

  /**
   * Find all entries from the interest filter table where the interest conforms
   * to the entry's filter, and add to the matchedFilters list.
   * @param interest The interest which may match the filter in multiple entries.
   * @param matchedFilters Add each matching InterestFilterTable.Entry from the
   * interest filter table.  The caller should pass in an empty ArrayList.
   */
  public synchronized final void
  getMatchedFilters(Interest interest, ArrayList matchedFilters)
  {
    for (int i = 0; i < table_.size(); ++i) {
      Entry entry = table_.get(i);
      if (entry.getFilter().doesMatch(interest.getName()))
        matchedFilters.add(entry);
    }
  }

  /**
   * Remove the interest filter entry which has the interestFilterId from the
   * interest filter table. This does not affect another interest filter with
   * a different interestFilterId, even if it has the same prefix name.
   * If there is no entry with the interestFilterId, do nothing.
   * @param interestFilterId The ID returned from setInterestFilter.
   */
  public synchronized final void
  unsetInterestFilter(long interestFilterId)
  {
    int count = 0;
    // Go backwards through the list so we can remove entries.
    // Remove all entries even though interestFilterId should be unique.
    for (int i = table_.size() - 1; i >= 0; --i) {
      if ((table_.get(i)).getInterestFilterId() == interestFilterId) {
        ++count;
        table_.remove(i);
      }
    }

    if (count == 0)
      logger_.log
        (Level.WARNING, "unsetInterestFilter: Didn't find interestFilterId {0}",
         interestFilterId);
  }

  private final ArrayList<Entry> table_ = new ArrayList<Entry>();
  private static final Logger logger_ = Logger.getLogger
    (InterestFilterTable.class.getName());
  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
