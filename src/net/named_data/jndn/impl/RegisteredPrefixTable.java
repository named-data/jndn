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
import net.named_data.jndn.Name;
import net.named_data.jndn.util.Common;

/**
 * A RegisteredPrefixTable is an internal class to hold a list of registered
 * prefixes with information necessary to remove the registration later.
 */
public class RegisteredPrefixTable {
  /**
   * Create a new RegisteredPrefixTable with an empty table.
   * @param interestFilterTable See removeRegisteredPrefix(), which may call
   * interestFilterTable.unsetInterestFilter().
   */
  public RegisteredPrefixTable(InterestFilterTable interestFilterTable)
  {
    interestFilterTable_ = interestFilterTable;
  }

  /**
   * Add a new entry to the table. However, if removeRegisteredPrefix was already
   * called with the registeredPrefixId, don't add an entry and return false.
   * @param registeredPrefixId The ID from Node.getNextEntryId().
   * @param prefix The name prefix.
   * @param relatedInterestFilterId (optional) The related interestFilterId
   * for the filter set in the same registerPrefix operation. If omitted, set
   * to 0.
   * @return True if added an entry, false if removeRegisteredPrefix was already
   * called with the registeredPrefixId.
   */
  public synchronized final boolean
  add(long registeredPrefixId, Name prefix, long relatedInterestFilterId)
  {
    int removeRequestIndex = removeRequests_.indexOf(registeredPrefixId);
    if (removeRequestIndex >= 0) {
      // removeRegisteredPrefix was called with the registeredPrefixId returned
      //   by registerPrefix before we got here, so don't add a registered
      //   prefix table entry.
      removeRequests_.remove(removeRequestIndex);
      return false;
    }

    table_.add(new Entry(registeredPrefixId, prefix, relatedInterestFilterId));
    return true;
  }

  /**
   * Remove the registered prefix entry with the registeredPrefixId from the
   * registered prefix table. This does not affect another registered prefix with
   * a different registeredPrefixId, even if it has the same prefix name. If an
   * interest filter was automatically created by registerPrefix, also call
   * interestFilterTable_.unsetInterestFilter to remove it.
   * If there is no entry with the registeredPrefixId, do nothing.
   * @param registeredPrefixId The ID returned from registerPrefix.
   */
  public synchronized final void
  removeRegisteredPrefix(long registeredPrefixId)
  {
    int count = 0;
    // Go backwards through the list so we can remove entries.
    // Remove all entries even though registeredPrefixId should be unique.
    for (int i = table_.size() - 1; i >= 0; --i) {
      Entry entry = table_.get(i);

      if (entry.getRegisteredPrefixId() == registeredPrefixId) {
        ++count;

        if (entry.getRelatedInterestFilterId() > 0)
          // Remove the related interest filter.
          interestFilterTable_.unsetInterestFilter
            (entry.getRelatedInterestFilterId());

        table_.remove(i);
      }
    }

    if (count == 0)
      logger_.log
        (Level.WARNING, "removeRegisteredPrefix: Didn't find registeredPrefixId {0}",
         registeredPrefixId);

    if (count == 0) {
      // The registeredPrefixId was not found. Perhaps this has been called before
      //   the callback in registerPrefix can add to the registered prefix table.
      //   Add this removal request which will be checked before adding to the
      //   registered prefix table.
      if (removeRequests_.indexOf(registeredPrefixId) < 0)
        // Not already requested, so add the request.
        removeRequests_.add(registeredPrefixId);
    }
  }

  /**
   * A RegisteredPrefixTable.Entry holds a registeredPrefixId and information
   * necessary to remove the registration later. It optionally holds a related
   * interestFilterId if the InterestFilter was set in the same registerPrefix
   * operation.
   */
  private static class Entry {
    /**
     * Create a RegisteredPrefixTable.Entry with the given values.
     * @param registeredPrefixId The ID from Node.getNextEntryId().
     * @param prefix The name prefix.
     * @param relatedInterestFilterId (optional) The related interestFilterId
     * for the filter set in the same registerPrefix operation. If omitted, set
     * to 0.
     */
    public Entry
      (long registeredPrefixId, Name prefix, long relatedInterestFilterId)
    {
      registeredPrefixId_ = registeredPrefixId;
      prefix_ = prefix;
      relatedInterestFilterId_ = relatedInterestFilterId;
    }

    /**
     * Get the registeredPrefixId given to the constructor.
     * @return The registeredPrefixId.
     */
    public final long
    getRegisteredPrefixId() { return registeredPrefixId_; }

    /**
     * Get the name prefix given to the constructor.
     * @return The name prefix.
     */
    public final Name
    getPrefix() { return prefix_; }

    /**
     * Get the related interestFilterId given to the constructor.
     * @return The related interestFilterId.
     */
    public final long
    getRelatedInterestFilterId() { return relatedInterestFilterId_; }

    private final long registeredPrefixId_; /**< A unique identifier for this entry so it can be deleted */
    private final Name prefix_;
    private final long relatedInterestFilterId_;
  }

  private final ArrayList<Entry> table_ = new ArrayList<Entry>();
  private final InterestFilterTable interestFilterTable_;
  private final ArrayList<Long> removeRequests_ = new ArrayList<Long>();
  private static final Logger logger_ = Logger.getLogger
    (RegisteredPrefixTable.class.getName());
  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
