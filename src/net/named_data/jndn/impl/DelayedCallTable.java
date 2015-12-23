/**
 * Copyright (C) 2015 Regents of the University of California.
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
import net.named_data.jndn.util.Common;

/**
 * DelayedCallTable is an internal class used by the Node implementation of
 * callLater to store callbacks and call them when they time out.
 */
public class DelayedCallTable {
  /**
   * Call callback.run() after the given delay. This adds to the delayed call
   * table which is used by callTimedOut().
   * @param delayMilliseconds The delay in milliseconds.
   * @param callback This calls callback.run() after the delay.
   */
  public synchronized final void
  callLater(double delayMilliseconds, Runnable callback)
  {
    Entry delayedCall = new Entry(delayMilliseconds, callback);
    // Insert into delayedCallTable_, sorted on delayedCall.getCallTime().
    // Search from the back since we expect it to go there.
    int i = table_.size() - 1;
    while (i >= 0) {
      if (((Entry)table_.get(i)).getCallTime() <= delayedCall.getCallTime())
        break;
      --i;
    }
    // Element i is the greatest less than or equal to
    // delayedCall.getCallTime(), so insert after it.
    table_.add(i + 1, delayedCall);
  }

  /**
   * Call and remove timed-out callback entries. Since callLater does a sorted
   * insert into the delayed call table, the check for timed-out entries is
   * quick and does not require searching the entire table. This synchronizes on
   * the delayed call table when checking it, but not when calling the callback.
   */
  public final void
  callTimedOut()
  {
    double now = Common.getNowMilliseconds();
    // delayedCallTable_ is sorted on _callTime, so we only need to process
    // the timed-out entries at the front, then quit.
    while (true) {
      Entry delayedCall;
      // Lock while we check and maybe pop the element at the front.
      synchronized(this) {
        if (table_.isEmpty())
          break;
        delayedCall = (Entry)table_.get(0);
        if (delayedCall.getCallTime() > now)
          // It is not time to call the entry at the front of the list, so finish.
          break;
        table_.remove(0);
      }

      // The lock on delayedCallTable_ is removed, so call the callback.
      delayedCall.callCallback();
    }
  }

  /**
   * Entry holds the callback and other fields for an entry in the delayed call
   * table.
   */
  private static class Entry {
    /**
     * Create a new DelayedCallTable.Entry and set the call time based on the
     * current time and the delayMilliseconds.
     * @param delayMilliseconds The delay in milliseconds.
     * @param callback This calls callback.run() after the delay.
     */
    public Entry(double delayMilliseconds, Runnable callback)
    {
      callback_ = callback;
      callTime_ = Common.getNowMilliseconds() + delayMilliseconds;
    }

    /**
     * Get the time at which the callback should be called.
     * @return The call time in milliseconds, similar to
     * Common.getNowMilliseconds().
     */
    public final double
    getCallTime() { return callTime_; }

    /**
     * Call the callback given to the constructor. This does not catch
     * exceptions.
     */
    public final void
    callCallback() { callback_.run(); }

    private final Runnable callback_;
    private final double callTime_;
  }

  // Use ArrayList without generics so it works with older Java compilers.
  private final List table_ = new ArrayList();  // Entry
  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
