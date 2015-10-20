/**
 * Copyright (C) 2015 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/schedule https://github.com/named-data/ndn-group-encrypt
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

package net.named_data.jndn.encrypt;

import java.util.Iterator;
import java.util.TreeSet;

/**
 * Schedule is used to manage the times when a member can access data using two
 * sets of RepetitiveInterval as follows. whiteIntervalList is an ordered
 * set for the times a member is allowed to access to data, and
 * blackIntervalList is for the times a member is not allowed.
 */
public class Schedule {
  /**
   * Create a Schedule with empty whiteIntervalList and blackIntervalList.
   */
  public Schedule()
  {
  }

  /**
   * Add the repetitiveInterval to the whiteIntervalList.
   * @param repetitiveInterval The RepetitiveInterval to add. If the list
   * already contains the same RepetitiveInterval, this does nothing.
   * @return This Schedule so you can chain calls to add.
   */
  public final Schedule
  addWhiteInterval(RepetitiveInterval repetitiveInterval)
  {
    // RepetitiveInterval is immutable, so we don't need to make a copy.
    whiteIntervalList_.add(repetitiveInterval);
    return this;
  }

  /**
   * Add the repetitiveInterval to the blackIntervalList.
   * @param repetitiveInterval The RepetitiveInterval to add. If the list
   * already contains the same RepetitiveInterval, this does nothing.
   * @return This Schedule so you can chain calls to add.
   */
  public final Schedule
  addBlackInterval(RepetitiveInterval repetitiveInterval)
  {
    // RepetitiveInterval is immutable, so we don't need to make a copy.
    blackIntervalList_.add(repetitiveInterval);
    return this;
  }

  /**
   * Get the interval that covers the time point. This iterates over the two
   * repetitive interval sets and find the shortest interval that allows a group
   * member to access the data. If there is no interval covering the time point,
   * this returns false for isPositive and returns a negative interval.
   * @param timePoint The time point as milliseconds since Jan 1, 1970 GMT.
   * @param isPositive Set isPositive[0] true if the returned interval is
   * positive, false if negative.
   * @return The interval covering the time point, or a negative interval if not
   * found.
   */
  public final Interval
  getCoveringInterval(double timePoint, boolean[] isPositive)
  {
    Interval blackPositiveResult = new Interval(true);
    Interval whitePositiveResult = new Interval(true);

    Interval blackNegativeResult = new Interval();
    Interval whiteNegativeResult = new Interval();

    boolean[] localIsPositive = { false };

    // Get the black result.
    for (Iterator i = blackIntervalList_.iterator(); i.hasNext(); ) {
      RepetitiveInterval element = (RepetitiveInterval)i.next();

      Interval tempInterval = element.getInterval(timePoint, localIsPositive);
      if (localIsPositive[0] == true)
        // tempInterval covers the time point, so union the black negative
        // result with it.
        // Get the union interval of all the black intervals covering the
        // time point.
        // Return false for isPositive and the union interval.
        blackPositiveResult.unionWith(tempInterval);
      else {
        // tempInterval does not cover the time point, so intersect the black
        // negative result with it.
        // Get the intersection interval of all the black intervals not covering
        // the time point.
        // Return true for isPositive if the white positive result is not empty,
        // false if it is empty.
        if (!blackNegativeResult.isValid())
          blackNegativeResult = tempInterval;
        else
          blackNegativeResult.intersectWith(tempInterval);
      }
    }

    // If the black positive result is not full, then isPositive must be false.
    if (!blackPositiveResult.isEmpty()) {
      isPositive[0] = false;
      return blackPositiveResult;
    }

    // Get the whiteResult.
    for (Iterator i = whiteIntervalList_.iterator(); i.hasNext(); ) {
      RepetitiveInterval element = (RepetitiveInterval)i.next();

      Interval tempInterval = element.getInterval(timePoint, localIsPositive);
      if (localIsPositive[0] == true)
        // tempInterval covers the time point, so union the white positive
        // result with it.
        // Get the union interval of all the white intervals covering the time
        // point.
        // Return true for isPositive.
        whitePositiveResult.unionWith(tempInterval);
      else {
        // tempInterval does not cover the time point, so intersect the white
        // negative result with it.
        // Get the intersection of all the white intervals not covering the time
        // point.
        // Return false for isPositive if the positive result is empty, or
        // true if it is not empty.
        if (!whiteNegativeResult.isValid())
          whiteNegativeResult = tempInterval;
        else
          whiteNegativeResult.intersectWith(tempInterval);
      }
    }

    // If the positive result is empty then return false for isPositive. If it
    // is not empty then return true for isPositive.
    if (!whitePositiveResult.isEmpty()) {
      isPositive[0] = true;
      return whitePositiveResult.intersectWith(blackNegativeResult);
    }
    else {
      isPositive[0] = false;
      return whiteNegativeResult;
    }
  }
  
  // Use TreeSet without generics so it works with older Java compilers.
  private final TreeSet whiteIntervalList_ = new TreeSet(); // of RepetitiveInterval
  private final TreeSet blackIntervalList_ = new TreeSet(); // of RepetitiveInterval
}
