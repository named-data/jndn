/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/interval https://github.com/named-data/ndn-group-encrypt
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

/**
 * An Interval defines a time duration which contains a start timestamp and an
 * end timestamp.
 * @note This class is an experimental feature. The API may change.
 */
public class Interval {
  /**
   * Interval.Error extends Exception for errors using Interval methods. Note
   * that even though this is called "Error" to be consistent with the other
   * libraries, it extends the Java Exception class, not Error.
   */
  public static class Error extends Exception {
    public Error(String message)
    {
      super(message);
    }
  }

  /**
   * Create an Interval that is either invalid or an empty interval.
   * @param isValid True to create a valid empty interval, false to create an
   * invalid interval.
   */
  public Interval(boolean isValid)
  {
    isValid_ = isValid;
    startTime_ = -Double.MAX_VALUE;
    endTime_ = -Double.MAX_VALUE;
  }

  /**
   * Create a valid Interval with the given start and end times. The start
   * time must be less than the end time. To create an empty interval (start
   * time equals end time), use the constructor Interval(true).
   * @param startTime The start time as milliseconds since Jan 1, 1970 UTC.
   * @param endTime The end time as milliseconds since Jan 1, 1970 UTC.
   */
  public Interval(double startTime, double endTime)
  {
    if (!(startTime < endTime))
      throw new java.lang.Error("Interval start time must be less than the end time");

    startTime_ = startTime;
    endTime_ = endTime;
    isValid_ = true;
  }

  /**
   * Create an Interval, copying values from the other interval.
   * @param interval The other Interval with values to copy
   */
  public Interval(Interval interval)
  {
    startTime_ = interval.startTime_;
    endTime_ = interval.endTime_;
    isValid_ = interval.isValid_;
  }

  /**
   * Create an Interval that is invalid.
   */
  public Interval()
  {
    isValid_ = false;
    startTime_ = -Double.MAX_VALUE;
    endTime_ = -Double.MAX_VALUE;
  }

  /**
   * Set this interval to have the same values as the other interval.
   * @param interval The other Interval with values to copy.
   */
  public void
  set(Interval interval)
  {
    startTime_ = interval.startTime_;
    endTime_ = interval.endTime_;
    isValid_ = interval.isValid_;
  }

  /**
   * Check if the time point is in this interval.
   * @param timePoint The time point to check as milliseconds since Jan 1, 1970 UTC.
   * @return True if timePoint is in this interval.
   */
  public final boolean
  covers(double timePoint)
  {
    if (!isValid_)
      throw new java.lang.Error("Interval.covers: This Interval is invalid");

    if (isEmpty())
      return false;
    else
      return startTime_ <= timePoint && timePoint < endTime_;
  }

  /**
   * Set this Interval to the intersection of this and the other interval.
   * This and the other interval should be valid but either can be empty.
   * @param interval The other Interval to intersect with.
   * @return This Interval.
   */
  public final Interval
  intersectWith(Interval interval)
  {
    if (!isValid_)
      throw new java.lang.Error("Interval.intersectWith: This Interval is invalid");
    if (!interval.isValid_)
      throw new java.lang.Error("Interval.intersectWith: The other Interval is invalid");

    if (isEmpty() || interval.isEmpty()) {
      // If either is empty, the result is empty.
      startTime_ = endTime_;
      return this;
    }

    if (startTime_ >= interval.endTime_ || endTime_ <= interval.startTime_) {
      // The two intervals don't have an intersection, so the result is empty.
      startTime_ = endTime_;
      return this;
    }

    // Get the start time.
    if (startTime_ <= interval.startTime_)
      startTime_ = interval.startTime_;

    // Get the end time.
    if (endTime_ > interval.endTime_)
      endTime_ = interval.endTime_;

    return this;
  }

  /**
   * Set this Interval to the union of this and the other interval.
   * This and the other interval should be valid but either can be empty.
   * This and the other interval should have an intersection. (Contiguous
   * intervals are not allowed.)
   * @param interval The other Interval to union with.
   * @return This Interval.
   * @throws Interval.Error if the two intervals do not have an intersection.
   */
  public final Interval
  unionWith(Interval interval) throws Interval.Error
  {
    if (!isValid_)
      throw new java.lang.Error("Interval.intersectWith: This Interval is invalid");
    if (!interval.isValid_)
      throw new java.lang.Error("Interval.intersectWith: The other Interval is invalid");

    if (isEmpty()) {
      // This interval is empty, so use the other.
      startTime_ = interval.startTime_;
      endTime_ = interval.endTime_;
      return this;
    }

    if (interval.isEmpty())
      // The other interval is empty, so keep using this one.
      return this;

    if (startTime_ >= interval.endTime_ || endTime_ <= interval.startTime_)
      throw new Interval.Error
        ("Interval.unionWith: The two intervals do not have an intersection");

    // Get the start time.
    if (startTime_ > interval.startTime_)
      startTime_ = interval.startTime_;

    // Get the end time.
    if (endTime_ < interval.endTime_)
      endTime_ = interval.endTime_;

    return this;
  }

  /**
   * Get the start time.
   * @return The start time as milliseconds since Jan 1, 1970 UTC.
   */
  public final double
  getStartTime()
  {
    if (!isValid_)
      throw new java.lang.Error("Interval.getStartTime: This Interval is invalid");
    return startTime_;
  }

  /**
   * Get the end time.
   * @return The end time as milliseconds since Jan 1, 1970 UTC.
   */
  public final double
  getEndTime()
  {
    if (!isValid_)
      throw new java.lang.Error("Interval.getEndTime: This Interval is invalid");
    return endTime_;
  }

  /**
   * Check if this Interval is valid.
   * @return True if this interval is valid, false if invalid.
   */
  public final boolean
  isValid() { return isValid_; }

  /**
   * Check if this Interval is empty.
   * @return True if this Interval is empty (start time equals end time), false
   * if not.
   */
  public final boolean
  isEmpty()
  {
    if (!isValid_)
      throw new java.lang.Error("Interval.isEmpty: This Interval is invalid");
    return startTime_ == endTime_;
  }

  private double startTime_; // MillisecondsSince1970 UTC
  private double endTime_;   // MillisecondsSince1970 UTC
  private boolean isValid_;
}
