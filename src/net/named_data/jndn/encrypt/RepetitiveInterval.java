/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/repetitive-interval https://github.com/named-data/ndn-group-encrypt
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

import java.util.Calendar;
import java.util.TimeZone;

/**
 * A RepetitiveInterval is an advanced interval which can repeat and can be used
 * to find a simple Interval that a time point falls in.
 * @note This class is an experimental feature. The API may change.
 */
public class RepetitiveInterval implements Comparable {
  public enum RepeatUnit {
    NONE, DAY, MONTH, YEAR
  }

  /**
   * Get the numeric value associated with the repeatUnit. This is a separate
   * method for portability.
   * @param repeatUnit The RepeatUnit.
   * @return The numeric value for repeatUnit.
   */
  public static final int
  getRepeatUnitNumericType(RepeatUnit repeatUnit)
  {
    if (repeatUnit == RepeatUnit.DAY)
      return 1;
    else if (repeatUnit == RepeatUnit.MONTH)
      return 2;
    else if (repeatUnit == RepeatUnit.YEAR)
      return 3;
    else
      return 0;
  }

  public static class Result {
    public Result(boolean isPositive, Interval interval)
    {
      this.isPositive = isPositive;
      this.interval = interval;
    }

    public boolean isPositive;
    public Interval interval;
  }

  /**
   * Create a default RepetitiveInterval with one day duration, non-repeating.
   */
  public RepetitiveInterval()
  {
    startDate_ = -Double.MAX_VALUE;
    endDate_ = -Double.MAX_VALUE;
    intervalStartHour_ = 0;
    intervalEndHour_ = 24;
    nRepeats_ = 0;
    repeatUnit_ = RepeatUnit.NONE;
  }

  /**
   * Create a RepetitiveInterval with the given values. startDate must be
   * earlier than or same as endDate. intervalStartHour must be less than
   * intervalEndHour.
   * @param startDate The start date as milliseconds since Jan 1, 1970 UTC.
   * @param endDate The end date as milliseconds since Jan 1, 1970 UTC.
   * @param intervalStartHour The start hour in the day, from 0 to 23.
   * @param intervalEndHour The end hour in the day from 1 to 24.
   * @param nRepeats Repeat the interval nRepeats repetitions, every unit, until
   * endDate.
   * @param repeatUnit The unit of the repetition. If this is NONE, then
   * startDate must equal endDate.
   * @throws Error if the above conditions are not met.
   */
  public RepetitiveInterval
    (double startDate, double endDate, int intervalStartHour,
     int intervalEndHour, int nRepeats, RepeatUnit repeatUnit)
  {
    startDate_ = toDateOnlyMilliseconds(startDate);
    endDate_ = toDateOnlyMilliseconds(endDate);
    intervalStartHour_ = intervalStartHour;
    intervalEndHour_ = intervalEndHour;
    nRepeats_ = nRepeats;
    repeatUnit_ = repeatUnit;

    validate();
  }

  /**
   * Create a RepetitiveInterval with the given values, and no repetition.
   * Because there is no repetition, startDate must equal endDate.
   * intervalStartHour must be less than intervalEndHour.
   * @param startDate The start date as milliseconds since Jan 1, 1970 UTC.
   * @param endDate The end date as milliseconds since Jan 1, 1970 UTC.
   * @param intervalStartHour The start hour in the day, from 0 to 23.
   * @param intervalEndHour The end hour in the day from 1 to 24.
   * @throws Error if the above conditions are not met.
   */
  public RepetitiveInterval
    (double startDate, double endDate, int intervalStartHour,
     int intervalEndHour)
  {
    startDate_ = toDateOnlyMilliseconds(startDate);
    endDate_ = toDateOnlyMilliseconds(endDate);
    intervalStartHour_ = intervalStartHour;
    intervalEndHour_ = intervalEndHour;
    nRepeats_ = 0;
    repeatUnit_ = RepeatUnit.NONE;

    validate();
  }

  /**
   * Create a RepetitiveInterval, copying values from the given repetitiveInterval.
   * @param repetitiveInterval The RepetitiveInterval to copy values from.
   */
  public RepetitiveInterval(RepetitiveInterval repetitiveInterval)
  {
    startDate_ = repetitiveInterval.startDate_;
    endDate_ = repetitiveInterval.endDate_;
    intervalStartHour_ = repetitiveInterval.intervalStartHour_;
    intervalEndHour_ = repetitiveInterval.intervalEndHour_;
    nRepeats_ = repetitiveInterval.nRepeats_;
    repeatUnit_ = repetitiveInterval.repeatUnit_;
  }

  private void
  validate()
  {
    if (!(intervalStartHour_ < intervalEndHour_))
      throw new Error("ReptitiveInterval: startHour must be less than endHour");
    if (!(startDate_ <= endDate_))
      throw new Error
        ("ReptitiveInterval: startDate must be earlier than or same as endDate");
    if (!(intervalStartHour_ >= 0))
      throw new Error("ReptitiveInterval: intervalStartHour must be non-negative");
    if (!(intervalEndHour_ >= 1 && intervalEndHour_ <= 24))
      throw new Error("ReptitiveInterval: intervalEndHour must be from 1 to 24");
    if (repeatUnit_ == RepeatUnit.NONE) {
      if (!(startDate_ == endDate_))
        throw new Error
          ("ReptitiveInterval: With RepeatUnit.NONE, startDate must equal endDate");
    }
  }

  /**
   * Get an interval that covers the time point. If there is no interval
   * covering the time point, this returns false for isPositive and returns a
   * negative interval.
   * @param timePoint The time point as milliseconds since Jan 1, 1970 UTC.
   * @return An object with fields (isPositive, interval) where isPositive is
   * true if the returned interval is positive or false if negative, and
   * interval is the Interval covering the time point or a negative interval if
   * not found.
   */
  public final Result
  getInterval(double timePoint)
  {
    boolean isPositive;
    double startTime;
    double endTime;

    if (!hasIntervalOnDate(timePoint)) {
      // There is no interval on the date of timePoint.
      startTime = toDateOnlyMilliseconds(timePoint);
      endTime = toDateOnlyMilliseconds(timePoint) + 24 * MILLISECONDS_IN_HOUR;
      isPositive = false;
    }
    else {
      // There is an interval on the date of timePoint.
      startTime =
        toDateOnlyMilliseconds(timePoint) + intervalStartHour_ * MILLISECONDS_IN_HOUR;
      endTime =
        toDateOnlyMilliseconds(timePoint) + intervalEndHour_ * MILLISECONDS_IN_HOUR;

      // check if in the time duration
      if (timePoint < startTime) {
        endTime = startTime;
        startTime = toDateOnlyMilliseconds(timePoint);
        isPositive = false;
      }
      else if (timePoint > endTime) {
        startTime = endTime;
        endTime = toDateOnlyMilliseconds(timePoint) + MILLISECONDS_IN_DAY;
        isPositive = false;
      }
      else
        isPositive = true;
    }

    return new Result(isPositive, new Interval(startTime, endTime));
  }

  /**
   * Compare this to the other RepetitiveInterval.
   * @param other The other RepetitiveInterval to compare to.
   * @return -1 if this is less than the other, 1 if greater and 0 if equal.
   */
  public final int
  compare(RepetitiveInterval other)
  {
    if (startDate_ < other.startDate_)
      return -1;
    if (startDate_ > other.startDate_)
      return 1;

    if (endDate_ < other.endDate_)
      return -1;
    if (endDate_ > other.endDate_)
      return 1;

    if (intervalStartHour_ < other.intervalStartHour_)
      return -1;
    if (intervalStartHour_ > other.intervalStartHour_)
      return 1;

    if (intervalEndHour_ < other.intervalEndHour_)
      return -1;
    if (intervalEndHour_ > other.intervalEndHour_)
      return 1;

    if (nRepeats_ < other.nRepeats_)
      return -1;
    if (nRepeats_ > other.nRepeats_)
      return 1;

    // Lastly, compare the repeat units.
    // Compare without using Integer.compare so it works in older Java compilers.
    if (getRepeatUnitNumericType(repeatUnit_) <
        getRepeatUnitNumericType(other.repeatUnit_))
      return -1;
    else if (getRepeatUnitNumericType(repeatUnit_) ==
             getRepeatUnitNumericType(other.repeatUnit_))
      return 0;
    else
      return 1;
  }

  public int
  compareTo(Object other) { return compare((RepetitiveInterval)other); }

  // Also include this version for portability.
  public int
  CompareTo(Object other) { return compare((RepetitiveInterval)other); }

  public boolean equals(Object other)
  {
    if (!(other instanceof RepetitiveInterval))
      return false;

    return compare((RepetitiveInterval)other) == 0;
  }

  public int hashCode() {
    int hash = 3;
    hash = 73 * hash + (int)
      (Double.doubleToLongBits(startDate_) ^ (Double.doubleToLongBits(startDate_) >>> 32));
    hash = 73 * hash + (int)
      (Double.doubleToLongBits(endDate_) ^ (Double.doubleToLongBits(endDate_) >>> 32));
    hash = 73 * hash + intervalStartHour_;
    hash = 73 * hash + intervalEndHour_;
    hash = 73 * hash + nRepeats_;
    hash = 73 * hash + getRepeatUnitNumericType(repeatUnit_);
    return hash;
  }

  /**
   * Get the start date.
   * @return The start date as milliseconds since Jan 1, 1970 UTC.
   */
  public final double
  getStartDate() { return startDate_; }

  /**
   * Get the end date.
   * @return The end date as milliseconds since Jan 1, 1970 UTC.
   */
  public final double
  getEndDate() { return endDate_; }

  /**
   * Get the interval start hour.
   * @return The interval start hour.
   */
  public final int
  getIntervalStartHour() { return intervalStartHour_; }

  /**
   * Get the interval end hour.
   * @return The interval end hour.
   */
  public final int
  getIntervalEndHour() { return intervalEndHour_; }

  /**
   * Get the number of repeats.
   * @return The number of repeats.
   */
  public final int
  getNRepeats() { return nRepeats_; }

  /**
   * Get the repeat unit.
   * @return The repeat unit.
   */
  public final RepeatUnit
  getRepeatUnit() { return repeatUnit_; }

  /**
   * Check if the date of the time point is in any interval.
   * @param timePoint The time point as milliseconds since Jan 1, 1970 UTC.
   * @return True if the date of the time point is in any interval.
   */
  private boolean
  hasIntervalOnDate(double timePoint)
  {
    double timePointDateMilliseconds = toDateOnlyMilliseconds(timePoint);

    if (timePointDateMilliseconds < startDate_ ||
        timePointDateMilliseconds > endDate_)
      return false;

    if (repeatUnit_ == RepeatUnit.NONE)
      return true;
    else if (repeatUnit_ == RepeatUnit.DAY) {
      long durationDays = (long)(timePointDateMilliseconds - startDate_) /
                          MILLISECONDS_IN_DAY;
      if (durationDays % nRepeats_ == 0)
        return true;
    }
    else {
      Calendar timePointDate = toCalendar(timePointDateMilliseconds);
      Calendar startDate = toCalendar(startDate_);

      if (repeatUnit_ == RepeatUnit.MONTH &&
               timePointDate.get(Calendar.DAY_OF_MONTH) ==
               startDate.get(Calendar.DAY_OF_MONTH)) {
        int yearDifference =
          timePointDate.get(Calendar.YEAR) - startDate.get(Calendar.YEAR);
        int monthDifference = 12 * yearDifference +
          timePointDate.get(Calendar.MONTH) - startDate.get(Calendar.MONTH);
        if (monthDifference % nRepeats_ == 0)
          return true;
      }
      else if (repeatUnit_ == RepeatUnit.YEAR &&
               timePointDate.get(Calendar.DAY_OF_MONTH) ==
                 startDate.get(Calendar.DAY_OF_MONTH) &&
               timePointDate.get(Calendar.MONTH) ==
                 startDate.get(Calendar.MONTH)) {
        int difference = timePointDate.get(Calendar.YEAR) -
          startDate.get(Calendar.YEAR);
        if (difference % nRepeats_ == 0)
          return true;
      }
    }

    return false;
  }

  /**
   * Return a time point on the beginning of the date (without hours, minutes, etc.)
   * @param timePoint The time point as milliseconds since Jan 1, 1970 UTC.
   * @return A time point as milliseconds since Jan 1, 1970 UTC.
   */
  public static double
  toDateOnlyMilliseconds(double timePoint)
  {
    long result = (long)Math.round(timePoint);
    result -= result % MILLISECONDS_IN_DAY;
    return result;
  }

  /**
   * Return a Calendar for the time point.
   * @param timePoint The time point as milliseconds since Jan 1, 1970 UTC.
   * @return The Calendar.
   */
  private static Calendar
  toCalendar(double timePoint)
  {
    Calendar result = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
    result.setTimeInMillis((long)timePoint);
    return result;
  }

  private static final long MILLISECONDS_IN_HOUR = 3600 * 1000;
  private static final long MILLISECONDS_IN_DAY = 24 * 3600 * 1000;
  private final double startDate_; // MillisecondsSince1970 UTC
  private final double endDate_;   // MillisecondsSince1970 UTC
  private final int intervalStartHour_;
  private final int intervalEndHour_;
  private final int nRepeats_;
  private final RepeatUnit repeatUnit_;
}
