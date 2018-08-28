/**
 * Copyright (C) 2015-2018 Regents of the University of California.
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

import java.nio.ByteBuffer;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.TimeZone;
import java.util.HashSet;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.tlv.Tlv;
import net.named_data.jndn.encoding.tlv.TlvDecoder;
import net.named_data.jndn.encoding.tlv.TlvEncoder;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

/**
 * Schedule is used to manage the times when a member can access data using two
 * sets of RepetitiveInterval as follows. whiteIntervalList is an ordered
 * set for the times a member is allowed to access to data, and
 * blackIntervalList is for the times a member is not allowed.
 * @note This class is an experimental feature. The API may change.
 */
public class Schedule {
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
   * Create a Schedule with empty whiteIntervalList and blackIntervalList.
   */
  public Schedule()
  {
  }

  /**
   * Create a Schedule, copying values from the given schedule.
   * @param schedule The Schedule to copy values from.
   */
  public Schedule(Schedule schedule)
  {
    // RepetitiveInterval is immutable, so we don't need to make a deep copy.
    whiteIntervalList_.addAll(schedule.whiteIntervalList_);
    blackIntervalList_.addAll(schedule.blackIntervalList_);
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
   * Get the interval that covers the time stamp. This iterates over the two
   * repetitive interval sets and find the shortest interval that allows a group
   * member to access the data. If there is no interval covering the time stamp,
   * this returns false for isPositive and returns a negative interval.
   * @param timeStamp The time stamp as milliseconds since Jan 1, 1970 UTC.
   * @return An object with fields (isPositive, interval) where isPositive is
   * true if the returned interval is positive or false if negative, and
   * interval is the Interval covering the time stamp, or a negative interval if
   * not found.
   */
  public final Result
  getCoveringInterval(double timeStamp)
  {
    Interval blackPositiveResult = new Interval(true);
    Interval whitePositiveResult = new Interval(true);

    Interval blackNegativeResult = new Interval();
    Interval whiteNegativeResult = new Interval();

    // Get the black result.
    calculateIntervalResult
      (blackIntervalList_, timeStamp, blackPositiveResult, blackNegativeResult);

    // If the black positive result is not empty, then isPositive must be false.
    if (!blackPositiveResult.isEmpty())
      return new Result(false, blackPositiveResult);

    // Get the whiteResult.
    calculateIntervalResult
      (whiteIntervalList_, timeStamp, whitePositiveResult, whiteNegativeResult);

    if (whitePositiveResult.isEmpty() && !whiteNegativeResult.isValid()) {
      // There is no white interval covering the time stamp.
      // Return false and a 24-hour interval.
      double timeStampDateOnly =
        RepetitiveInterval.toDateOnlyMilliseconds(timeStamp);
      return new Result
        (false, new Interval
         (timeStampDateOnly, timeStampDateOnly + MILLISECONDS_IN_DAY));
    }

    if (!whitePositiveResult.isEmpty()) {
      // There is white interval covering the time stamp.
      // Return true and calculate the intersection.
      if (blackNegativeResult.isValid())
        return new Result
          (true, whitePositiveResult.intersectWith(blackNegativeResult));
      else
        return new Result(true, whitePositiveResult);
    }
    else
      // There is no white interval covering the time stamp.
      // Return false.
      return new Result(false, whiteNegativeResult);
  }

  /**
   * Encode this Schedule.
   * @return The encoded buffer.
   */
  public final Blob
  wireEncode()
  {
    // For now, don't use WireFormat and hardcode to use TLV since the encoding
    // doesn't go out over the wire, only into the local SQL database.
    TlvEncoder encoder = new TlvEncoder(256);
    int saveLength = encoder.getLength();

    // Encode backwards.
    // Encode the blackIntervalList.
    int saveLengthForList = encoder.getLength();
    Object[] array = blackIntervalList_.toArray();
    Arrays.sort(array);
    for (int i = array.length - 1; i >= 0; --i) {
      RepetitiveInterval element = (RepetitiveInterval)array[i];
      encodeRepetitiveInterval(element, encoder);
    }
    encoder.writeTypeAndLength
      (Tlv.Encrypt_BlackIntervalList, encoder.getLength() - saveLengthForList);

    // Encode the whiteIntervalList.
    saveLengthForList = encoder.getLength();
    array = whiteIntervalList_.toArray();
    Arrays.sort(array);
    for (int i = array.length - 1; i >= 0; --i) {
      RepetitiveInterval element = (RepetitiveInterval)array[i];
      encodeRepetitiveInterval(element, encoder);
    }
    encoder.writeTypeAndLength
      (Tlv.Encrypt_WhiteIntervalList, encoder.getLength() - saveLengthForList);

    encoder.writeTypeAndLength
      (Tlv.Encrypt_Schedule, encoder.getLength() - saveLength);

    return new Blob(encoder.getOutput(), false);
  }

  /**
   * Decode the input and update this Schedule object.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(ByteBuffer input) throws EncodingException
  {
    // For now, don't use WireFormat and hardcode to use TLV since the encoding
    // doesn't go out over the wire, only into the local SQL database.
    TlvDecoder decoder = new TlvDecoder(input);

    int endOffset = decoder.readNestedTlvsStart(Tlv.Encrypt_Schedule);

    // Decode the whiteIntervalList.
    whiteIntervalList_.clear();
    int listEndOffset = decoder.readNestedTlvsStart(Tlv.Encrypt_WhiteIntervalList);
    while (decoder.getOffset() < listEndOffset)
      whiteIntervalList_.add(decodeRepetitiveInterval(decoder));
    decoder.finishNestedTlvs(listEndOffset);

    // Decode the blackIntervalList.
    blackIntervalList_.clear();
    listEndOffset = decoder.readNestedTlvsStart(Tlv.Encrypt_BlackIntervalList);
    while (decoder.getOffset() < listEndOffset)
      blackIntervalList_.add(decodeRepetitiveInterval(decoder));
    decoder.finishNestedTlvs(listEndOffset);

    decoder.finishNestedTlvs(endOffset);
  }

  /**
   * Decode the input and update this Schedule object.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(Blob input) throws EncodingException
  {
    wireDecode(input.buf());
  }

  /**
   * Encode the RepetitiveInterval as NDN-TLV to the encoder.
   * @param repetitiveInterval The RepetitiveInterval to encode.
   * @param encoder The TlvEncoder to receive the encoding.
   */
  private static void
  encodeRepetitiveInterval
    (RepetitiveInterval repetitiveInterval, TlvEncoder encoder)
  {
    int saveLength = encoder.getLength();

    // Encode backwards.
    encoder.writeNonNegativeIntegerTlv
      (Tlv.Encrypt_RepeatUnit,
       RepetitiveInterval.getRepeatUnitNumericType(repetitiveInterval.getRepeatUnit()));
    encoder.writeNonNegativeIntegerTlv
      (Tlv.Encrypt_NRepeats, repetitiveInterval.getNRepeats());
    encoder.writeNonNegativeIntegerTlv
      (Tlv.Encrypt_IntervalEndHour, repetitiveInterval.getIntervalEndHour());
    encoder.writeNonNegativeIntegerTlv
      (Tlv.Encrypt_IntervalStartHour, repetitiveInterval.getIntervalStartHour());
    // Use Blob to convert the string to UTF8 encoding.
    encoder.writeBlobTlv(Tlv.Encrypt_EndDate,
      new Blob(toIsoString(repetitiveInterval.getEndDate())).buf());
    encoder.writeBlobTlv(Tlv.Encrypt_StartDate,
      new Blob(toIsoString(repetitiveInterval.getStartDate())).buf());

    encoder.writeTypeAndLength
      (Tlv.Encrypt_RepetitiveInterval, encoder.getLength() - saveLength);
  }

  /**
   * Decode the input as an NDN-TLV RepetitiveInterval.
   * @param decoder The decoder with the input to decode.
   * @return A new RepetitiveInterval with the decoded result.
   */
  private static RepetitiveInterval
  decodeRepetitiveInterval(TlvDecoder decoder) throws EncodingException
  {
    int endOffset = decoder.readNestedTlvsStart(Tlv.Encrypt_RepetitiveInterval);

    // Use Blob to convert UTF8 to a string.
    double startDate = fromIsoString
      (new Blob(decoder.readBlobTlv(Tlv.Encrypt_StartDate), true).toString());
    double endDate = fromIsoString
      (new Blob(decoder.readBlobTlv(Tlv.Encrypt_EndDate), true).toString());
    int startHour = (int)decoder.readNonNegativeIntegerTlv
      (Tlv.Encrypt_IntervalStartHour);
    int endHour = (int)decoder.readNonNegativeIntegerTlv
      (Tlv.Encrypt_IntervalEndHour);
    int nRepeats = (int)decoder.readNonNegativeIntegerTlv(Tlv.Encrypt_NRepeats);

    int repeatUnitCode = (int)decoder.readNonNegativeIntegerTlv
      (Tlv.Encrypt_RepeatUnit);
    RepetitiveInterval.RepeatUnit repeatUnit;
    if (repeatUnitCode == Tlv.Encrypt_RepeatUnit_NONE)
      repeatUnit = RepetitiveInterval.RepeatUnit.NONE;
    else if (repeatUnitCode == Tlv.Encrypt_RepeatUnit_DAY)
      repeatUnit = RepetitiveInterval.RepeatUnit.DAY;
    else if (repeatUnitCode == Tlv.Encrypt_RepeatUnit_MONTH)
      repeatUnit = RepetitiveInterval.RepeatUnit.MONTH;
    else if (repeatUnitCode == Tlv.Encrypt_RepeatUnit_YEAR)
      repeatUnit = RepetitiveInterval.RepeatUnit.YEAR;
    else
      throw new EncodingException
        ("Unrecognized RepetitiveInterval RepeatUnit code: " + repeatUnitCode);

    decoder.finishNestedTlvs(endOffset);
    return new RepetitiveInterval
      (startDate, endDate, startHour, endHour, nRepeats, repeatUnit);
  }

  /**
   * A helper function to calculate black interval results or white interval
   * results.
   * @param list The set of RepetitiveInterval, which can be the white list or
   * the black list.
   * @param timeStamp The time stamp as milliseconds since Jan 1, 1970 UTC.
   * @param positiveResult The positive result which is updated.
   * @param negativeResult The negative result which is updated.
   */
  private static void
  calculateIntervalResult
    (HashSet<RepetitiveInterval> list, double timeStamp, Interval positiveResult,
     Interval negativeResult)
  {
    Object[] array = list.toArray();
    Arrays.sort(array);
    for (Object elementObj : array) {
      RepetitiveInterval element = (RepetitiveInterval)elementObj;

      RepetitiveInterval.Result result = element.getInterval(timeStamp);
      Interval tempInterval = result.interval;
      if (result.isPositive == true) {
        try {
          positiveResult.unionWith(tempInterval);
        } catch (Interval.Error ex) {
          // We don't expect to get this error.
          throw new Error("Error in Interval.unionWith: " + ex.getMessage());
        }
      }
      else {
        if (!negativeResult.isValid())
          negativeResult.set(tempInterval);
        else
          negativeResult.intersectWith(tempInterval);
      }
    }
  }

  public static double
  fromIsoString(String dateString) throws EncodingException
  {
    try {
      return (double)Common.dateToMillisecondsSince1970
        (dateFormat.parse(dateString));
    } catch (ParseException ex) {
      throw new EncodingException("Cannot parse date string " + dateString);
    }
  }

  public static String
  toIsoString(double msSince1970)
  {
    return dateFormat.format
      (Common.millisecondsSince1970ToDate((long)Math.round(msSince1970)));
  }

  private static SimpleDateFormat
  getDateFormat()
  {
    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd'T'HHmmss");
    dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    return dateFormat;
  }

  private final HashSet<RepetitiveInterval> whiteIntervalList_ = new HashSet<RepetitiveInterval>();
  private final HashSet<RepetitiveInterval> blackIntervalList_ = new HashSet<RepetitiveInterval>();
  private static final SimpleDateFormat dateFormat = getDateFormat();
  private static final long MILLISECONDS_IN_DAY = 24 * 3600 * 1000;
}
