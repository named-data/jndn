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

import java.nio.ByteBuffer;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Iterator;
import java.util.TimeZone;
import java.util.TreeSet;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.tlv.Tlv;
import net.named_data.jndn.encoding.tlv.TlvDecoder;
import net.named_data.jndn.encoding.tlv.TlvEncoder;
import net.named_data.jndn.util.Blob;

/**
 * Schedule is used to manage the times when a member can access data using two
 * sets of RepetitiveInterval as follows. whiteIntervalList is an ordered
 * set for the times a member is allowed to access to data, and
 * blackIntervalList is for the times a member is not allowed.
 * @note This class is an experimental feature. The API may change.
 */
public class Schedule {
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
    for (Iterator i = blackIntervalList_.descendingIterator(); i.hasNext(); ) {
      RepetitiveInterval element = (RepetitiveInterval)i.next();
      encodeRepetitiveInterval(element, encoder);
    }
    encoder.writeTypeAndLength
      (Tlv.Encrypt_BlackIntervalList, encoder.getLength() - saveLengthForList);

    // Encode the whiteIntervalList.
    saveLengthForList = encoder.getLength();
    for (Iterator i = whiteIntervalList_.descendingIterator(); i.hasNext(); ) {
      RepetitiveInterval element = (RepetitiveInterval)i.next();
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
      (Tlv.Encrypt_RepeatUnit, repetitiveInterval.getRepeatUnit().getNumericType());
    encoder.writeNonNegativeIntegerTlv
      (Tlv.Encrypt_NRepeats, repetitiveInterval.getNRepeats());
    encoder.writeNonNegativeIntegerTlv
      (Tlv.Encrypt_IntervalEndHour, repetitiveInterval.getIntervalEndHour());
    encoder.writeNonNegativeIntegerTlv
      (Tlv.Encrypt_IntervalStartHour, repetitiveInterval.getIntervalStartHour());
    // Use Blob to convert the string to UTF8 encoding.
    encoder.writeBlobTlv(Tlv.Encrypt_EndDate,
      new Blob(formatDate(repetitiveInterval.getEndDate())).buf());
    encoder.writeBlobTlv(Tlv.Encrypt_StartDate,
      new Blob(formatDate(repetitiveInterval.getStartDate())).buf());

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
    double startDate = parseDate
      (new Blob(decoder.readBlobTlv(Tlv.Encrypt_StartDate), true).toString());
    double endDate = parseDate
      (new Blob(decoder.readBlobTlv(Tlv.Encrypt_EndDate), true).toString());
    int startHour = (int)decoder.readNonNegativeIntegerTlv
      (Tlv.Encrypt_IntervalStartHour);
    int endHour = (int)decoder.readNonNegativeIntegerTlv
      (Tlv.Encrypt_IntervalEndHour);
    int nRepeats = (int)decoder.readNonNegativeIntegerTlv(Tlv.Encrypt_NRepeats);
    
    int repeatUnitCode = (int)decoder.readNonNegativeIntegerTlv
      (Tlv.Encrypt_RepeatUnit);
    RepetitiveInterval.RepeatUnit repeatUnit;
    if (repeatUnitCode == RepetitiveInterval.RepeatUnit.NONE.getNumericType())
      repeatUnit = RepetitiveInterval.RepeatUnit.NONE;
    else if (repeatUnitCode == RepetitiveInterval.RepeatUnit.DAY.getNumericType())
      repeatUnit = RepetitiveInterval.RepeatUnit.DAY;
    else if (repeatUnitCode == RepetitiveInterval.RepeatUnit.MONTH.getNumericType())
      repeatUnit = RepetitiveInterval.RepeatUnit.MONTH;
    else if (repeatUnitCode == RepetitiveInterval.RepeatUnit.YEAR.getNumericType())
      repeatUnit = RepetitiveInterval.RepeatUnit.YEAR;
    else
      throw new EncodingException
        ("Unrecognized RepetitiveInterval RepeatUnit code: " + repeatUnitCode);

    decoder.finishNestedTlvs(endOffset);
    return new RepetitiveInterval
      (startDate, endDate, startHour, endHour, nRepeats, repeatUnit);
  }

  private static double
  parseDate(String dateString) throws EncodingException
  {
    try {
      return (double)dateFormat.parse(dateString).getTime();
    } catch (ParseException ex) {
      throw new EncodingException("Cannot parse date string " + dateString);
    }
  }

  private static String
  formatDate(double msSince1970)
  {
    return dateFormat.format(new Date((long)Math.round(msSince1970)));
  }

  private static SimpleDateFormat
  getDateFormat()
  {
    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd'T'HHmmss");
    dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
    return dateFormat;
  }

  // Use TreeSet without generics so it works with older Java compilers.
  private final TreeSet whiteIntervalList_ = new TreeSet(); // of RepetitiveInterval
  private final TreeSet blackIntervalList_ = new TreeSet(); // of RepetitiveInterval
  private static final SimpleDateFormat dateFormat = getDateFormat();
}
