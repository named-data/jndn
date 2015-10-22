/**
 * Copyright (C) 2015 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/schedule.t.cpp
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

package net.named_data.jndn.tests.unit_tests;

import java.nio.ByteBuffer;
import java.text.ParseException;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encrypt.Interval;
import net.named_data.jndn.encrypt.RepetitiveInterval;
import net.named_data.jndn.encrypt.Schedule;
import net.named_data.jndn.util.Blob;
import static net.named_data.jndn.tests.unit_tests.UnitTestsCommon.toIsoString;
import static net.named_data.jndn.tests.unit_tests.UnitTestsCommon.fromIsoString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.Test;

public class TestSchedule {
  @Test
  public void
  testCalculateCoveringInterval() throws ParseException
  {
    Schedule schedule = new Schedule();

    RepetitiveInterval interval1 = new RepetitiveInterval
      (fromIsoString("20150825T000000"),
       fromIsoString("20150827T000000"), 5, 10, 2, RepetitiveInterval.RepeatUnit.DAY);
    RepetitiveInterval interval2 = new RepetitiveInterval
      (fromIsoString("20150825T000000"),
       fromIsoString("20150827T000000"), 6, 8, 1, RepetitiveInterval.RepeatUnit.DAY);
    RepetitiveInterval interval3 = new RepetitiveInterval
      (fromIsoString("20150827T000000"),
       fromIsoString("20150827T000000"), 7, 8);
    RepetitiveInterval interval4 = new RepetitiveInterval
      (fromIsoString("20150825T000000"),
       fromIsoString("20150825T000000"), 4, 7);

    schedule.addWhiteInterval(interval1);
    schedule.addWhiteInterval(interval2);
    schedule.addWhiteInterval(interval4);
    schedule.addBlackInterval(interval3);

    Interval resultInterval;
    boolean[] isPositive = { false };

    // timePoint1 --> positive 8.25 4-10
    double timePoint1 = fromIsoString("20150825T063000");
    resultInterval = schedule.getCoveringInterval(timePoint1, isPositive);
    assertEquals(true, isPositive[0]);
    assertEquals("20150825T040000", toIsoString(resultInterval.getStartTime()));
    assertEquals("20150825T100000", toIsoString(resultInterval.getEndTime()));

    // timePoint2 --> positive 8.26 6-8
    double timePoint2 = fromIsoString("20150826T073000");
    resultInterval = schedule.getCoveringInterval(timePoint2, isPositive);
    assertEquals(true, isPositive[0]);
    assertEquals("20150826T060000", toIsoString(resultInterval.getStartTime()));
    assertEquals("20150826T080000", toIsoString(resultInterval.getEndTime()));

    // timePoint3 --> positive 8.27 5-7
    double timePoint3 = fromIsoString("20150827T053000");
    resultInterval = schedule.getCoveringInterval(timePoint3, isPositive);
    assertEquals(true, isPositive[0]);
    assertEquals("20150827T050000", toIsoString(resultInterval.getStartTime()));
    assertEquals("20150827T070000", toIsoString(resultInterval.getEndTime()));

    // timePoint4 --> positive 8.27 5-7
    double timePoint4 = fromIsoString("20150827T063000");
    resultInterval = schedule.getCoveringInterval(timePoint4, isPositive);
    assertEquals(true, isPositive[0]);
    assertEquals("20150827T050000", toIsoString(resultInterval.getStartTime()));
    assertEquals("20150827T070000", toIsoString(resultInterval.getEndTime()));

    // timePoint5 --> negative 8.27 7-8
    double timePoint5 = fromIsoString("20150827T073000");
    resultInterval = schedule.getCoveringInterval(timePoint5, isPositive);
    assertEquals(false, isPositive[0]);
    assertEquals(false, resultInterval.isEmpty());
    assertEquals("20150827T070000", toIsoString(resultInterval.getStartTime()));
    assertEquals("20150827T080000", toIsoString(resultInterval.getEndTime()));

    // timePoint6 --> negative 8.25 10-24
    double timePoint6 = fromIsoString("20150825T113000");
    resultInterval = schedule.getCoveringInterval(timePoint6, isPositive);
    assertEquals(false, isPositive[0]);
    assertEquals(false, resultInterval.isEmpty());
    assertEquals("20150825T100000", toIsoString(resultInterval.getStartTime()));
    assertEquals("20150826T000000", toIsoString(resultInterval.getEndTime()));
  }

  // Convert the int array to a ByteBuffer.
  public static ByteBuffer
  toBuffer(int[] array)
  {
    ByteBuffer result = ByteBuffer.allocate(array.length);
    for (int i = 0; i < array.length; ++i)
      result.put((byte)(array[i] & 0xff));

    result.flip();
    return result;
  }

  private static final ByteBuffer SCHEDULE = toBuffer(new int[] {
  0x8f, 0xc4,// Schedule
  0x8d, 0x90,// WhiteIntervalList
  /////
  0x8c, 0x2e, // RepetitiveInterval
    0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x04,
    0x89, 0x01,
      0x07,
    0x8a, 0x01,
      0x00,
    0x8b, 0x01,
      0x00,
  /////
  0x8c, 0x2e, // RepetitiveInterval
    0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x38, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x05,
    0x89, 0x01,
      0x0a,
    0x8a, 0x01,
      0x02,
    0x8b, 0x01,
      0x01,
  /////
  0x8c, 0x2e, // RepetitiveInterval
    0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x35, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x38, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x06,
    0x89, 0x01,
      0x08,
    0x8a, 0x01,
      0x01,
    0x8b, 0x01,
      0x01,
  /////
  0x8e, 0x30, // BlackIntervalList
  /////
  0x8c, 0x2e, // RepetitiveInterval
     0x86, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x37, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x87, 0x0f,
      0x32, 0x30, 0x31, 0x35, 0x30, 0x38, 0x32, 0x37, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x88, 0x01,
      0x07,
    0x89, 0x01,
      0x08,
    0x8a, 0x01,
      0x00,
    0x8b, 0x01,
      0x00
  });


  @Test
  public void
  testEncodeAndDecode() throws ParseException
  {
    Schedule schedule = new Schedule();

    RepetitiveInterval interval1 = new RepetitiveInterval
      (fromIsoString("20150825T000000"),
       fromIsoString("20150828T000000"), 5, 10, 2, RepetitiveInterval.RepeatUnit.DAY);
    RepetitiveInterval interval2 = new RepetitiveInterval
      (fromIsoString("20150825T000000"),
       fromIsoString("20150828T000000"), 6, 8, 1, RepetitiveInterval.RepeatUnit.DAY);
    RepetitiveInterval interval3 = new RepetitiveInterval
      (fromIsoString("20150827T000000"),
       fromIsoString("20150827T000000"), 7, 8);
    RepetitiveInterval interval4 = new RepetitiveInterval
      (fromIsoString("20150825T000000"),
       fromIsoString("20150825T000000"), 4, 7);

    schedule.addWhiteInterval(interval1);
    schedule.addWhiteInterval(interval2);
    schedule.addWhiteInterval(interval4);
    schedule.addBlackInterval(interval3);

    Blob encoding = schedule.wireEncode();
    Blob encoding2 = new Blob(SCHEDULE, false);
    assertTrue(encoding.equals(encoding2));

    Schedule schedule2 = new Schedule();
    try {
      schedule2.wireDecode(encoding);
    } catch (EncodingException ex) {
      fail("Error decoding Schedule: " + ex.getMessage());
    }
    Interval resultInterval;
    boolean[] isPositive = { false };

    // timePoint1 --> positive 8.25 4-10
    double timePoint1 = fromIsoString("20150825T063000");
    resultInterval = schedule.getCoveringInterval(timePoint1, isPositive);
    assertEquals(true, isPositive[0]);
    assertEquals("20150825T040000", toIsoString(resultInterval.getStartTime()));
    assertEquals("20150825T100000", toIsoString(resultInterval.getEndTime()));

    // timePoint2 --> positive 8.26 6-8
    double timePoint2 = fromIsoString("20150826T073000");
    resultInterval = schedule.getCoveringInterval(timePoint2, isPositive);
    assertEquals(true, isPositive[0]);
    assertEquals("20150826T060000", toIsoString(resultInterval.getStartTime()));
    assertEquals("20150826T080000", toIsoString(resultInterval.getEndTime()));
  }
}