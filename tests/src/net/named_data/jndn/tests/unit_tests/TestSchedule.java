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

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import net.named_data.jndn.encrypt.Interval;
import net.named_data.jndn.encrypt.RepetitiveInterval;
import net.named_data.jndn.encrypt.Schedule;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

public class TestSchedule {
  static SimpleDateFormat dateFormat = getDateFormat();

  private static SimpleDateFormat
  getDateFormat()
  {
    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd'T'HHmmss");
    dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
    return dateFormat;
  }

  static double parseDate(String dateString) throws ParseException
  {
    return (double)dateFormat.parse(dateString).getTime();
  }

  static String formatDate(double msSince1970)
  {
    return dateFormat.format(new Date((long)Math.round(msSince1970)));
  }

  @Test
  public void
  testCalculateCoveringInterval() throws ParseException
  {
    Schedule schedule = new Schedule();

    RepetitiveInterval interval1 = new RepetitiveInterval
      (parseDate("20150825T000000"),
       parseDate("20150827T000000"), 5, 10, 2, RepetitiveInterval.RepeatUnit.DAY);
    RepetitiveInterval interval2 = new RepetitiveInterval
      (parseDate("20150825T000000"),
       parseDate("20150827T000000"), 6, 8, 1, RepetitiveInterval.RepeatUnit.DAY);
    RepetitiveInterval interval3 = new RepetitiveInterval
      (parseDate("20150827T000000"),
       parseDate("20150827T000000"), 7, 8);
    RepetitiveInterval interval4 = new RepetitiveInterval
      (parseDate("20150825T000000"),
       parseDate("20150825T000000"), 4, 7);

    schedule.addWhiteInterval(interval1);
    schedule.addWhiteInterval(interval2);
    schedule.addWhiteInterval(interval4);
    schedule.addBlackInterval(interval3);

    Interval resultInterval;
    boolean[] isPositive = { false };

    // timePoint1 --> positive 8.25 4-10
    double timePoint1 = parseDate("20150825T063000");
    resultInterval = schedule.getCoveringInterval(timePoint1, isPositive);
    assertEquals(true, isPositive[0]);
    assertEquals("20150825T040000", formatDate(resultInterval.getStartTime()));
    assertEquals("20150825T100000", formatDate(resultInterval.getEndTime()));

    // timePoint2 --> positive 8.26 6-8
    double timePoint2 = parseDate("20150826T073000");
    resultInterval = schedule.getCoveringInterval(timePoint2, isPositive);
    assertEquals(true, isPositive[0]);
    assertEquals("20150826T060000", formatDate(resultInterval.getStartTime()));
    assertEquals("20150826T080000", formatDate(resultInterval.getEndTime()));

    // timePoint3 --> positive 8.27 5-7
    double timePoint3 = parseDate("20150827T053000");
    resultInterval = schedule.getCoveringInterval(timePoint3, isPositive);
    assertEquals(true, isPositive[0]);
    assertEquals("20150827T050000", formatDate(resultInterval.getStartTime()));
    assertEquals("20150827T070000", formatDate(resultInterval.getEndTime()));

    // timePoint4 --> positive 8.27 5-7
    double timePoint4 = parseDate("20150827T063000");
    resultInterval = schedule.getCoveringInterval(timePoint4, isPositive);
    assertEquals(true, isPositive[0]);
    assertEquals("20150827T050000", formatDate(resultInterval.getStartTime()));
    assertEquals("20150827T070000", formatDate(resultInterval.getEndTime()));

    // timePoint5 --> negative 8.27 7-8
    double timePoint5 = parseDate("20150827T073000");
    resultInterval = schedule.getCoveringInterval(timePoint5, isPositive);
    assertEquals(false, isPositive[0]);
    assertEquals(false, resultInterval.isEmpty());
    assertEquals("20150827T070000", formatDate(resultInterval.getStartTime()));
    assertEquals("20150827T080000", formatDate(resultInterval.getEndTime()));

    // timePoint6 --> negative 8.25 10-24
    double timePoint6 = parseDate("20150825T113000");
    resultInterval = schedule.getCoveringInterval(timePoint6, isPositive);
    assertEquals(false, isPositive[0]);
    assertEquals(false, resultInterval.isEmpty());
    assertEquals("20150825T100000", formatDate(resultInterval.getStartTime()));
    assertEquals("20150826T000000", formatDate(resultInterval.getEndTime()));
  }
}