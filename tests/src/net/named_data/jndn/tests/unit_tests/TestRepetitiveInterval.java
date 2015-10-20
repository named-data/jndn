/**
 * Copyright (C) 2015 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/repetitive-interval.t.cpp
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
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import net.named_data.jndn.encrypt.Interval;
import net.named_data.jndn.encrypt.RepetitiveInterval;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

public class TestRepetitiveInterval {
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
  testConstruction() throws ParseException
  {
    RepetitiveInterval repetitiveInterval1 = new RepetitiveInterval
      (parseDate("20150825T000000"), parseDate("20150825T000000"), 5, 10);
    assertEquals("20150825T000000", formatDate(repetitiveInterval1.getStartDate()));
    assertEquals("20150825T000000", formatDate(repetitiveInterval1.getEndDate()));
    assertEquals(5, repetitiveInterval1.getIntervalStartHour());
    assertEquals(10, repetitiveInterval1.getIntervalEndHour());

    RepetitiveInterval repetitiveInterval2 = new RepetitiveInterval
      (parseDate("20150825T000000"), parseDate("20150827T000000"), 5, 10, 1,
       RepetitiveInterval.RepeatUnit.DAY);

    assertEquals(1, repetitiveInterval2.getNRepeats());
    assertEquals
      (RepetitiveInterval.RepeatUnit.DAY, repetitiveInterval2.getRepeatUnit());

    RepetitiveInterval repetitiveInterval3 = new RepetitiveInterval
      (parseDate("20150825T000000"), parseDate("20151227T000000"), 5, 10, 2,
       RepetitiveInterval.RepeatUnit.MONTH);

    assertEquals(2, repetitiveInterval3.getNRepeats());
    assertEquals
      (RepetitiveInterval.RepeatUnit.MONTH, repetitiveInterval3.getRepeatUnit());

    RepetitiveInterval repetitiveInterval4 = new RepetitiveInterval
      (parseDate("20150825T000000"), parseDate("20301227T000000"), 5, 10, 5,
       RepetitiveInterval.RepeatUnit.YEAR);

    assertEquals(5, repetitiveInterval4.getNRepeats());
    assertEquals
      (RepetitiveInterval.RepeatUnit.YEAR, repetitiveInterval4.getRepeatUnit());

    RepetitiveInterval repetitiveInterval5 = new RepetitiveInterval();

    assertEquals(0, repetitiveInterval5.getNRepeats());
    assertEquals
      (RepetitiveInterval.RepeatUnit.NONE, repetitiveInterval5.getRepeatUnit());
  }

  @Test
  public void
  testCoverTimePoint() throws ParseException
  {
    ///////////////////////////////////////////// With the repeat unit DAY.

    RepetitiveInterval repetitiveInterval1 = new RepetitiveInterval
      (parseDate("20150825T000000"), parseDate("20150925T000000"), 5, 10, 2,
       RepetitiveInterval.RepeatUnit.DAY);
    Interval resultInterval;
    boolean[] isPositive = { false };

    double timePoint1 = parseDate("20150825T050000");

    resultInterval = repetitiveInterval1.getInterval(timePoint1, isPositive);
    assertEquals(true, isPositive[0]);
    assertEquals("20150825T050000", formatDate(resultInterval.getStartTime()));
    assertEquals("20150825T100000", formatDate(resultInterval.getEndTime()));

    double timePoint2 = parseDate("20150902T060000");

    resultInterval = repetitiveInterval1.getInterval(timePoint2, isPositive);
    assertEquals(true, isPositive[0]);
    assertEquals("20150902T050000", formatDate(resultInterval.getStartTime()));
    assertEquals("20150902T100000", formatDate(resultInterval.getEndTime()));

    double timePoint3 = parseDate("20150929T040000");

    repetitiveInterval1.getInterval(timePoint3, isPositive);
    assertEquals(false, isPositive[0]);

    ///////////////////////////////////////////// With the repeat unit MONTH.

    RepetitiveInterval repetitiveInterval2 = new RepetitiveInterval
      (parseDate("20150825T000000"), parseDate("20160825T000000"), 5, 10, 2,
       RepetitiveInterval.RepeatUnit.MONTH);

    double timePoint4 = parseDate("20150825T050000");

    resultInterval = repetitiveInterval2.getInterval(timePoint4, isPositive);
    assertEquals(true, isPositive[0]);
    assertEquals("20150825T050000", formatDate(resultInterval.getStartTime()));
    assertEquals("20150825T100000", formatDate(resultInterval.getEndTime()));

    double timePoint5 = parseDate("20151025T060000");

    resultInterval = repetitiveInterval2.getInterval(timePoint5, isPositive);
    assertEquals(true, isPositive[0]);
    assertEquals("20151025T050000", formatDate(resultInterval.getStartTime()));
    assertEquals("20151025T100000", formatDate(resultInterval.getEndTime()));

    double timePoint6 = parseDate("20151226T050000");

    repetitiveInterval2.getInterval(timePoint6, isPositive);
    assertEquals(false, isPositive[0]);

    double timePoint7 = parseDate("20151225T040000");

    repetitiveInterval2.getInterval(timePoint7, isPositive);
    assertEquals(false, isPositive[0]);

    ///////////////////////////////////////////// With the repeat unit YEAR.

    RepetitiveInterval repetitiveInterval3 = new RepetitiveInterval
      (parseDate("20150825T000000"), parseDate("20300825T000000"), 5, 10, 3,
       RepetitiveInterval.RepeatUnit.YEAR);

    double timePoint8 = parseDate("20150825T050000");

    resultInterval = repetitiveInterval3.getInterval(timePoint8, isPositive);
    assertEquals(true, isPositive[0]);
    assertEquals("20150825T050000", formatDate(resultInterval.getStartTime()));
    assertEquals("20150825T100000", formatDate(resultInterval.getEndTime()));

    double timePoint9 = parseDate("20180825T060000");

    resultInterval = repetitiveInterval3.getInterval(timePoint9, isPositive);
    assertEquals(true, isPositive[0]);
    assertEquals("20180825T050000", formatDate(resultInterval.getStartTime()));
    assertEquals("20180825T100000", formatDate(resultInterval.getEndTime()));

    double timePoint10 = parseDate("20180826T050000");
    repetitiveInterval3.getInterval(timePoint10, isPositive);
    assertEquals(false, isPositive[0]);

    double timePoint11 = parseDate("20210825T040000");
    repetitiveInterval3.getInterval(timePoint11, isPositive);
    assertEquals(false, isPositive[0]);

    double timePoint12 = parseDate("20300825T040000");
    repetitiveInterval3.getInterval(timePoint12, isPositive);
    assertEquals(false, isPositive[0]);
  }
}