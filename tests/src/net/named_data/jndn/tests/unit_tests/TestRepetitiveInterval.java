/**
 * Copyright (C) 2015-2017 Regents of the University of California.
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

import java.text.ParseException;
import static net.named_data.jndn.tests.unit_tests.UnitTestsCommon.toIsoString;
import static net.named_data.jndn.tests.unit_tests.UnitTestsCommon.fromIsoString;
import net.named_data.jndn.encrypt.Interval;
import net.named_data.jndn.encrypt.RepetitiveInterval;
import net.named_data.jndn.util.Common;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

public class TestRepetitiveInterval {
  @Test
  public void
  testConstruction() throws ParseException
  {
    RepetitiveInterval repetitiveInterval1 = new RepetitiveInterval
      (fromIsoString("20150825T000000"), fromIsoString("20150825T000000"), 5, 10);
    assertEquals("20150825T000000", toIsoString(repetitiveInterval1.getStartDate()));
    assertEquals("20150825T000000", toIsoString(repetitiveInterval1.getEndDate()));
    assertEquals(5, repetitiveInterval1.getIntervalStartHour());
    assertEquals(10, repetitiveInterval1.getIntervalEndHour());

    RepetitiveInterval repetitiveInterval2 = new RepetitiveInterval
      (fromIsoString("20150825T000000"), fromIsoString("20150827T000000"), 5, 10, 1,
       RepetitiveInterval.RepeatUnit.DAY);

    assertEquals(1, repetitiveInterval2.getNRepeats());
    assertEquals
      (RepetitiveInterval.RepeatUnit.DAY, repetitiveInterval2.getRepeatUnit());

    RepetitiveInterval repetitiveInterval3 = new RepetitiveInterval
      (fromIsoString("20150825T000000"), fromIsoString("20151227T000000"), 5, 10, 2,
       RepetitiveInterval.RepeatUnit.MONTH);

    assertEquals(2, repetitiveInterval3.getNRepeats());
    assertEquals
      (RepetitiveInterval.RepeatUnit.MONTH, repetitiveInterval3.getRepeatUnit());

    RepetitiveInterval repetitiveInterval4 = new RepetitiveInterval
      (fromIsoString("20150825T000000"), fromIsoString("20301227T000000"), 5, 10, 5,
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
      (fromIsoString("20150825T000000"), fromIsoString("20150925T000000"), 5, 10, 2,
       RepetitiveInterval.RepeatUnit.DAY);
    RepetitiveInterval.Result result;

    double timePoint1 = fromIsoString("20150825T050000");

    result = repetitiveInterval1.getInterval(timePoint1);
    assertEquals(true, result.isPositive);
    assertEquals("20150825T050000", toIsoString(result.interval.getStartTime()));
    assertEquals("20150825T100000", toIsoString(result.interval.getEndTime()));

    double timePoint2 = fromIsoString("20150902T060000");

    result = repetitiveInterval1.getInterval(timePoint2);
    assertEquals(true, result.isPositive);
    assertEquals("20150902T050000", toIsoString(result.interval.getStartTime()));
    assertEquals("20150902T100000", toIsoString(result.interval.getEndTime()));

    double timePoint3 = fromIsoString("20150929T040000");

    result = repetitiveInterval1.getInterval(timePoint3);
    assertEquals(false, result.isPositive);

    ///////////////////////////////////////////// With the repeat unit MONTH.

    RepetitiveInterval repetitiveInterval2 = new RepetitiveInterval
      (fromIsoString("20150825T000000"), fromIsoString("20160825T000000"), 5, 10, 2,
       RepetitiveInterval.RepeatUnit.MONTH);

    double timePoint4 = fromIsoString("20150825T050000");

    result = repetitiveInterval2.getInterval(timePoint4);
    assertEquals(true, result.isPositive);
    assertEquals("20150825T050000", toIsoString(result.interval.getStartTime()));
    assertEquals("20150825T100000", toIsoString(result.interval.getEndTime()));

    double timePoint5 = fromIsoString("20151025T060000");

    result = repetitiveInterval2.getInterval(timePoint5);
    assertEquals(true, result.isPositive);
    assertEquals("20151025T050000", toIsoString(result.interval.getStartTime()));
    assertEquals("20151025T100000", toIsoString(result.interval.getEndTime()));

    double timePoint6 = fromIsoString("20151226T050000");

    result = repetitiveInterval2.getInterval(timePoint6);
    assertEquals(false, result.isPositive);

    double timePoint7 = fromIsoString("20151225T040000");

    result = repetitiveInterval2.getInterval(timePoint7);
    assertEquals(false, result.isPositive);

    ///////////////////////////////////////////// With the repeat unit YEAR.

    RepetitiveInterval repetitiveInterval3 = new RepetitiveInterval
      (fromIsoString("20150825T000000"), fromIsoString("20300825T000000"), 5, 10, 3,
       RepetitiveInterval.RepeatUnit.YEAR);

    double timePoint8 = fromIsoString("20150825T050000");

    result = repetitiveInterval3.getInterval(timePoint8);
    assertEquals(true, result.isPositive);
    assertEquals("20150825T050000", toIsoString(result.interval.getStartTime()));
    assertEquals("20150825T100000", toIsoString(result.interval.getEndTime()));

    double timePoint9 = fromIsoString("20180825T060000");

    result = repetitiveInterval3.getInterval(timePoint9);
    assertEquals(true, result.isPositive);
    assertEquals("20180825T050000", toIsoString(result.interval.getStartTime()));
    assertEquals("20180825T100000", toIsoString(result.interval.getEndTime()));

    double timePoint10 = fromIsoString("20180826T050000");
    result = repetitiveInterval3.getInterval(timePoint10);
    assertEquals(false, result.isPositive);

    double timePoint11 = fromIsoString("20210825T040000");
    result = repetitiveInterval3.getInterval(timePoint11);
    assertEquals(false, result.isPositive);

    double timePoint12 = fromIsoString("20300825T040000");
    result = repetitiveInterval3.getInterval(timePoint12);
    assertEquals(false, result.isPositive);
  }

  private static boolean
  check(RepetitiveInterval small, RepetitiveInterval big)
  {
    return small.compare(big) < 0 && !(big.compare(small) < 0);
  }

  @Test
  public void
  testComparison() throws ParseException
  {
    assertTrue(check(new RepetitiveInterval(fromIsoString("20150825T000000"),
                                            fromIsoString("20150828T000000"),
                                         5, 10, 2, RepetitiveInterval.RepeatUnit.DAY),
                     new RepetitiveInterval(fromIsoString("20150826T000000"),
                                            fromIsoString("20150828T000000"),
                                         5, 10, 2, RepetitiveInterval.RepeatUnit.DAY)));

    assertTrue(check(new RepetitiveInterval(fromIsoString("20150825T000000"),
                                            fromIsoString("20150828T000000"),
                                         5, 10, 2, RepetitiveInterval.RepeatUnit.DAY),
                     new RepetitiveInterval(fromIsoString("20150825T000000"),
                                            fromIsoString("20150828T000000"),
                                         6, 10, 2, RepetitiveInterval.RepeatUnit.DAY)));

    assertTrue(check(new RepetitiveInterval(fromIsoString("20150825T000000"),
                                            fromIsoString("20150828T000000"),
                                         5, 10, 2, RepetitiveInterval.RepeatUnit.DAY),
                     new RepetitiveInterval(fromIsoString("20150825T000000"),
                                            fromIsoString("20150828T000000"),
                                         5, 11, 2, RepetitiveInterval.RepeatUnit.DAY)));

    assertTrue(check(new RepetitiveInterval(fromIsoString("20150825T000000"),
                                            fromIsoString("20150828T000000"),
                                         5, 10, 2, RepetitiveInterval.RepeatUnit.DAY),
                     new RepetitiveInterval(fromIsoString("20150825T000000"),
                                            fromIsoString("20150828T000000"),
                                         5, 10, 3, RepetitiveInterval.RepeatUnit.DAY)));

    assertTrue(check(new RepetitiveInterval(fromIsoString("20150825T000000"),
                                            fromIsoString("20150828T000000"),
                                         5, 10, 2, RepetitiveInterval.RepeatUnit.DAY),
                     new RepetitiveInterval(fromIsoString("20150825T000000"),
                                            fromIsoString("20150828T000000"),
                                         5, 10, 2, RepetitiveInterval.RepeatUnit.MONTH)));
  }

  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}