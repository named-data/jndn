/**
 * Copyright (C) 2015 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/interval.t.cpp
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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import org.junit.Test;

public class TestInterval {
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
    // Construct with the right parameters.
    Interval interval1 = new Interval(parseDate("20150825T120000"),
                                      parseDate("20150825T160000"));
    assertEquals("20150825T120000", formatDate(interval1.getStartTime()));
    assertEquals("20150825T160000", formatDate(interval1.getEndTime()));
    assertEquals(true, interval1.isValid());

    // Construct with the invalid interval.
    Interval interval2 = new Interval();
    assertEquals(false, interval2.isValid());

    // Construct with the empty interval.
    Interval interval3 = new Interval(true);
    assertEquals(true, interval3.isValid());
    assertEquals(true, interval3.isEmpty());
  }

  @Test
  public void
  testCoverTimePoint() throws ParseException
  {
    Interval interval = new Interval(parseDate("20150825T120000"),
                                     parseDate("20150825T160000"));

    double timePoint1 = parseDate("20150825T120000");
    double timePoint2 = parseDate("20150825T130000");
    double timePoint3 = parseDate("20150825T170000");
    double timePoint4 = parseDate("20150825T110000");

    assertEquals(true, interval.covers(timePoint1));
    assertEquals(true, interval.covers(timePoint2));
    assertEquals(false, interval.covers(timePoint3));
    assertEquals(false, interval.covers(timePoint4));
  }

  @Test
  public void
  testIntersectionAndUnion() throws ParseException
  {
    Interval interval1 = new Interval(parseDate("20150825T030000"),
                                      parseDate("20150825T050000"));
    // No intersection.
    Interval interval2 = new Interval(parseDate("20150825T050000"),
                                      parseDate("20150825T070000"));
    // No intersection.
    Interval interval3 = new Interval(parseDate("20150825T060000"),
                                      parseDate("20150825T070000"));
    // There's an intersection.
    Interval interval4 = new Interval(parseDate("20150825T010000"),
                                      parseDate("20150825T040000"));
    // Right in interval1, there's an intersection.
    Interval interval5 = new Interval(parseDate("20150825T030000"),
                                      parseDate("20150825T040000"));
    // Wrap interval1, there's an intersection.
    Interval interval6 = new Interval(parseDate("20150825T010000"),
                                      parseDate("20150825T050000"));
    // Empty interval.
    Interval interval7 = new Interval(true);

    Interval tempInterval = new Interval(interval1);
    tempInterval.intersectWith(interval2);
    assertEquals(tempInterval.isEmpty(), true);

    tempInterval = new Interval(interval1);
    boolean gotError = true;
    try {
      tempInterval.unionWith(interval2);
      gotError = false;
    } catch (Error ex) {}
    if (!gotError)
      fail("Expected error in unionWith(interval2)");

    tempInterval = new Interval(interval1);
    tempInterval.intersectWith(interval3);
    assertEquals(tempInterval.isEmpty(), true);

    tempInterval = new Interval(interval1);
    gotError = true;
    try {
      tempInterval.unionWith(interval3);
      gotError = false;
    } catch (Error ex) {}
    if (!gotError)
      fail("Expected error in unionWith(interval3)");

    tempInterval = new Interval(interval1);
    tempInterval.intersectWith(interval4);
    assertEquals(tempInterval.isEmpty(), false);
    assertEquals("20150825T030000", formatDate(tempInterval.getStartTime()));
    assertEquals("20150825T040000", formatDate(tempInterval.getEndTime()));

    tempInterval = new Interval(interval1);
    tempInterval.unionWith(interval4);
    assertEquals(tempInterval.isEmpty(), false);
    assertEquals("20150825T010000", formatDate(tempInterval.getStartTime()));
    assertEquals("20150825T050000", formatDate(tempInterval.getEndTime()));

    tempInterval = new Interval(interval1);
    tempInterval.intersectWith(interval5);
    assertEquals(tempInterval.isEmpty(), false);
    assertEquals("20150825T030000", formatDate(tempInterval.getStartTime()));
    assertEquals("20150825T040000", formatDate(tempInterval.getEndTime()));

    tempInterval = new Interval(interval1);
    tempInterval.unionWith(interval5);
    assertEquals(tempInterval.isEmpty(), false);
    assertEquals("20150825T030000", formatDate(tempInterval.getStartTime()));
    assertEquals("20150825T050000", formatDate(tempInterval.getEndTime()));

    tempInterval = new Interval(interval1);
    tempInterval.intersectWith(interval6);
    assertEquals(tempInterval.isEmpty(), false);
    assertEquals("20150825T030000", formatDate(tempInterval.getStartTime()));
    assertEquals("20150825T050000", formatDate(tempInterval.getEndTime()));

    tempInterval = new Interval(interval1);
    tempInterval.unionWith(interval6);
    assertEquals(tempInterval.isEmpty(), false);
    assertEquals("20150825T010000", formatDate(tempInterval.getStartTime()));
    assertEquals("20150825T050000", formatDate(tempInterval.getEndTime()));

    tempInterval = new Interval(interval1);
    tempInterval.intersectWith(interval7);
    assertEquals(tempInterval.isEmpty(), true);

    tempInterval = new Interval(interval1);
    tempInterval.unionWith(interval7);
    assertEquals(tempInterval.isEmpty(), false);
    assertEquals("20150825T030000", formatDate(tempInterval.getStartTime()));
    assertEquals("20150825T050000", formatDate(tempInterval.getEndTime()));
  }
}