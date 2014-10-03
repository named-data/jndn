/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx NamingConventions unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/test-name.cpp.
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

import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import org.junit.Test;

public class TestNameConventions {
  @Test
  public void
  testNumberWithMarker()
  {
    Name expected = new Name("/%AA%03%E8");
    long number = 1000;
    int marker = 0xAA;
    assertEquals("fromNumberWithMarker did not create the expected component",
                 new Name().append(Name.Component.fromNumberWithMarker(number, marker)), expected);
    try {
      assertEquals("toNumberWithMarker did not return the expected value",
              expected.get(0).toNumberWithMarker(marker), number);
    } catch (EncodingException ex) {
      fail("Error while parsing a nonNegativeInteger: " + ex.getMessage());
    }
  }

  @Test
  public void
  testSegment()
  {
    Name expected = new Name("/%00%27%10");
    long number = 10000;
    assertEquals("appendSegment did not create the expected component",
                 new Name().appendSegment(number), expected);
    try {
      assertEquals("toSegment did not return the expected value",
                   expected.get(0).toSegment(), number);
    } catch (EncodingException ex) {
      fail("Error while parsing a nonNegativeInteger: " + ex.getMessage());
    }
  }

  @Test
  public void
  testSegmentOffset()
  {
    Name expected = new Name("/%FB%00%01%86%A0");
    long number = 100000;
    assertEquals("appendSegmentOffset did not create the expected component",
                 new Name().appendSegmentOffset(number), expected);
    try {
      assertEquals("toSegmentOffset did not return the expected value",
                   expected.get(0).toSegmentOffset(), number);
    } catch (EncodingException ex) {
      fail("Error while parsing a nonNegativeInteger: " + ex.getMessage());
    }
  }

  @Test
  public void
  testVersion()
  {
    Name expected = new Name("/%FD%00%0FB%40");
    long number = 1000000;
    assertEquals("appendVersion did not create the expected component",
                 new Name().appendVersion(number), expected);
    try {
      assertEquals("toVersion did not return the expected value",
                   expected.get(0).toVersion(), number);
    } catch (EncodingException ex) {
      fail("Error while parsing a nonNegativeInteger: " + ex.getMessage());
    }
  }

  @Test
  public void
  testSequenceNumber()
  {
    Name expected = new Name("/%FE%00%98%96%80");
    long number = 10000000;
    assertEquals("appendSequenceNumber did not create the expected component",
                 new Name().appendSequenceNumber(number), expected);
    try {
      assertEquals("toSequenceNumber did not return the expected value",
                   expected.get(0).toSequenceNumber(), number);
    } catch (EncodingException ex) {
      fail("Error while parsing a nonNegativeInteger: " + ex.getMessage());
    }
  }

  @Test
  public void
  testTimestamp()
  {
    Name expected = new Name("/%FC%00%04%7BE%E3%1B%00%00");
    // 40 years (not counting leap years) in microseconds.
    long number = (long)40 * 365 * 24 * 3600 * 1000000;
    assertEquals("appendTimestamp did not create the expected component",
                 new Name().appendTimestamp(number), expected);
    try {
      assertEquals("toTimestamp did not return the expected value",
                   expected.get(0).toTimestamp(), number);
    } catch (EncodingException ex) {
      fail("Error while parsing a nonNegativeInteger: " + ex.getMessage());
    }
  }
}