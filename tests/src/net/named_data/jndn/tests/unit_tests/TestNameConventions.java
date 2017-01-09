/**
 * Copyright (C) 2014-2017 Regents of the University of California.
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
import net.named_data.jndn.util.Common;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
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
                 expected, new Name().append(Name.Component.fromNumberWithMarker(number, marker)));
    try {
      assertEquals("toNumberWithMarker did not return the expected value",
                   number, expected.get(0).toNumberWithMarker(marker));
    } catch (EncodingException ex) {
      fail("Error while parsing a nonNegativeInteger: " + ex.getMessage());
    }
  }

  @Test
  public void
  testSegment()
  {
    Name expected = new Name("/%00%27%10");
    assertTrue(expected.get(0).isSegment());
    long number = 10000;
    assertEquals("appendSegment did not create the expected component",
                 expected, new Name().appendSegment(number));
    try {
      assertEquals("toSegment did not return the expected value",
                   number, expected.get(0).toSegment());
    } catch (EncodingException ex) {
      fail("Error while parsing a nonNegativeInteger: " + ex.getMessage());
    }
  }

  @Test
  public void
  testSegmentOffset()
  {
    Name expected = new Name("/%FB%00%01%86%A0");
    assertTrue(expected.get(0).isSegmentOffset());
    long number = 100000;
    assertEquals("appendSegmentOffset did not create the expected component",
                 expected, new Name().appendSegmentOffset(number));
    try {
      assertEquals("toSegmentOffset did not return the expected value",
                   number, expected.get(0).toSegmentOffset());
    } catch (EncodingException ex) {
      fail("Error while parsing a nonNegativeInteger: " + ex.getMessage());
    }
  }

  @Test
  public void
  testVersion()
  {
    Name expected = new Name("/%FD%00%0FB%40");
    assertTrue(expected.get(0).isVersion());
    long number = 1000000;
    assertEquals("appendVersion did not create the expected component",
                 expected, new Name().appendVersion(number));
    try {
      assertEquals("toVersion did not return the expected value",
                   number, expected.get(0).toVersion());
    } catch (EncodingException ex) {
      fail("Error while parsing a nonNegativeInteger: " + ex.getMessage());
    }
  }

  @Test
  public void
  testSequenceNumber()
  {
    Name expected = new Name("/%FE%00%98%96%80");
    assertTrue(expected.get(0).isSequenceNumber());
    long number = 10000000;
    assertEquals("appendSequenceNumber did not create the expected component",
                 expected, new Name().appendSequenceNumber(number));
    try {
      assertEquals("toSequenceNumber did not return the expected value",
                  number,  expected.get(0).toSequenceNumber());
    } catch (EncodingException ex) {
      fail("Error while parsing a nonNegativeInteger: " + ex.getMessage());
    }
  }

  @Test
  public void
  testTimestamp()
  {
    Name expected = new Name("/%FC%00%04%7BE%E3%1B%00%00");
    assertTrue(expected.get(0).isTimestamp());
    // 40 years (not counting leap years) in microseconds.
    long number = (long)40 * 365 * 24 * 3600 * 1000000;
    assertEquals("appendTimestamp did not create the expected component",
                 expected, new Name().appendTimestamp(number));
    try {
      assertEquals("toTimestamp did not return the expected value",
                   number, expected.get(0).toTimestamp());
    } catch (EncodingException ex) {
      fail("Error while parsing a nonNegativeInteger: " + ex.getMessage());
    }
  }

  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}