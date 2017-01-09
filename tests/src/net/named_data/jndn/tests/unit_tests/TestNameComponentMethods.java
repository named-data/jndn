/**
 * Copyright (C) 2014-2017 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From PyNDN unit-tests by Adeola Bannis.
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
import net.named_data.jndn.util.Common;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class TestNameComponentMethods {
  @Test
  public void
  testUnicode()
  {
    Name.Component comp1 = new Name.Component("entr\u00E9e");
    String expected = "entr%C3%A9e";
    assertEquals("Unicode URI not decoded correctly", expected, comp1.toEscapedString());
  }

  @Test
  public void
  testHashCode()
  {
    Name.Component foo1 = new Name.Component("foo");
    Name.Component foo2 = new Name.Component("foo");

    assertEquals
      ("Hash codes for same strings are not equal",
       foo1.hashCode(), foo2.hashCode());

    Name.Component bar = new Name.Component("bar");
    // Strictly speaking, it is possible for a hash collision, but unlikely.
    assertTrue
      ("Hash codes for different strings are not different",
       foo1.hashCode() != bar.hashCode());
  }
  
  @Test
  public void
  testCompare()
  {
    Name.Component c7f = new Name("/%7F").get(0);
    Name.Component c80 = new Name("/%80").get(0);
    Name.Component c81 = new Name("/%81").get(0);
    
    assertTrue("%81 should be greater than %80", c81.compare(c80) > 0);
    assertTrue("%80 should be greater than %7f", c80.compare(c7f) > 0);
  }

  // Many more component methods to be tested!

  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
