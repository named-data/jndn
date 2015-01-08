/**
 * Copyright (C) 2014-2015 Regents of the University of California.
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
import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class TestNameComponentMethods {
  @Test
  public void
  testUnicode()
  {
    Name.Component comp1 = new Name.Component("entr\u00E9e");
    String expected = "entr%C3%A9e";
    assertEquals("Unicode URI not decoded correctly", comp1.toEscapedString(), expected);
  }

  // Many more component methods to be tested!
}
