/**
 * Copyright (C) 2014 Regents of the University of California.
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

package net.named_data.jndn.tests.unit_tests;

import net.named_data.jndn.Name;
import net.named_data.jndn.util.Blob;
import static org.junit.Assert.assertEquals;
import org.junit.Before;

import org.junit.Test;

public class TestNameMethods {
  private String expectedURI;
  private Name.Component comp2;

  @Before
  public void
  setUp()
  {
    expectedURI = "/entr%C3%A9e/..../%00%01%02%03";
    comp2 = new Name.Component(new Blob(new int[] {0x00, 0x01, 0x02, 0x03}));
  }

  @Test
  public void
  testUriConstructor()
  {
    Name name = new Name(expectedURI);
    assertEquals("Constructed name has " + name.size() + " components instead of 3", name.size(), 3);
    assertEquals("URI is incorrect", name.toUri(), expectedURI);
  }
}
