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
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU Lesser General Public License is in the file COPYING.
 */

package net.named_data.jndn.tests.unit_tests;

import java.util.ArrayList;
import java.util.Arrays;
import net.named_data.jndn.Name;
import net.named_data.jndn.util.Blob;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertArrayEquals;
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

  @Test
  public void
  testCopyConstructor()
  {
    Name name = new Name(expectedURI);
    Name name2 = new Name(name);
    assertTrue("Name from copy constructor does not match original", name.equals(name2));
  }

  @Test
  public void
  testGetComponent()
  {
    Name name = new Name(expectedURI);
    Name.Component component2 = name.get(2);
    assertTrue("Component at index 2 is incorrect", comp2.equals(component2));
  }

  @Test
  public void
  testPrefix()
  {
    Name name = new Name(expectedURI);
    Name name2 = name.getPrefix(2);
    assertEquals("Name prefix has " + name2.size() + " components instead of 2", name2.size(), 2);
    for (int i = 0; i < 2; ++i)
      assertTrue(name.get(i).getValue().equals(name2.get(i).getValue()));
  }

  @Test
  public void
  testAppend()
  {
    // could possibly split this into different tests
    String uri = "/localhost/user/folders/files/%00%0F";
    Name name = new Name(uri);
    Name name2 = new Name("/localhost").append(new Name("/user/folders/"));
    assertEquals("Name constructed by appending names has " + name2.size() + " components instead of 3", name2.size(), 3);
    assertTrue("Name constructed with append has wrong suffix", name2.get(2).getValue().equals(new Blob("folders")));
    name2 = name2.append("files");
    assertEquals("Name constructed by appending string has " + name2.size() + " components instead of 4", name2.size(), 4);
    name2 = name2.appendSegment(15);
    assertTrue("Name constructed by appending segment has wrong segment value", name2.get(4).getValue().equals(new Blob(new int[] { 0x00, 0x0F })));

    assertTrue("Name constructed with append is not equal to URI constructed name", name2.equals(name));
    assertEquals("Name constructed with append has wrong URI", name2.toUri(), name.toUri());
  }

  @Test
  public void
  testSubName()
  {
    Name name = new Name("/edu/cmu/andrew/user/3498478");
    Name subName1 = name.getSubName(0);
    assertTrue("Subname from first component does not match original name", subName1.equals(name));
    Name subName2 = name.getSubName(3);
    assertEquals("/user/3498478", subName2.toUri());

    Name subName3 = name.getSubName(1, 3);
    assertEquals("/cmu/andrew/user", subName3.toUri());

    Name subName4 = name.getSubName(0, 100);
    assertTrue("Subname with more components than original should stop at end of original name", name.equals(subName4));

    Name subName5 = name.getSubName(7,9);
    assertTrue("Subname beginning after end of name should be empty", new Name().equals(subName5));
  }

  @Test
  public void
  testClear()
  {
    Name name = new Name(expectedURI);
    name.clear();
    assertTrue("Cleared name is not empty", new Name().equals(name));
  }

  @Test
  public void
  testCompare()
  {
    Name[] names = new Name[] { new Name("/a/b/d"), new Name("/c"), new Name("/c/a"), new Name("/bb"), new Name("/a/b/cc") };
    Object[] expectedOrder = new Object[] { "/a/b/d", "/a/b/cc", "/c", "/c/a", "/bb" };
    // sort calls Name.compareTo which calls Name.compare.
    Arrays.sort(names);

    ArrayList sortedURIs = new ArrayList();
    for (int i = 0; i < names.length; ++i)
      sortedURIs.add(names[i].toUri());
    assertArrayEquals("Name comparison gave incorrect order", sortedURIs.toArray(), expectedOrder);
  }

  @Test
  public void
  testMatch()
  {
    Name name = new Name("/edu/cmu/andrew/user/3498478");
    Name name2 = new Name(name);
    assertTrue("Name does not match deep copy of itself", name.match(name2));

    name2 = name.getPrefix(2);
    assertTrue("Name did not match prefix", name2.match(name));
    assertFalse("Name should not match shorter name", name.match(name2));
    assertTrue("Empty name should always match another", new Name().match(name));
  }
}
