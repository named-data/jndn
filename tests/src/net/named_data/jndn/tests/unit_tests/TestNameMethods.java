/**
 * Copyright (C) 2014-2016 Regents of the University of California.
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
    assertEquals("Constructed name has " + name.size() + " components instead of 3", 3, name.size());
    assertEquals("URI is incorrect", expectedURI, name.toUri());
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
  testAppend()
  {
    // could possibly split this into different tests
    String uri = "/localhost/user/folders/files/%00%0F";
    Name name = new Name(uri);
    Name name2 = new Name("/localhost").append(new Name("/user/folders/"));
    assertEquals("Name constructed by appending names has " + name2.size() + " components instead of 3", 3, name2.size());
    assertTrue("Name constructed with append has wrong suffix", name2.get(2).getValue().equals(new Blob("folders")));
    name2 = name2.append("files");
    assertEquals("Name constructed by appending string has " + name2.size() + " components instead of 4", 4, name2.size());
    name2 = name2.appendSegment(15);
    assertTrue("Name constructed by appending segment has wrong segment value", name2.get(4).getValue().equals(new Blob(new int[] { 0x00, 0x0F })));

    assertTrue("Name constructed with append is not equal to URI constructed name", name2.equals(name));
    assertEquals("Name constructed with append has wrong URI", name.toUri(), name2.toUri());
  }

  @Test
  public void
  testPrefix()
  {
    Name name = new Name("/edu/cmu/andrew/user/3498478");
    Name prefix1 = name.getPrefix(2);
    assertEquals("Name prefix has " + prefix1.size() + " components instead of 2", 2, prefix1.size());
    for (int i = 0; i < 2; ++i)
      assertTrue(name.get(i).getValue().equals(prefix1.get(i).getValue()));

    Name prefix2 = name.getPrefix(100);
    assertEquals("Prefix with more components than original should stop at end of original name", name, prefix2);
  }

  @Test
  public void
  testSubName()
  {
    Name name = new Name("/edu/cmu/andrew/user/3498478");
    Name subName1 = name.getSubName(0);
    assertEquals("Subname from first component does not match original name", name, subName1);
    Name subName2 = name.getSubName(3);
    assertEquals("/user/3498478", subName2.toUri());

    Name subName3 = name.getSubName(1, 3);
    assertEquals("/cmu/andrew/user", subName3.toUri());

    Name subName4 = name.getSubName(0, 100);
    assertEquals("Subname with more components than original should stop at end of original name", name, subName4);

    Name subName5 = name.getSubName(7, 2);
    assertEquals("Subname beginning after end of name should be empty", new Name(), subName5);

    Name subName6 = name.getSubName(-1, 7);
    assertEquals("Negative subname with more components than original should stop at end of original name", new Name("/3498478"), subName6);

    Name subName7 = name.getSubName(-5, 5);
    assertEquals("Subname from (-length) should match original name", name, subName7);
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

  @Test
  public void
  testHashCode()
  {
    Name foo1 = new Name("/ndn/foo");
    Name foo2 = new Name("/ndn/foo");

    assertEquals
      ("Hash codes for same Name value are not equal",
       foo1.hashCode(), foo2.hashCode());

    Name bar1 = new Name("/ndn/bar");
    // Strictly speaking, it is possible for a hash collision, but unlikely.
    assertTrue
      ("Hash codes for different Name values are not different",
       foo1.hashCode() != bar1.hashCode());

    Name bar2 = new Name("/ndn");
    int beforeHashCode = bar2.hashCode();
    bar2.append("bar");
    assertTrue
      ("Hash code did not change when changing the Name object",
       beforeHashCode != bar2.hashCode());
    assertEquals
      ("Hash codes for same Name value after changes are not equal",
       bar1.hashCode(), bar2.hashCode());
  }
}
