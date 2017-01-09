/**
 * Copyright (C) 2014-2017 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From PyNDN unit-tests by Adeola Bannis.
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/name.t.cpp
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
import java.util.ArrayList;
import java.util.Arrays;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.TlvWireFormat;
import net.named_data.jndn.util.Blob;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.fail;
import org.junit.Before;
import org.junit.Test;

public class TestNameMethods {
  // Convert the int array to a ByteBuffer.
  private static ByteBuffer
  toBuffer(int[] array)
  {
    ByteBuffer result = ByteBuffer.allocate(array.length);
    for (int i = 0; i < array.length; ++i)
      result.put((byte)(array[i] & 0xff));

    result.flip();
    return result;
  }

  private static final ByteBuffer TEST_NAME = toBuffer(new int[] {
    0x7,  0x14, // Name
      0x8,  0x5, // NameComponent
          0x6c,  0x6f,  0x63,  0x61,  0x6c,
      0x8,  0x3, // NameComponent
          0x6e,  0x64,  0x6e,
      0x8,  0x6, // NameComponent
          0x70,  0x72,  0x65,  0x66,  0x69,  0x78
  });

  private static final ByteBuffer TEST_NAME_IMPLICIT_DIGEST = toBuffer(new int[] {
    0x7,  0x36, // Name
      0x8,  0x5, // NameComponent
          0x6c,  0x6f,  0x63,  0x61,  0x6c,
      0x8,  0x3, // NameComponent
          0x6e,  0x64,  0x6e,
      0x8,  0x6, // NameComponent
          0x70,  0x72,  0x65,  0x66,  0x69,  0x78,
      0x01, 0x20, // ImplicitSha256DigestComponent
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
  });

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

    // Tests from ndn-cxx name.t.cpp Compare.
    assertEquals(new Name("/A")  .compare(new Name("/A")),    0);
    assertEquals(new Name("/A")  .compare(new Name("/A")),    0);
    assertTrue  (new Name("/A")  .compare(new Name("/B"))   < 0);
    assertTrue  (new Name("/B")  .compare(new Name("/A"))   > 0);
    assertTrue  (new Name("/A")  .compare(new Name("/AA"))  < 0);
    assertTrue  (new Name("/AA") .compare(new Name("/A"))   > 0);
    assertTrue  (new Name("/A")  .compare(new Name("/A/C")) < 0);
    assertTrue  (new Name("/A/C").compare(new Name("/A"))   > 0);

    assertEquals(new Name("/Z/A/Y")  .compare(1, 1, new Name("/A")),    0);
    assertEquals(new Name("/Z/A/Y")  .compare(1, 1, new Name("/A")),    0);
    assertTrue  (new Name("/Z/A/Y")  .compare(1, 1, new Name("/B"))   < 0);
    assertTrue  (new Name("/Z/B/Y")  .compare(1, 1, new Name("/A"))   > 0);
    assertTrue  (new Name("/Z/A/Y")  .compare(1, 1, new Name("/AA"))  < 0);
    assertTrue  (new Name("/Z/AA/Y") .compare(1, 1, new Name("/A"))   > 0);
    assertTrue  (new Name("/Z/A/Y")  .compare(1, 1, new Name("/A/C")) < 0);
    assertTrue  (new Name("/Z/A/C/Y").compare(1, 2, new Name("/A"))   > 0);

    assertEquals(new Name("/Z/A")  .compare(1, 9, new Name("/A")),    0);
    assertEquals(new Name("/Z/A")  .compare(1, 9, new Name("/A")),    0);
    assertTrue  (new Name("/Z/A")  .compare(1, 9, new Name("/B"))   < 0);
    assertTrue  (new Name("/Z/B")  .compare(1, 9, new Name("/A"))   > 0);
    assertTrue  (new Name("/Z/A")  .compare(1, 9, new Name("/AA"))  < 0);
    assertTrue  (new Name("/Z/AA") .compare(1, 9, new Name("/A"))   > 0);
    assertTrue  (new Name("/Z/A")  .compare(1, 9, new Name("/A/C")) < 0);
    assertTrue  (new Name("/Z/A/C").compare(1, 9, new Name("/A"))   > 0);

    assertEquals(new Name("/Z/A/Y")  .compare(1, 1, new Name("/X/A/W"),   1, 1),  0);
    assertEquals(new Name("/Z/A/Y")  .compare(1, 1, new Name("/X/A/W"),   1, 1),  0);
    assertTrue  (new Name("/Z/A/Y")  .compare(1, 1, new Name("/X/B/W"),   1, 1) < 0);
    assertTrue  (new Name("/Z/B/Y")  .compare(1, 1, new Name("/X/A/W"),   1, 1) > 0);
    assertTrue  (new Name("/Z/A/Y")  .compare(1, 1, new Name("/X/AA/W"),  1, 1) < 0);
    assertTrue  (new Name("/Z/AA/Y") .compare(1, 1, new Name("/X/A/W"),   1, 1) > 0);
    assertTrue  (new Name("/Z/A/Y")  .compare(1, 1, new Name("/X/A/C/W"), 1, 2) < 0);
    assertTrue  (new Name("/Z/A/C/Y").compare(1, 2, new Name("/X/A/W"),   1, 1) > 0);

    assertEquals(new Name("/Z/A/Y")  .compare(1, 1, new Name("/X/A"),   1),  0);
    assertEquals(new Name("/Z/A/Y")  .compare(1, 1, new Name("/X/A"),   1),  0);
    assertTrue  (new Name("/Z/A/Y")  .compare(1, 1, new Name("/X/B"),   1) < 0);
    assertTrue  (new Name("/Z/B/Y")  .compare(1, 1, new Name("/X/A"),   1) > 0);
    assertTrue  (new Name("/Z/A/Y")  .compare(1, 1, new Name("/X/AA"),  1) < 0);
    assertTrue  (new Name("/Z/AA/Y") .compare(1, 1, new Name("/X/A"),   1) > 0);
    assertTrue  (new Name("/Z/A/Y")  .compare(1, 1, new Name("/X/A/C"), 1) < 0);
    assertTrue  (new Name("/Z/A/C/Y").compare(1, 2, new Name("/X/A"),   1) > 0);
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
  testGetSuccessor()
  {
    assertEquals(new Name("ndn:/%00%01/%01%03"), new Name("ndn:/%00%01/%01%02").getSuccessor());
    assertEquals(new Name("ndn:/%00%01/%02%00"), new Name("ndn:/%00%01/%01%FF").getSuccessor());
    assertEquals(new Name("ndn:/%00%01/%00%00%00"), new Name("ndn:/%00%01/%FF%FF").getSuccessor());
    assertEquals(new Name("/%00"), new Name().getSuccessor());
    assertEquals(new Name("/%00%01/%00"), new Name("/%00%01/...").getSuccessor());
  }

  @Test
  public void
  testEncodeDecode()
  {
    Name name = new Name("/local/ndn/prefix");

    Blob encoding = name.wireEncode(TlvWireFormat.get());
    assertTrue(encoding.equals(new Blob(TEST_NAME, false)));

    Name decodedName = new Name();
    try {
      decodedName.wireDecode(new Blob(TEST_NAME, false), TlvWireFormat.get());
    } catch (EncodingException ex) {
      fail("Can't decode TEST_NAME");
    }
    assertEquals(decodedName, name);

    // Test ImplicitSha256Digest.
    Name name2 = new Name
      ("/local/ndn/prefix/sha256digest=" +
       "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    Blob encoding2 = name2.wireEncode(TlvWireFormat.get());
    assertTrue(encoding2.equals(new Blob(TEST_NAME_IMPLICIT_DIGEST, false)));

    Name decodedName2 = new Name();
    try {
      decodedName2.wireDecode(new Blob(TEST_NAME_IMPLICIT_DIGEST, false), TlvWireFormat.get());
    } catch (EncodingException ex) {
      fail("Can't decode TEST_NAME");
    }
    assertEquals(decodedName2, name2);
  }

  @Test
  public void
  testImplicitSha256Digest() throws EncodingException
  {
    Name name = new Name();

    ByteBuffer digest = toBuffer(new int[] {
      0x28, 0xba, 0xd4, 0xb5, 0x27, 0x5b, 0xd3, 0x92,
      0xdb, 0xb6, 0x70, 0xc7, 0x5c, 0xf0, 0xb6, 0x6f,
      0x13, 0xf7, 0x94, 0x2b, 0x21, 0xe8, 0x0f, 0x55,
      0xc0, 0xe8, 0x6b, 0x37, 0x47, 0x53, 0xa5, 0x48,
      0x00, 0x00
    });

    digest.limit(32);
    name.appendImplicitSha256Digest(new Blob(digest, true));
    name.appendImplicitSha256Digest(new Blob(digest, true).getImmutableArray());
    assertEquals(name.get(0), name.get(1));

    digest.limit(34);
    boolean gotError = true;
    try {
      name.appendImplicitSha256Digest(new Blob(digest, true));
      gotError = false;
    } catch (Throwable ex) {}
    if (!gotError)
      fail("Expected error in appendImplicitSha256Digest");

    digest.limit(30);
    gotError = true;
    try {
      name.appendImplicitSha256Digest(new Blob(digest, true));
      gotError = false;
    } catch (Throwable ex) {}
    if (!gotError)
      fail("Expected error in appendImplicitSha256Digest");

    // Add name.get(2) as a generic component.
    digest.limit(32);
    name.append(new Blob(digest, true));
    assertTrue(name.get(0).compare(name.get(2)) < 0);
    assertTrue(name.get(0).getValue().equals(name.get(2).getValue()));

    // Add name.get(3) as a generic component whose first byte is greater.
    digest.position(1);
    digest.limit(33);
    name.append(new Blob(digest, true));
    assertTrue(name.get(0).compare(name.get(3)) < 0);

    assertEquals
      ("sha256digest=" +
       "28bad4b5275bd392dbb670c75cf0b66f13f7942b21e80f55c0e86b374753a548",
       name.get(0).toEscapedString());

    assertEquals(true, name.get(0).isImplicitSha256Digest());
    assertEquals(false, name.get(2).isImplicitSha256Digest());

    gotError = true;
    try {
      new Name("/hello/sha256digest=hmm");
      gotError = false;
    } catch (Throwable ex) {}
    if (!gotError)
      fail("Expected error in new Name from URI");

    // Check canonical URI encoding (lower case).
    Name name2 = new Name
      ("/hello/sha256digest=" +
       "28bad4b5275bd392dbb670c75cf0b66f13f7942b21e80f55c0e86b374753a548");
    assertEquals(name.get(0), name2.get(1));

    // Check that it will accept a hex value in upper case too.
    name2 = new Name
      ("/hello/sha256digest=" +
       "28BAD4B5275BD392DBB670C75CF0B66F13F7942B21E80F55C0E86B374753A548");
    assertEquals(name.get(0), name2.get(1));

    // This is not valid sha256digest component. It should be treated as generic.
    name2 = new Name
      ("/hello/SHA256DIGEST=" +
       "28BAD4B5275BD392DBB670C75CF0B66F13F7942B21E80F55C0E86B374753A548");
    assertFalse(name.get(0).equals(name2.get(1)));
    assertTrue(name2.get(1).isGeneric());
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
