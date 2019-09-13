/**
 * Copyright (C) 2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From PSync unit tests:
 * https://github.com/named-data/PSync/blob/master/tests/test-iblt.cpp
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

import java.io.IOException;
import java.util.HashSet;
import net.named_data.jndn.Name;
import net.named_data.jndn.sync.detail.InvertibleBloomLookupTable;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.Test;

public class TestInvertibleBloomLookupTable {
  @Test
  public void
  testEqual() throws IOException
  {
    int size = 10;

    InvertibleBloomLookupTable iblt1 = new InvertibleBloomLookupTable(size);
    InvertibleBloomLookupTable iblt2 = new InvertibleBloomLookupTable(size);

    assertTrue(iblt1.equals(iblt2));

    String prefix = new Name("/test/memphis").appendNumber(1).toUri();
    long newHash = Common.murmurHash3(11, new Blob(prefix).getImmutableArray());
    iblt1.insert(newHash);
    iblt2.insert(newHash);
    assertTrue(iblt1.equals(iblt2));

    Name ibfName1 = new Name("/sync");
    Name ibfName2 = new Name("/sync");
    ibfName1.append(iblt1.encode());
    ibfName2.append(iblt2.encode());
    assertTrue(ibfName1.equals(ibfName2));
  }

  @Test
  public void
  testNameAppendAndExtract() throws IOException
  {
    int size = 10;

    InvertibleBloomLookupTable iblt = new InvertibleBloomLookupTable(size);
    String prefix = new Name("/test/memphis").appendNumber(1).toUri();
    long newHash = Common.murmurHash3(11, new Blob(prefix).getImmutableArray());
    iblt.insert(newHash);

    Blob expectedEncoding = new Blob(new int[] {
      0x78, 0xda, 0x63, 0x64, 0x60, 0x60, 0xd8, 0x55, 0xb5, 0xfc,
      0x5b, 0xb2, 0xef, 0xe2, 0x6c, 0x06, 0x0a, 0x00, 0x23, 0x1d,
      0xcd, 0x01, 0x00, 0x65, 0x29, 0x0d, 0xb1
    });

    Name ibltName = new Name("sync");
    Blob encodedIblt = iblt.encode();
    assertTrue(encodedIblt.equals(expectedEncoding));
    ibltName.append(encodedIblt);

    InvertibleBloomLookupTable received = new InvertibleBloomLookupTable(size);
    received.initialize(ibltName.get(-1).getValue());

    assertTrue(iblt.equals(received));

    InvertibleBloomLookupTable receivedDifferentSize = new InvertibleBloomLookupTable(20);
    try {
      receivedDifferentSize.initialize(ibltName.get(-1).getValue());
      fail("Did not throw the expected exception");
    }
    catch (AssertionError ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }
  }

  @Test
  public void
  testCopyInsertErase()
  {
    int size = 10;

    InvertibleBloomLookupTable iblt1 = new InvertibleBloomLookupTable(size);

    String prefix = new Name("/test/memphis").appendNumber(1).toUri();
    long hash1 = Common.murmurHash3(11, new Blob(prefix).getImmutableArray());
    iblt1.insert(hash1);

    InvertibleBloomLookupTable iblt2 = new InvertibleBloomLookupTable(iblt1);
    iblt2.erase(hash1);
    prefix = new Name("/test/memphis").appendNumber(2).toUri();
    long hash3 = Common.murmurHash3(11, new Blob(prefix).getImmutableArray());
    iblt2.insert(hash3);

    iblt1.erase(hash1);
    prefix = new Name("/test/memphis").appendNumber(5).toUri();
    long hash5 = Common.murmurHash3(11, new Blob(prefix).getImmutableArray());
    iblt1.insert(hash5);

    iblt2.erase(hash3);
    iblt2.insert(hash5);

    assertTrue(iblt1.equals(iblt2));
  }

  @Test
  public void
  testHigherSequence()
  {
    // This is the case where we can't recognize if the received IBF has a higher
    // sequence number. This is relevant to the full sync case.
    int size = 10;

    InvertibleBloomLookupTable ownIblt = new InvertibleBloomLookupTable(size);
    InvertibleBloomLookupTable receivedIblt = new InvertibleBloomLookupTable(size);

    String prefix = new Name("/test/memphis").appendNumber(3).toUri();
    long hash1 = Common.murmurHash3(11, new Blob(prefix).getImmutableArray());
    ownIblt.insert(hash1);

    String prefix2 = new Name("/test/memphis").appendNumber(4).toUri();
    long hash2 = Common.murmurHash3(11, new Blob(prefix2).getImmutableArray());
    receivedIblt.insert(hash2);

    InvertibleBloomLookupTable diff = ownIblt.difference(receivedIblt);
    HashSet<Long> positive = new HashSet<Long>();
    HashSet<Long> negative = new HashSet<Long>();

    assertTrue(diff.listEntries(positive, negative));
    assertEquals(1, positive.size());
    assertTrue((Long)positive.toArray()[0] == hash1);

    assertEquals(1, negative.size());
    assertTrue((Long)negative.toArray()[0] == hash2);
  }

  @Test
  public void
  testDifference()
  {
    int size = 10;

    InvertibleBloomLookupTable ownIblt = new InvertibleBloomLookupTable(size);

    InvertibleBloomLookupTable receivedIblt = new InvertibleBloomLookupTable(ownIblt);

    InvertibleBloomLookupTable diff = ownIblt.difference(receivedIblt);

    // Non-empty positive means we have some elements that the other doesn't.
    HashSet<Long> positive = new HashSet<Long>();
    HashSet<Long> negative = new HashSet<Long>();

    assertTrue(diff.listEntries(positive, negative));
    assertEquals(0, positive.size());
    assertEquals(0, negative.size());

    String prefix = new Name("/test/memphis").appendNumber(1).toUri();
    long newHash = Common.murmurHash3(11, new Blob(prefix).getImmutableArray());
    ownIblt.insert(newHash);

    diff = ownIblt.difference(receivedIblt);
    assertTrue(diff.listEntries(positive, negative));
    assertEquals(1, positive.size());
    assertEquals(0, negative.size());

    prefix = new Name("/test/csu").appendNumber(1).toUri();
    newHash = Common.murmurHash3(11, new Blob(prefix).getImmutableArray());
    receivedIblt.insert(newHash);

    diff = ownIblt.difference(receivedIblt);
    assertTrue(diff.listEntries(positive, negative));
    assertEquals(1, positive.size());
    assertEquals(1, negative.size());
  }

  @Test
  public void
  testDifferenceBwOversizedIblts()
  {
    // Insert 50 elements into an IBLT of size 10. Then check that we can still
    // list the difference even though we can't list the IBLT itself.

    int size = 10;

    InvertibleBloomLookupTable ownIblt = new InvertibleBloomLookupTable(size);

    for (int i = 0; i < 50; ++i) {
      String prefix = new Name("/test/memphis" + i).appendNumber(1).toUri();
      long newHash = Common.murmurHash3(11, new Blob(prefix).getImmutableArray());
      ownIblt.insert(newHash);
    }

    InvertibleBloomLookupTable receivedIblt = new InvertibleBloomLookupTable(ownIblt);

    String prefix = new Name("/test/ucla").appendNumber(1).toUri();
    long newHash = Common.murmurHash3(11, new Blob(prefix).getImmutableArray());
    ownIblt.insert(newHash);

    InvertibleBloomLookupTable diff = ownIblt.difference(receivedIblt);

    HashSet<Long> positive = new HashSet<Long>();
    HashSet<Long> negative = new HashSet<Long>();
    assertTrue(diff.listEntries(positive, negative));
    assertEquals(1, positive.size());
    assertTrue(newHash == (Long)positive.toArray()[0]);
    assertEquals(0, negative.size());

    assertTrue(!ownIblt.listEntries(positive, negative));
    assertTrue(!receivedIblt.listEntries(positive, negative));
  }

  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
