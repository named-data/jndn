/**
 * Copyright (C) 2017-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/pib/key-container.t.cpp
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
import net.named_data.jndn.security.pib.Pib;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.security.pib.PibKey;
import net.named_data.jndn.security.pib.PibKeyContainer;
import net.named_data.jndn.security.pib.PibMemory;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.util.Common;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.Test;
import org.junit.Before;

public class TestPibKeyContainer {
  @Before
  public void
  setUp() throws EncodingException, CertificateV2.Error
  {
    fixture = new PibDataFixture();
  }

  PibDataFixture fixture;

  @Test
  public void
  testBasic() throws PibImpl.Error, CertificateV2.Error, Pib.Error
  {
    PibMemory pibImpl = new PibMemory();

    // Start with an empty container.
    PibKeyContainer container = new PibKeyContainer(fixture.id1, pibImpl);
    assertEquals(0, container.size());
    assertEquals(0, container.getKeys_().size());

    // Add the first key.
    PibKey key11 = container.add(fixture.id1Key1.buf(), fixture.id1Key1Name);
    assertTrue(fixture.id1Key1Name.equals(key11.getName()));
    assertTrue(key11.getPublicKey().equals(fixture.id1Key1));
    assertEquals(1, container.size());
    assertEquals(1, container.getKeys_().size());
    assertTrue(container.getKeys_().containsKey(fixture.id1Key1Name));

    // Add the same key again.
    PibKey key12 = container.add(fixture.id1Key1.buf(), fixture.id1Key1Name);
    assertTrue(fixture.id1Key1Name.equals(key12.getName()));
    assertTrue(key12.getPublicKey().equals(fixture.id1Key1));
    assertEquals(1, container.size());
    assertEquals(1, container.getKeys_().size());
    assertTrue(container.getKeys_().containsKey(fixture.id1Key1Name));

    // Add the second key.
    PibKey key21 = container.add(fixture.id1Key2.buf(), fixture.id1Key2Name);
    assertTrue(fixture.id1Key2Name.equals(key21.getName()));
    assertTrue(key21.getPublicKey().equals(fixture.id1Key2));
    assertEquals(2, container.size());
    assertEquals(2, container.getKeys_().size());
    assertTrue(container.getKeys_().containsKey(fixture.id1Key1Name));
    assertTrue(container.getKeys_().containsKey(fixture.id1Key2Name));

    // Get keys.
    try {
      container.get(fixture.id1Key1Name);
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }
    try {
      container.get(fixture.id1Key2Name);
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }
    Name id1Key3Name = PibKey.constructKeyName
      (fixture.id1, new Name.Component("non-existing-id"));
    try {
      container.get(id1Key3Name);
      fail("Did not throw the expected exception");
    }
    catch (Pib.Error ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    // Get and check keys.
    PibKey key1 = container.get(fixture.id1Key1Name);
    PibKey key2 = container.get(fixture.id1Key2Name);
    assertTrue(fixture.id1Key1Name.equals(key1.getName()));
    assertTrue(key1.getPublicKey().equals(fixture.id1Key1));
    assertEquals(fixture.id1Key2Name, key2.getName());
    assertTrue(key2.getPublicKey().equals(fixture.id1Key2));

    // Create another container using the same PibImpl. The cache should be empty.
    PibKeyContainer container2 = new PibKeyContainer(fixture.id1, pibImpl);
    assertEquals(2, container2.size());
    assertEquals(0, container2.getKeys_().size());

    // Get a key. The cache should be filled.
    try {
      container2.get(fixture.id1Key1Name);
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }
    assertEquals(2, container2.size());
    assertEquals(1, container2.getKeys_().size());

    try {
      container2.get(fixture.id1Key2Name);
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }
    assertEquals(2, container2.size());
    assertEquals(2, container2.getKeys_().size());

    // Remove a key.
    container2.remove(fixture.id1Key1Name);
    assertEquals(1, container2.size());
    assertEquals(1, container2.getKeys_().size());
    assertTrue(!container2.getKeys_().containsKey(fixture.id1Key1Name));
    assertTrue(container2.getKeys_().containsKey(fixture.id1Key2Name));

    // Remove another key.
    container2.remove(fixture.id1Key2Name);
    assertEquals(0, container2.size());
    assertEquals(0, container2.getKeys_().size());
    assertTrue(!container2.getKeys_().containsKey(fixture.id1Key2Name));
  }

  @Test
  public void
  testErrors() throws PibImpl.Error
  {
    PibMemory pibImpl = new PibMemory();

    PibKeyContainer container = new PibKeyContainer(fixture.id1, pibImpl);

    try {
      container.add(fixture.id2Key1.buf(), fixture.id2Key1Name);
      fail("Did not throw the expected exception");
    }
    catch (IllegalArgumentException ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    try {
      container.remove(fixture.id2Key1Name);
      fail("Did not throw the expected exception");
    }
    catch (IllegalArgumentException ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    try {
      container.get(fixture.id2Key1Name);
      fail("Did not throw the expected exception");
    }
    catch (IllegalArgumentException ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }
  }

  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}