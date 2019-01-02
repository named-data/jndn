/**
 * Copyright (C) 2017-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/pib/identity-container.t.cpp
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
import net.named_data.jndn.security.pib.PibIdentity;
import net.named_data.jndn.security.pib.PibIdentityContainer;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.security.pib.PibMemory;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.util.Common;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.Test;
import org.junit.Before;

public class TestPibIdentityContainer {
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
    PibIdentityContainer container = new PibIdentityContainer(pibImpl);
    assertEquals(0, container.size());
    assertEquals(0, container.getIdentities_().size());

    // Add the first identity.
    PibIdentity identity11 = container.add(fixture.id1);
    assertTrue(fixture.id1.equals(identity11.getName()));
    assertEquals(1, container.size());
    assertEquals(1, container.getIdentities_().size());
    assertTrue(container.getIdentities_().containsKey(fixture.id1));

    // Add the same identity again.
    PibIdentity identity12 = container.add(fixture.id1);
    assertTrue(fixture.id1.equals(identity12.getName()));
    assertEquals(1, container.size());
    assertEquals(1, container.getIdentities_().size());
    assertTrue(container.getIdentities_().containsKey(fixture.id1));

    // Add the second identity.
    PibIdentity identity21 = container.add(fixture.id2);
    assertTrue(fixture.id2.equals(identity21.getName()));
    assertEquals(2, container.size());
    assertEquals(2, container.getIdentities_().size());
    assertTrue(container.getIdentities_().containsKey(fixture.id1));
    assertTrue(container.getIdentities_().containsKey(fixture.id2));

    // Get identities.
    try {
      container.get(fixture.id1);
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }
    try {
      container.get(fixture.id2);
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }
    try {
      container.get(new Name("/non-existing"));
      fail("Did not throw the expected exception");
    }
    catch (Pib.Error ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    // Check the identity.
    PibIdentity identity1 = container.get(fixture.id1);
    PibIdentity identity2 = container.get(fixture.id2);
    assertTrue(fixture.id1.equals(identity1.getName()));
    assertTrue(fixture.id2.equals(identity2.getName()));

    // Create another container from the same PibImpl. The cache should be empty.
    PibIdentityContainer container2 = new PibIdentityContainer(pibImpl);
    assertEquals(2, container2.size());
    assertEquals(0, container2.getIdentities_().size());

    // Get keys. The cache should be filled.
    try {
      container2.get(fixture.id1);
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }
    assertEquals(2, container2.size());
    assertEquals(1, container2.getIdentities_().size());

    try {
      container2.get(fixture.id2);
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }
    assertEquals(2, container2.size());
    assertEquals(2, container2.getIdentities_().size());

    // Remove a key.
    container2.remove(fixture.id1);
    assertEquals(1, container2.size());
    assertEquals(1, container2.getIdentities_().size());
    assertTrue(!container2.getIdentities_().containsKey(fixture.id1));
    assertTrue(container2.getIdentities_().containsKey(fixture.id2));

    // Remove another key.
    container2.remove(fixture.id2);
    assertEquals(0, container2.size());
    assertEquals(0, container2.getIdentities_().size());
    assertTrue(!container2.getIdentities_().containsKey(fixture.id2));
  }

  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}