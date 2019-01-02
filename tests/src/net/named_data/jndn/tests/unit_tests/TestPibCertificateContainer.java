/**
 * Copyright (C) 2017-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/pib/certificate-container.t.cpp
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
import net.named_data.jndn.security.pib.PibCertificateContainer;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.security.pib.PibMemory;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.util.Common;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.Test;
import org.junit.Before;

public class TestPibCertificateContainer {
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
    PibCertificateContainer container =
      new PibCertificateContainer(fixture.id1Key1Name, pibImpl);
    assertEquals(0, container.size());
    assertEquals(0, container.getCertificates_().size());

    // Add a certificate.
    container.add(fixture.id1Key1Cert1);
    assertEquals(1, container.size());
    assertEquals(1, container.getCertificates_().size());
    assertTrue
      (container.getCertificates_().containsKey(fixture.id1Key1Cert1.getName()));

    // Add the same certificate again.
    container.add(fixture.id1Key1Cert1);
    assertEquals(1, container.size());
    assertEquals(1, container.getCertificates_().size());
    assertTrue
      (container.getCertificates_().containsKey(fixture.id1Key1Cert1.getName()));

    // Add another certificate.
    container.add(fixture.id1Key1Cert2);
    assertEquals(2, container.size());
    assertEquals(2, container.getCertificates_().size());
    assertTrue
      (container.getCertificates_().containsKey(fixture.id1Key1Cert1.getName()));
    assertTrue
      (container.getCertificates_().containsKey(fixture.id1Key1Cert2.getName()));

    // Get the certificates.
    try {
      container.get(fixture.id1Key1Cert1.getName());
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }
    try {
      container.get(fixture.id1Key1Cert2.getName());
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }
    Name id1Key1Cert3Name = new Name(fixture.id1Key1Name);
    id1Key1Cert3Name.append("issuer").appendVersion(3);
    try {
      container.get(id1Key1Cert3Name);
      fail("Did not throw the expected exception");
    }
    catch (Pib.Error ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    // Check the certificates.
    CertificateV2 cert1 = container.get(fixture.id1Key1Cert1.getName());
    CertificateV2 cert2 = container.get(fixture.id1Key1Cert2.getName());
    // Use the wire encoding to check equivalence.
    assertTrue(cert1.wireEncode().equals(fixture.id1Key1Cert1.wireEncode()));
    assertTrue(cert2.wireEncode().equals(fixture.id1Key1Cert2.wireEncode()));

    // Create another container with the same PibImpl. The cache should be empty.
    PibCertificateContainer container2 =
      new PibCertificateContainer(fixture.id1Key1Name, pibImpl);
    assertEquals(2, container2.size());
    assertEquals(0, container2.getCertificates_().size());

    // Get a certificate. The cache should be filled.
    try {
      container2.get(fixture.id1Key1Cert1.getName());
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }
    assertEquals(2, container2.size());
    assertEquals(1, container2.getCertificates_().size());

    try {
      container2.get(fixture.id1Key1Cert2.getName());
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }
    assertEquals(2, container2.size());
    assertEquals(2, container2.getCertificates_().size());

    // Remove a certificate.
    container2.remove(fixture.id1Key1Cert1.getName());
    assertEquals(1, container2.size());
    assertEquals(1, container2.getCertificates_().size());
    assertTrue
      (!container2.getCertificates_().containsKey(fixture.id1Key1Cert1.getName()));
    assertTrue
      (container2.getCertificates_().containsKey(fixture.id1Key1Cert2.getName()));

    // Remove another certificate.
    container2.remove(fixture.id1Key1Cert2.getName());
    assertEquals(0, container2.size());
    assertEquals(0, container2.getCertificates_().size());
    assertTrue
      (!container2.getCertificates_().containsKey(fixture.id1Key1Cert2.getName()));
  }
  @Test
  public void
  testErrors() throws PibImpl.Error
  {
    PibMemory pibImpl = new PibMemory();

    PibCertificateContainer container =
      new PibCertificateContainer(fixture.id1Key1Name, pibImpl);

    try {
      container.add(fixture.id1Key2Cert1);
      fail("Did not throw the expected exception");
    }
    catch (IllegalArgumentException ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    try {
      container.remove(fixture.id1Key2Cert1.getName());
      fail("Did not throw the expected exception");
    }
    catch (IllegalArgumentException ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    try {
      container.get(fixture.id1Key2Cert1.getName());
      fail("Did not throw the expected exception");
    }
    catch (IllegalArgumentException ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }
  }

  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}