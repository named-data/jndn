/**
 * Copyright (C) 2017-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/pib/detail/key-impl.t.cpp
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
import net.named_data.jndn.Sha256WithRsaSignature;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.security.KeyType;
import net.named_data.jndn.security.pib.Pib;
import net.named_data.jndn.security.pib.detail.PibKeyImpl;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.security.pib.PibMemory;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;
import org.junit.Test;
import org.junit.Before;

public class TestPibKeyImpl {
  @Before
  public void
  setUp() throws EncodingException, CertificateV2.Error
  {
    fixture = new PibDataFixture();
  }

  PibDataFixture fixture;

  @Test
  public void
  testBasic() throws PibImpl.Error, Pib.Error
  {
    PibMemory pibImpl = new PibMemory();
    PibKeyImpl key11 = new PibKeyImpl
      (fixture.id1Key1Name, fixture.id1Key1.buf(), pibImpl);

    assertTrue(fixture.id1Key1Name.equals(key11.getName()));
    assertTrue(fixture.id1.equals(key11.getIdentityName()));
    assertEquals(KeyType.RSA, key11.getKeyType());
    assertTrue(key11.getPublicKey().equals(fixture.id1Key1));

    PibKeyImpl key11FromBackend = new PibKeyImpl(fixture.id1Key1Name, pibImpl);
    assertTrue(fixture.id1Key1Name.equals(key11FromBackend.getName()));
    assertTrue(fixture.id1.equals(key11FromBackend.getIdentityName()));
    assertEquals(KeyType.RSA, key11FromBackend.getKeyType());
    assertTrue(key11FromBackend.getPublicKey().equals(fixture.id1Key1));
  }

  @Test
  public void
  testCertificateOperation() throws PibImpl.Error, Pib.Error, CertificateV2.Error
  {
    PibMemory pibImpl = new PibMemory();
    PibKeyImpl key11 = new PibKeyImpl
      (fixture.id1Key1Name, fixture.id1Key1.buf(), pibImpl);
    try {
      new PibKeyImpl(fixture.id1Key1Name, pibImpl);
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }

    // The key should not have any certificates.
    assertEquals(0, key11.getCertificates_().size());

    // Getting a non-existing certificate should throw Pib.Error.
    try {
      key11.getCertificate(fixture.id1Key1Cert1.getName());
      fail("Did not throw the expected exception");
    }
    catch (Pib.Error ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    // Getting the non-existing default certificate should throw Pib.Error.
    try {
      key11.getDefaultCertificate();
      fail("Did not throw the expected exception");
    }
    catch (Pib.Error ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    // Setting a non-existing certificate as the default should throw Pib.Error.
    try {
      key11.setDefaultCertificate(fixture.id1Key1Cert1.getName());
      fail("Did not throw the expected exception");
    }
    catch (Pib.Error ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    // Add a certificate.
    key11.addCertificate(fixture.id1Key1Cert1);
    try {
       key11.getCertificate(fixture.id1Key1Cert1.getName());
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }

    // The new certificate becomes the default when there was no default.
    try {
      key11.getDefaultCertificate();
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }
    CertificateV2 defaultCert0 = key11.getDefaultCertificate();
    assertTrue(fixture.id1Key1Cert1.getName().equals(defaultCert0.getName()));
    // Use the wire encoding to check equivalence.
    assertTrue(fixture.id1Key1Cert1.wireEncode().equals
               (defaultCert0.wireEncode()));

    // Remove the certificate.
    key11.removeCertificate(fixture.id1Key1Cert1.getName());
    try {
      key11.getCertificate(fixture.id1Key1Cert1.getName());
      fail("Did not throw the expected exception");
    }
    catch (Pib.Error ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    try {
      key11.getDefaultCertificate();
      fail("Did not throw the expected exception");
    }
    catch (Pib.Error ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    // Set the default certificate directly.
    try {
      key11.setDefaultCertificate(fixture.id1Key1Cert1);
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }
    try {
      key11.getDefaultCertificate();
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }
    try {
      key11.getCertificate(fixture.id1Key1Cert1.getName());
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }

    // Check the default cert.
    CertificateV2 defaultCert1 = key11.getDefaultCertificate();
    assertTrue(fixture.id1Key1Cert1.getName().equals(defaultCert1.getName()));
    assertTrue(defaultCert1.wireEncode().equals(fixture.id1Key1Cert1.wireEncode()));

    // Add another certificate.
    key11.addCertificate(fixture.id1Key1Cert2);
    assertEquals(2, key11.getCertificates_().size());

    // Set the default certificate using a name.
    try {
      key11.setDefaultCertificate(fixture.id1Key1Cert2.getName());
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }
    try {
      key11.getDefaultCertificate();
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }
    CertificateV2 defaultCert2 = key11.getDefaultCertificate();
    assertTrue(fixture.id1Key1Cert2.getName().equals(defaultCert2.getName()));
    assertTrue(defaultCert2.wireEncode().equals(fixture.id1Key1Cert2.wireEncode()));

    // Remove a certificate.
    key11.removeCertificate(fixture.id1Key1Cert1.getName());
    try {
      key11.getCertificate(fixture.id1Key1Cert1.getName());
      fail("Did not throw the expected exception");
    }
    catch (Pib.Error ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    assertEquals(1, key11.getCertificates_().size());

    // Set the default certificate directly again, which should change the default.
    try {
      key11.setDefaultCertificate(fixture.id1Key1Cert1);
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }
    CertificateV2 defaultCert3 = key11.getDefaultCertificate();
    assertTrue(fixture.id1Key1Cert1.getName().equals(defaultCert3.getName()));
    assertTrue(defaultCert3.wireEncode().equals(fixture.id1Key1Cert1.wireEncode()));
    assertEquals(2, key11.getCertificates_().size());

    // Remove all certificates.
    key11.removeCertificate(fixture.id1Key1Cert1.getName());
    try {
      key11.getCertificate(fixture.id1Key1Cert1.getName());
      fail("Did not throw the expected exception");
    }
    catch (Pib.Error ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    assertEquals(1, key11.getCertificates_().size());
    key11.removeCertificate(fixture.id1Key1Cert2.getName());
    try {
      key11.getCertificate(fixture.id1Key1Cert2.getName());
      fail("Did not throw the expected exception");
    }
    catch (Pib.Error ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    try {
      key11.getDefaultCertificate();
      fail("Did not throw the expected exception");
    }
    catch (Pib.Error ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }
    assertEquals(0, key11.getCertificates_().size());
  }

  @Test
  public void
  testOverwrite() throws PibImpl.Error, Pib.Error, CertificateV2.Error
  {
    PibMemory pibImpl = new PibMemory();

    try {
      new PibKeyImpl(fixture.id1Key1Name, pibImpl);
      fail("Did not throw the expected exception");
    }
    catch (Pib.Error ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    new PibKeyImpl(fixture.id1Key1Name, fixture.id1Key1.buf(), pibImpl);
    PibKeyImpl key1 = new PibKeyImpl(fixture.id1Key1Name, pibImpl);

    // Overwriting the key should work.
    new PibKeyImpl(fixture.id1Key1Name, fixture.id1Key2.buf(), pibImpl);
    PibKeyImpl key2 = new PibKeyImpl(fixture.id1Key1Name, pibImpl);

    // key1 should have cached the original public key.
    assertTrue(!key1.getPublicKey().equals(key2.getPublicKey()));
    assertTrue(key2.getPublicKey().equals(fixture.id1Key2));

    key1.addCertificate(fixture.id1Key1Cert1);
    // Use the wire encoding to check equivalence.
    assertTrue
      (key1.getCertificate(fixture.id1Key1Cert1.getName()).wireEncode().equals
       (fixture.id1Key1Cert1.wireEncode()));

    CertificateV2 otherCert = new CertificateV2(fixture.id1Key1Cert1);
    ((Sha256WithRsaSignature)otherCert.getSignature()).getValidityPeriod()
      .setPeriod(Common.getNowMilliseconds(), Common.getNowMilliseconds() + 1000);
    // Don't bother resigning so we don't have to load a private key.

    assertTrue(fixture.id1Key1Cert1.getName().equals(otherCert.getName()));
    assertTrue(otherCert.getContent().equals(fixture.id1Key1Cert1.getContent()));
    assertFalse(otherCert.wireEncode().equals(fixture.id1Key1Cert1.wireEncode()));

    key1.addCertificate(otherCert);

    assertTrue
      (key1.getCertificate(fixture.id1Key1Cert1.getName()).wireEncode().equals
       (otherCert.wireEncode()));
  }

  @Test
  public void
  testErrors() throws PibImpl.Error, Pib.Error, CertificateV2.Error
  {
    PibMemory pibImpl = new PibMemory();

    try {
      new PibKeyImpl(fixture.id1Key1Name, pibImpl);
      fail("Did not throw the expected exception");
    }
    catch (Pib.Error ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    PibKeyImpl key11 = new PibKeyImpl
      (fixture.id1Key1Name, fixture.id1Key1.buf(), pibImpl);

    try {
      new PibKeyImpl(new Name("/wrong"), pibImpl);
      fail("Did not throw the expected exception");
    }
    catch (IllegalArgumentException ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    try {
      new PibKeyImpl(new Name("/wrong"), fixture.id1Key1.buf(), pibImpl);
      fail("Did not throw the expected exception");
    }
    catch (IllegalArgumentException ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    Blob wrongKey = new Blob("");
    try {
      new PibKeyImpl(fixture.id1Key2Name, wrongKey.buf(), pibImpl);
      fail("Did not throw the expected exception");
    }
    catch (IllegalArgumentException ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    key11.addCertificate(fixture.id1Key1Cert1);
    try {
      key11.addCertificate(fixture.id1Key2Cert1);
      fail("Did not throw the expected exception");
    }
    catch (IllegalArgumentException ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    try {
      key11.removeCertificate(fixture.id1Key2Cert1.getName());
      fail("Did not throw the expected exception");
    }
    catch (IllegalArgumentException ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    try {
      key11.getCertificate(fixture.id1Key2Cert1.getName());
      fail("Did not throw the expected exception");
    }
    catch (IllegalArgumentException ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    try {
      key11.setDefaultCertificate(fixture.id1Key2Cert1);
      fail("Did not throw the expected exception");
    }
    catch (IllegalArgumentException ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    try {
      key11.setDefaultCertificate(fixture.id1Key2Cert1.getName());
      fail("Did not throw the expected exception");
    }
    catch (IllegalArgumentException ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }
  }
}
