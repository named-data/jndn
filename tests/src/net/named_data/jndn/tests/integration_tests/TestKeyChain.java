/**
 * Copyright (C) 2017-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/v2/key-chain.t.cpp
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

package src.net.named_data.jndn.tests.integration_tests;

import java.io.IOException;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.pib.Pib;
import net.named_data.jndn.security.pib.PibIdentity;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.security.pib.PibKey;
import net.named_data.jndn.security.tpm.Tpm;
import net.named_data.jndn.security.tpm.TpmBackEnd;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.util.Common;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class TestKeyChain {
  IdentityManagementFixture fixture_;

  @Before
  public void
  setUp() throws KeyChain.Error, PibImpl.Error, SecurityException, IOException
  {
    fixture_ = new IdentityManagementFixture();
  }

  @Test
  public void
  testManagement()
    throws PibImpl.Error, Pib.Error, Tpm.Error, TpmBackEnd.Error, KeyChain.Error, CertificateV2.Error
  {
    Name identityName = new Name("/test/id");
    Name identity2Name = new Name("/test/id2");

    assertEquals(0, fixture_.keyChain_.getPib().getIdentities_().size());
    try {
      fixture_.keyChain_.getPib().getDefaultIdentity();
      fail("Did not throw the expected exception");
    }
    catch (Pib.Error ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    // Create an identity.
    PibIdentity id = fixture_.keyChain_.createIdentityV2(identityName);
    assertTrue(id != null);
    assertTrue(fixture_.keyChain_.getPib().getIdentities_().getIdentities_().containsKey
               (identityName));

    // The first added identity becomes the default identity.
    try {
      fixture_.keyChain_.getPib().getDefaultIdentity();
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }

    // The default key of the added identity must exist.
    PibKey key = null;
    try {
      key = id.getDefaultKey();
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }

    // The default certificate of the default key must exist.
    try {
      key.getDefaultCertificate();
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }

    // Delete the key.
    Name key1Name = key.getName();
    try {
      id.getKey(key1Name);
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }

    assertEquals(1, id.getKeys_().size());
    fixture_.keyChain_.deleteKey(id, key);
/* TODO: Implement key validity.
    // The key instance should not be valid anymore.
    assertTrue(!key);
*/

    try {
      id.getKey(key1Name);
      fail("Did not throw the expected exception");
    }
    catch (Pib.Error ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    assertEquals(0, id.getKeys_().size());

    // Create another key.
    fixture_.keyChain_.createKey(id);
    // The added key becomes the default key.
    try {
      id.getDefaultKey();
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }

    PibKey key2 = id.getDefaultKey();
    assertTrue(key2 != null);
    assertTrue(!key2.getName().equals(key1Name));
    assertEquals(1, id.getKeys_().size());
    try {
      key2.getDefaultCertificate();
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }

    // Create a third key.
    PibKey key3 = fixture_.keyChain_.createKey(id);
    assertTrue(!key3.getName().equals(key2.getName()));
    // The added key will not be the default key, because the default key already exists.
    assertTrue(id.getDefaultKey().getName().equals(key2.getName()));
    assertEquals(2, id.getKeys_().size());
    try {
      key3.getDefaultCertificate();
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }

    // Delete the certificate.
    assertEquals(1, key3.getCertificates_().size());
    CertificateV2 key3Cert1 = (CertificateV2)
      key3.getCertificates_().getCertificates_().values().toArray()[0];
    Name key3CertName = key3Cert1.getName();
    fixture_.keyChain_.deleteCertificate(key3, key3CertName);
    assertEquals(0, key3.getCertificates_().size());
    try {
      key3.getDefaultCertificate();
      fail("Did not throw the expected exception");
    }
    catch (Pib.Error ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    // Add a certificate.
    fixture_.keyChain_.addCertificate(key3, key3Cert1);
    assertEquals(1, key3.getCertificates_().size());
    try {
      key3.getDefaultCertificate();
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }

    // Overwriting the certificate should work.
    fixture_.keyChain_.addCertificate(key3, key3Cert1);
    assertEquals(1, key3.getCertificates_().size());
    // Add another certificate.
    CertificateV2 key3Cert2 = new CertificateV2(key3Cert1);
    Name key3Cert2Name = new Name(key3.getName());
    key3Cert2Name.append("Self");
    key3Cert2Name.appendVersion(1);
    key3Cert2.setName(key3Cert2Name);
    fixture_.keyChain_.addCertificate(key3, key3Cert2);
    assertEquals(2, key3.getCertificates_().size());

    // Set the default certificate.
    assertTrue(key3.getDefaultCertificate().getName().equals(key3CertName));
    fixture_.keyChain_.setDefaultCertificate(key3, key3Cert2);
    assertTrue(key3.getDefaultCertificate().getName().equals(key3Cert2Name));

    // Set the default key.
    assertTrue(id.getDefaultKey().getName().equals(key2.getName()));
    fixture_.keyChain_.setDefaultKey(id, key3);
    assertTrue(id.getDefaultKey().getName().equals(key3.getName()));

    // Set the default identity.
    PibIdentity id2 = fixture_.keyChain_.createIdentityV2(identity2Name);
    assertTrue(fixture_.keyChain_.getPib().getDefaultIdentity().getName().equals
               (id.getName()));
    fixture_.keyChain_.setDefaultIdentity(id2);
    assertTrue(fixture_.keyChain_.getPib().getDefaultIdentity().getName().equals
               (id2.getName()));

    // Delete an identity.
    fixture_.keyChain_.deleteIdentity(id);
/* TODO: Implement identity validity.
    // The identity instance should not be valid any more.
    BOOST_CHECK(!id);
*/
    try {
      fixture_.keyChain_.getPib().getIdentity(identityName);
      fail("Did not throw the expected exception");
    }
    catch (Pib.Error ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    assertTrue(!fixture_.keyChain_.getPib().getIdentities_().getIdentities_().containsKey
               (identityName));
  }

  @Test
  public void
  testSelfSignedCertValidity()
    throws PibImpl.Error, Pib.Error, Tpm.Error, TpmBackEnd.Error, KeyChain.Error
  {
    CertificateV2 certificate = fixture_.addIdentity
      (new Name("/Security/V2/TestKeyChain/SelfSignedCertValidity"))
      .getDefaultKey().getDefaultCertificate();
    assertTrue(certificate.isValid());
    // Check 10 years from now.
    assertTrue(certificate.isValid
      (Common.getNowMilliseconds() + 10 * 365 * 24 * 3600 * 1000.0));
    // Check that notAfter is later than 10 years from now.
    assertTrue(certificate.getValidityPeriod().getNotAfter() >
      Common.getNowMilliseconds() + 10 * 365 * 24 * 3600 * 1000.0);
  }

  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
