/**
 * Copyright (C) 2017 Regents of the University of California.
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

package net.named_data.jndn.tests.unit_tests;

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
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class TestKeyChain {
  KeyChain keyChain_;

  @Before
  public void
  setUp() throws KeyChain.Error, PibImpl.Error, SecurityException, IOException
  {
    keyChain_ = new KeyChain("pib-memory:", "tpm-memory:");
  }

  @Test
  public void
  testManagement()
    throws PibImpl.Error, Pib.Error, Tpm.Error, TpmBackEnd.Error, KeyChain.Error, CertificateV2.Error
  {
    Name identityName = new Name("/test/id");
    Name identity2Name = new Name("/test/id2");

    assertEquals(0, keyChain_.getPib().getIdentities_().size());
    try {
      keyChain_.getPib().getDefaultIdentity();
      fail("Did not throw the expected exception");
    }
    catch (Pib.Error ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    // Create an identity.
    PibIdentity id = keyChain_.createIdentityV2(identityName);
    assertTrue(id != null);
    assertTrue(keyChain_.getPib().getIdentities_().getIdentities_().containsKey
               (identityName));

    // The first added identity becomes the default identity.
    try {
      keyChain_.getPib().getDefaultIdentity();
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
    keyChain_.deleteKey(id, key);
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
    keyChain_.createKey(id);
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
    PibKey key3 = keyChain_.createKey(id);
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
    CertificateV2 key3Cert1 =
      key3.getCertificates_().getCertificates_().values().iterator().next();
    Name key3CertName = key3Cert1.getName();
    keyChain_.deleteCertificate(key3, key3CertName);
    assertEquals(0, key3.getCertificates_().size());
    try {
      key3.getDefaultCertificate();
      fail("Did not throw the expected exception");
    }
    catch (Pib.Error ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    // Add a certificate.
    keyChain_.addCertificate(key3, key3Cert1);
    assertEquals(1, key3.getCertificates_().size());
    try {
      key3.getDefaultCertificate();
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }

    // Overwriting the certificate should work.
    keyChain_.addCertificate(key3, key3Cert1);
    assertEquals(1, key3.getCertificates_().size());
    // Add another certificate.
    CertificateV2 key3Cert2 = new CertificateV2(key3Cert1);
    Name key3Cert2Name = new Name(key3.getName());
    key3Cert2Name.append("Self");
    key3Cert2Name.appendVersion(1);
    key3Cert2.setName(key3Cert2Name);
    keyChain_.addCertificate(key3, key3Cert2);
    assertEquals(2, key3.getCertificates_().size());

    // Set the default certificate.
    assertTrue(key3.getDefaultCertificate().getName().equals(key3CertName));
    keyChain_.setDefaultCertificate(key3, key3Cert2);
    assertTrue(key3.getDefaultCertificate().getName().equals(key3Cert2Name));

    // Set the default key.
    assertTrue(id.getDefaultKey().getName().equals(key2.getName()));
    keyChain_.setDefaultKey(id, key3);
    assertTrue(id.getDefaultKey().getName().equals(key3.getName()));

    // Set the default identity.
    PibIdentity id2 = keyChain_.createIdentityV2(identity2Name);
    assertTrue(keyChain_.getPib().getDefaultIdentity().getName().equals(id.getName()));
    keyChain_.setDefaultIdentity(id2);
    assertTrue(keyChain_.getPib().getDefaultIdentity().getName().equals(id2.getName()));

    // Delete an identity.
    keyChain_.deleteIdentity(id);
/* TODO: Implement identity validity.
    // The identity instance should not be valid any more.
    BOOST_CHECK(!id);
*/
    try {
      keyChain_.getPib().getIdentity(identityName);
      fail("Did not throw the expected exception");
    }
    catch (Pib.Error ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    assertTrue(!keyChain_.getPib().getIdentities_().getIdentities_().containsKey
               (identityName));
  }
}
