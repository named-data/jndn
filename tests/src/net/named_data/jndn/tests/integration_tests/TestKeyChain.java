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
import net.named_data.jndn.security.SafeBag;
import net.named_data.jndn.util.Common;
import net.named_data.jndn.util.Blob;
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

    // Test import key
    Blob testKey = new Blob(new byte[]
            {-128, -3, 2, 23, 6, -3, 1, 43, 7, 43, 8, 3, 110, 100, 110, 8, 4, 116, 101, 115, 116, 8, 3, 75, 69, 89, 8,
            8, -109, 32, -119, 15, 65, 56, 25, 127, 8, 4, 115, 101, 108, 102, 8, 9, -3, 0, 0, 1, 110, -40, -122, -80,
            60, 20, 9, 24, 1, 2, 25, 4, 0, 54, -18, -128, 21, 91, 48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6,
            8, 42, -122, 72, -50, 61, 3, 1, 7, 3, 66, 0, 4, 44, 23, -66, 73, -9, 119, -44, 66, -10, -82, -91, 73, -96,
            -15, 104, -6, 53, 119, 41, -34, -73, -71, 76, 40, 34, -67, -66, -37, 113, 32, -110, 87, 10, 46, -81, 101,
            -54, 38, 98, 81, -46, 110, 4, -69, 78, -123, -109, -15, -103, -120, -64, 124, 49, 72, -47, 77, -122, -62,
            64, 82, 17, 2, -26, -39, 22, 75, 27, 1, 3, 28, 28, 7, 26, 8, 3, 110, 100, 110, 8, 4, 116, 101, 115, 116, 8,
            3, 75, 69, 89, 8, 8, -109, 32, -119, 15, 65, 56, 25, 127, -3, 0, -3, 38, -3, 0, -2, 15, 49, 57, 55, 48, 48,
            49, 48, 49, 84, 48, 48, 48, 48, 48, 48, -3, 0, -1, 15, 50, 48, 51, 57, 49, 50, 48, 49, 84, 48, 48, 48, 53,
            51, 53, 23, 71, 48, 69, 2, 33, 0, -61, -49, -65, 125, 21, 121, -34, -98, 60, -25, -5, 53, -32, -120, -65,
            26, 8, -37, -63, -125, 117, -48, -86, 121, -65, -100, 61, 21, -94, -118, 120, 40, 2, 32, 73, 114, -77, 120,
            113, -5, -52, -126, -26, -88, -81, 115, -11, 15, 78, 21, -85, -113, -38, -114, 127, -107, 13, -81, 13, 23,
            -67, -5, 118, 119, 19, -112, -127, -26, 48, -127, -29, 48, 78, 6, 9, 42, -122, 72, -122, -9, 13, 1, 5, 13,
            48, 65, 48, 41, 6, 9, 42, -122, 72, -122, -9, 13, 1, 5, 12, 48, 28, 4, 8, 62, -1, 17, 54, -107, 101, 80,
            109, 2, 2, 8, 0, 48, 12, 6, 8, 42, -122, 72, -122, -9, 13, 2, 9, 5, 0, 48, 20, 6, 8, 42, -122, 72, -122, -9,
            13, 3, 7, 4, 8, 17, -36, -101, 19, 19, 38, 9, 7, 4, -127, -112, -45, -43, -18, -67, -55, 85, 91, 124, 27,
            -123, -48, 127, 107, -49, -98, 51, 36, -123, 124, -78, -17, -118, 100, 126, -61, -64, 8, -73, 69, 40, 39,
            -96, -14, -18, -23, -37, -16, -88, -80, 90, 6, -48, 108, 109, 101, 49, 122, 74, -120, -112, -27, -18, -6,
            -111, -101, 117, -116, -100, 83, -45, 7, 19, 79, -87, 107, -47, 13, -51, -113, 40, -117, -17, 113, -59, 100,
            107, -66, -40, -71, 55, 39, 79, 97, -100, 82, -94, -110, -104, -91, -110, 21, 1, -1, 102, 95, -22, -111,
            112, -25, -59, 97, 60, -80, 107, -6, -70, 18, -17, -83, -53, -122, 42, -58, 82, 96, -30, -76, -18, -34, -5,
            -71, -70, 66, 114, 34, -7, 24, -31, -2, -49, -23, 20, 75, 94, -98, 25, -69, 46, 85, -76, 127, 125, -88, 117}
            );
    Blob password = new Blob(new byte[]
            {112, 97, 115, 115, 119, 111, 114, 100}
            );
    Name testName = new Name("/ndn/test/");

     try {
       SafeBag safebag = new SafeBag(testKey);
       fixture_.keyChain_.importSafeBag(safebag, password.buf());
     } catch (Throwable ex) {
       fail("Unexpected exception: " + ex.getMessage());
     }
     assertTrue(fixture_.keyChain_.getPib().getIdentities_().getIdentities_().containsKey
                (testName));
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
