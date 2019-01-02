/**
 * Copyright (C) 2017-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/pib/pib-impl.t.cpp
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

import java.io.File;
import java.util.HashSet;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.security.pib.Pib;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.security.pib.PibMemory;
import net.named_data.jndn.security.pib.PibSqlite3;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.util.Blob;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class TestPibImpl {
  class PibMemoryFixture extends PibDataFixture2 {
    public PibMemoryFixture() throws EncodingException, CertificateV2.Error
    {
      pib = myPib_;
    }

    private final PibMemory myPib_ = new PibMemory();
  };

  class PibSqlite3Fixture extends PibDataFixture2 {
    public PibSqlite3Fixture() throws EncodingException, CertificateV2.Error, PibImpl.Error
    {
      File databaseDirectoryPath =
        IntegrationTestsCommon.getPolicyConfigDirectory();
      String databaseFilename = "test-pib.db";
      databaseFilePath = new File
        (databaseDirectoryPath, databaseFilename);
      databaseFilePath.delete();

      myPib_ = new PibSqlite3
        (databaseDirectoryPath.getAbsolutePath(), databaseFilename);

      pib = myPib_;
    }

    private final PibSqlite3 myPib_;
  };

  PibMemoryFixture pibMemoryFixture;
  PibSqlite3Fixture pibSqlite3Fixture;

  PibDataFixture2[] pibImpls = new PibDataFixture2[2];
  
  @Before
  public void
  setUp() throws EncodingException, CertificateV2.Error, PibImpl.Error
  {
    pibMemoryFixture = new PibMemoryFixture();
    pibSqlite3Fixture = new PibSqlite3Fixture();

    pibImpls[0] = pibMemoryFixture;
    pibImpls[1] = pibSqlite3Fixture;
  }

  @After
  public void
  tearDown()
  {
    databaseFilePath.delete();
  }

  @Test
  public void
  testCertificateDecoding() throws CertificateV2.Error
  {
    // Use pibMemoryFixture to test.
    PibDataFixture2 fixture = pibMemoryFixture;

    assertTrue(fixture.id1Key1Cert1.getPublicKey().equals
      (fixture.id1Key1Cert2.getPublicKey()));
    assertTrue(fixture.id1Key2Cert1.getPublicKey().equals
      (fixture.id1Key2Cert2.getPublicKey()));
    assertTrue(fixture.id2Key1Cert1.getPublicKey().equals
      (fixture.id2Key1Cert2.getPublicKey()));
    assertTrue(fixture.id2Key2Cert1.getPublicKey().equals
      (fixture.id2Key2Cert2.getPublicKey()));

    assertTrue(fixture.id1Key1Cert1.getPublicKey().equals(fixture.id1Key1));
    assertTrue(fixture.id1Key1Cert2.getPublicKey().equals(fixture.id1Key1));
    assertTrue(fixture.id1Key2Cert1.getPublicKey().equals(fixture.id1Key2));
    assertTrue(fixture.id1Key2Cert2.getPublicKey().equals(fixture.id1Key2));

    assertTrue(fixture.id2Key1Cert1.getPublicKey().equals(fixture.id2Key1));
    assertTrue(fixture.id2Key1Cert2.getPublicKey().equals(fixture.id2Key1));
    assertTrue(fixture.id2Key2Cert1.getPublicKey().equals(fixture.id2Key2));
    assertTrue(fixture.id2Key2Cert2.getPublicKey().equals(fixture.id2Key2));

    assertTrue(fixture.id1Key1Cert2.getIdentity().equals(fixture.id1));
    assertTrue(fixture.id1Key2Cert1.getIdentity().equals(fixture.id1));
    assertTrue(fixture.id1Key2Cert2.getIdentity().equals(fixture.id1));

    assertTrue(fixture.id2Key1Cert2.getIdentity().equals(fixture.id2));
    assertTrue(fixture.id2Key2Cert1.getIdentity().equals(fixture.id2));
    assertTrue(fixture.id2Key2Cert2.getIdentity().equals(fixture.id2));

    assertTrue(fixture.id1Key1Cert2.getKeyName().equals(fixture.id1Key1Name));
    assertTrue(fixture.id1Key2Cert2.getKeyName().equals(fixture.id1Key2Name));

    assertTrue(fixture.id2Key1Cert2.getKeyName().equals(fixture.id2Key1Name));
    assertTrue(fixture.id2Key2Cert2.getKeyName().equals(fixture.id2Key2Name));
  }

  @Test
  public void
  testTpmLocator() throws PibImpl.Error
  {
    for (PibDataFixture2 fixture : pibImpls) {
      PibImpl pib = fixture.pib;

      // Basic getting and setting
      try {
        pib.getTpmLocator();
      } catch (Throwable ex) {
        fail("Unexpected exception: " + ex.getMessage());
      }

      try {
        pib.setTpmLocator("tpmLocator");
      } catch (Throwable ex) {
        fail("Unexpected exception: " + ex.getMessage());
      }
      assertEquals(pib.getTpmLocator(), "tpmLocator");

      // Add a certificate, and do not change the TPM locator.
      pib.addCertificate(fixture.id1Key1Cert1);
      assertTrue(pib.hasIdentity(fixture.id1));
      assertTrue(pib.hasKey(fixture.id1Key1Name));
      assertTrue(pib.hasCertificate(fixture.id1Key1Cert1.getName()));

      // Set the TPM locator to the same value. Nothing should change.
      pib.setTpmLocator("tpmLocator");
      assertTrue(pib.hasIdentity(fixture.id1));
      assertTrue(pib.hasKey(fixture.id1Key1Name));
      assertTrue(pib.hasCertificate(fixture.id1Key1Cert1.getName()));

      // Change the TPM locator. (The contents of the PIB should not change.)
      pib.setTpmLocator("newTpmLocator");
      assertTrue(pib.hasIdentity(fixture.id1));
      assertTrue(pib.hasKey(fixture.id1Key1Name));
      assertTrue(pib.hasCertificate(fixture.id1Key1Cert1.getName()));
    }
  }

  @Test
  public void
  testIdentityManagement() throws Pib.Error,  PibImpl.Error
  {
    for (PibDataFixture2 fixture : pibImpls) {
      PibImpl pib = fixture.pib;

      // No default identity is set. This should throw an Error.
      try {
        pib.getDefaultIdentity();
        fail("Did not throw the expected exception");
      }
      catch (Pib.Error ex) {}
      catch (Exception ex) { fail("Did not throw the expected exception"); }

      // Check for id1, which should not exist.
      assertEquals(false, pib.hasIdentity(fixture.id1));

      // Add id1, which should be the default.
      pib.addIdentity(fixture.id1);
      assertEquals(true, pib.hasIdentity(fixture.id1));
      try {
        pib.getDefaultIdentity();
      } catch (Throwable ex) {
        fail("Unexpected exception: " + ex.getMessage());
      }
      assertEquals(fixture.id1, pib.getDefaultIdentity());

      // Add id2, which should not be the default.
      pib.addIdentity(fixture.id2);
      assertEquals(true, pib.hasIdentity(fixture.id2));
      assertEquals(fixture.id1, pib.getDefaultIdentity());

      // Explicitly set id2 as the default.
      pib.setDefaultIdentity(fixture.id2);
      assertEquals(fixture.id2, pib.getDefaultIdentity());

      // Remove id2. The PIB should not have a default identity.
      pib.removeIdentity(fixture.id2);
      assertEquals(false, pib.hasIdentity(fixture.id2));
      try {
        pib.getDefaultIdentity();
        fail("Did not throw the expected exception");
      }
      catch (Pib.Error ex) {}
      catch (Exception ex) { fail("Did not throw the expected exception"); }

      // Set id2 as the default. This should add id2 again.
      pib.setDefaultIdentity(fixture.id2);
      assertEquals(fixture.id2, pib.getDefaultIdentity());

      // Get all the identities, which should have id1 and id2.
      HashSet<Name> idNames = pib.getIdentities();
      assertEquals(2, idNames.size());
      assertTrue(idNames.contains(fixture.id1));
      assertTrue(idNames.contains(fixture.id2));
    }
  }

  @Test
  public void
  testClearIdentities() throws Pib.Error,  PibImpl.Error
  {
    for (PibDataFixture2 fixture : pibImpls) {
      PibImpl pib = fixture.pib;

      pib.setTpmLocator("tpmLocator");

      // Add id, key, and cert.
      pib.addCertificate(fixture.id1Key1Cert1);
      assertTrue(pib.hasIdentity(fixture.id1));
      assertTrue(pib.hasKey(fixture.id1Key1Name));
      assertTrue(pib.hasCertificate(fixture.id1Key1Cert1.getName()));

      // Clear identities.
      pib.clearIdentities();
      assertEquals(0, pib.getIdentities().size());
      assertEquals(0, pib.getKeysOfIdentity(fixture.id1).size());
      assertEquals(0, pib.getCertificatesOfKey(fixture.id1Key1Name).size());
      assertEquals("tpmLocator", pib.getTpmLocator());
    }
  }

  @Test
  public void
  testKeyManagement() throws Pib.Error,  PibImpl.Error
  {
    for (PibDataFixture2 fixture : pibImpls) {
      PibImpl pib = fixture.pib;

      // There is no default setting. This should throw an Error.
      assertEquals(false, pib.hasIdentity(fixture.id2));
      try {
        pib.getDefaultKeyOfIdentity(fixture.id1);
        fail("Did not throw the expected exception");
      }
      catch (Pib.Error ex) {}
      catch (Exception ex) { fail("Did not throw the expected exception"); }

      // Check for id1Key1, which should not exist. Neither should id1.
      assertEquals(false, pib.hasKey(fixture.id1Key1Name));
      assertEquals(false, pib.hasIdentity(fixture.id1));

      // Add id1Key1, which should be the default. id1 should be added implicitly.
      pib.addKey(fixture.id1, fixture.id1Key1Name, fixture.id1Key1.buf());
      assertEquals(true, pib.hasKey(fixture.id1Key1Name));
      assertEquals(true, pib.hasIdentity(fixture.id1));
      Blob keyBits = pib.getKeyBits(fixture.id1Key1Name);
      assertTrue(keyBits.equals(fixture.id1Key1));
      try {
        pib.getDefaultKeyOfIdentity(fixture.id1);
      } catch (Throwable ex) {
        fail("Unexpected exception: " + ex.getMessage());
      }
      assertEquals(fixture.id1Key1Name, pib.getDefaultKeyOfIdentity(fixture.id1));

      // Add id1Key2, which should not be the default.
      pib.addKey(fixture.id1, fixture.id1Key2Name, fixture.id1Key2.buf());
      assertEquals(true, pib.hasKey(fixture.id1Key2Name));
      assertEquals(fixture.id1Key1Name, pib.getDefaultKeyOfIdentity(fixture.id1));

      // Explicitly Set id1Key2 as the default.
      pib.setDefaultKeyOfIdentity(fixture.id1, fixture.id1Key2Name);
      assertEquals(fixture.id1Key2Name, pib.getDefaultKeyOfIdentity(fixture.id1));

      // Set a non-existing key as the default. This should throw an Error.
      try {
        pib.setDefaultKeyOfIdentity(fixture.id1, new Name("/non-existing"));
        fail("Did not throw the expected exception");
      }
      catch (Pib.Error ex) {}
      catch (Exception ex) { fail("Did not throw the expected exception"); }

      // Remove id1Key2. The PIB should not have a default key.
      pib.removeKey(fixture.id1Key2Name);
      assertEquals(false, pib.hasKey(fixture.id1Key2Name));
      try {
        pib.getKeyBits(fixture.id1Key2Name);
        fail("Did not throw the expected exception");
      }
      catch (Pib.Error ex) {}
      catch (Exception ex) { fail("Did not throw the expected exception"); }

      try {
        pib.getDefaultKeyOfIdentity(fixture.id1);
        fail("Did not throw the expected exception");
      }
      catch (Pib.Error ex) {}
      catch (Exception ex) { fail("Did not throw the expected exception"); }

      // Add id1Key2 back, which should be the default.
      pib.addKey(fixture.id1, fixture.id1Key2Name, fixture.id1Key2.buf());
      try {
        pib.getKeyBits(fixture.id1Key2Name);
      } catch (Throwable ex) {
        fail("Unexpected exception: " + ex.getMessage());
      }
      assertEquals(fixture.id1Key2Name, pib.getDefaultKeyOfIdentity(fixture.id1));

      // Get all the keys, which should have id1Key1 and id1Key2.
      HashSet<Name> keyNames = pib.getKeysOfIdentity(fixture.id1);
      assertEquals(2, keyNames.size());
      assertTrue(keyNames.contains(fixture.id1Key1Name));
      assertTrue(keyNames.contains(fixture.id1Key2Name));

      // Remove id1, which should remove all the keys.
      pib.removeIdentity(fixture.id1);
      keyNames = pib.getKeysOfIdentity(fixture.id1);
      assertEquals(0, keyNames.size());
    }
  }

  @Test
  public void
  testCertificateManagement() throws Pib.Error,  PibImpl.Error
  {
    for (PibDataFixture2 fixture : pibImpls) {
      PibImpl pib = fixture.pib;

      // There is no default setting. This should throw an Error.
      try {
        pib.getDefaultCertificateOfKey(fixture.id1Key1Name);
        fail("Did not throw the expected exception");
      }
      catch (Pib.Error ex) {}
      catch (Exception ex) { fail("Did not throw the expected exception"); }

      // Check for id1Key1Cert1, which should not exist. Neither should id1 or id1Key1.
      assertEquals(false, pib.hasCertificate(fixture.id1Key1Cert1.getName()));
      assertEquals(false, pib.hasIdentity(fixture.id1));
      assertEquals(false, pib.hasKey(fixture.id1Key1Name));

      // Add id1Key1Cert1, which should be the default.
      // id1 and id1Key1 should be added implicitly.
      pib.addCertificate(fixture.id1Key1Cert1);
      assertEquals(true, pib.hasCertificate(fixture.id1Key1Cert1.getName()));
      assertEquals(true, pib.hasIdentity(fixture.id1));
      assertEquals(true, pib.hasKey(fixture.id1Key1Name));
      assertTrue(pib.getCertificate(fixture.id1Key1Cert1.getName()).wireEncode()
                  .equals(fixture.id1Key1Cert1.wireEncode()));
      try {
        pib.getDefaultCertificateOfKey(fixture.id1Key1Name);
      } catch (Throwable ex) {
        fail("Unexpected exception: " + ex.getMessage());
      }
      // Use the wire encoding to check equivalence.
      assertTrue(fixture.id1Key1Cert1.wireEncode().equals
                  (pib.getDefaultCertificateOfKey(fixture.id1Key1Name).wireEncode()));

      // Add id1Key1Cert2, which should not be the default.
      pib.addCertificate(fixture.id1Key1Cert2);
      assertEquals(true, pib.hasCertificate(fixture.id1Key1Cert2.getName()));
      assertTrue(fixture.id1Key1Cert1.wireEncode().equals
                  (pib.getDefaultCertificateOfKey(fixture.id1Key1Name).wireEncode()));

      // Explicitly set id1Key1Cert2 as the default.
      pib.setDefaultCertificateOfKey(fixture.id1Key1Name, fixture.id1Key1Cert2.getName());
      assertTrue(fixture.id1Key1Cert2.wireEncode().equals
                  (pib.getDefaultCertificateOfKey(fixture.id1Key1Name).wireEncode()));

      // Set a non-existing certificate as the default. This should throw an Error.
      try {
        pib.setDefaultCertificateOfKey(fixture.id1Key1Name, new Name("/non-existing"));
        fail("Did not throw the expected exception");
      }
      catch (Pib.Error ex) {}
      catch (Exception ex) { fail("Did not throw the expected exception"); }

      // Remove id1Key1Cert2, which should not have a default certificate.
      pib.removeCertificate(fixture.id1Key1Cert2.getName());
      assertEquals(false, pib.hasCertificate(fixture.id1Key1Cert2.getName()));
      try {
        pib.getCertificate(fixture.id1Key1Cert2.getName());
        fail("Did not throw the expected exception");
      }
      catch (Pib.Error ex) {}
      catch (Exception ex) { fail("Did not throw the expected exception"); }

      try {
        pib.getDefaultCertificateOfKey(fixture.id1Key1Name);
        fail("Did not throw the expected exception");
      }
      catch (Pib.Error ex) {}
      catch (Exception ex) { fail("Did not throw the expected exception"); }

      // Add id1Key1Cert2, which should be the default.
      pib.addCertificate(fixture.id1Key1Cert2);
      try {
        pib.getCertificate(fixture.id1Key1Cert1.getName());
      } catch (Throwable ex) {
        fail("Unexpected exception: " + ex.getMessage());
      }
      assertTrue(fixture.id1Key1Cert2.wireEncode().equals
                  (pib.getDefaultCertificateOfKey(fixture.id1Key1Name).wireEncode()));

      // Get all certificates, which should have id1Key1Cert1 and id1Key1Cert2.
      HashSet<Name> certNames = pib.getCertificatesOfKey(fixture.id1Key1Name);
      assertEquals(2, certNames.size());
      assertTrue(certNames.contains(fixture.id1Key1Cert1.getName()));
      assertTrue(certNames.contains(fixture.id1Key1Cert2.getName()));

      // Remove id1Key1, which should remove all the certificates.
      pib.removeKey(fixture.id1Key1Name);
      certNames = pib.getCertificatesOfKey(fixture.id1Key1Name);
      assertEquals(0, certNames.size());
    }
  }

  @Test
  public void
  testDefaultsManagement() throws Pib.Error,  PibImpl.Error
  {
    for (PibDataFixture2 fixture : pibImpls) {
      PibImpl pib = fixture.pib;

      pib.addIdentity(fixture.id1);
      assertEquals(fixture.id1, pib.getDefaultIdentity());

      pib.addIdentity(fixture.id2);
      assertEquals(fixture.id1, pib.getDefaultIdentity());

      pib.removeIdentity(fixture.id1);
      try {
        pib.getDefaultIdentity();
        fail("Did not throw the expected exception");
      }
      catch (Pib.Error ex) {}
      catch (Exception ex) { fail("Did not throw the expected exception"); }

      pib.addKey(fixture.id2, fixture.id2Key1Name, fixture.id2Key1.buf());
      assertEquals(fixture.id2, pib.getDefaultIdentity());
      assertEquals(fixture.id2Key1Name, pib.getDefaultKeyOfIdentity(fixture.id2));

      pib.addKey(fixture.id2, fixture.id2Key2Name, fixture.id2Key2.buf());
      assertEquals(fixture.id2Key1Name, pib.getDefaultKeyOfIdentity(fixture.id2));

      pib.removeKey(fixture.id2Key1Name);
      try {
        pib.getDefaultKeyOfIdentity(fixture.id2);
        fail("Did not throw the expected exception");
      }
      catch (Pib.Error ex) {}
      catch (Exception ex) { fail("Did not throw the expected exception"); }

      pib.addCertificate(fixture.id2Key2Cert1);
      assertEquals(fixture.id2Key2Name, pib.getDefaultKeyOfIdentity(fixture.id2));
      assertEquals(fixture.id2Key2Cert1.getName(),
                   pib.getDefaultCertificateOfKey(fixture.id2Key2Name).getName());

      pib.addCertificate(fixture.id2Key2Cert2);
      assertEquals(fixture.id2Key2Cert1.getName(),
                   pib.getDefaultCertificateOfKey(fixture.id2Key2Name).getName());

      pib.removeCertificate(fixture.id2Key2Cert2.getName());
      assertEquals(fixture.id2Key2Cert1.getName(),
                   pib.getDefaultCertificateOfKey(fixture.id2Key2Name).getName());
    }
  }

  @Test
  public void
  testOverwrite() throws Pib.Error,  PibImpl.Error
  {
    for (PibDataFixture2 fixture : pibImpls) {
      PibImpl pib = fixture.pib;

      // Check for id1Key1, which should not exist.
      pib.removeIdentity(fixture.id1);
      assertEquals(false, pib.hasKey(fixture.id1Key1Name));

      // Add id1Key1.
      pib.addKey(fixture.id1, fixture.id1Key1Name, fixture.id1Key1.buf());
      assertEquals(true, pib.hasKey(fixture.id1Key1Name));
      Blob keyBits = pib.getKeyBits(fixture.id1Key1Name);
      assertTrue(keyBits.equals(fixture.id1Key1));

      // To check overwrite, add a key with the same name.
      pib.addKey(fixture.id1, fixture.id1Key1Name, fixture.id1Key2.buf());
      Blob keyBits2 = pib.getKeyBits(fixture.id1Key1Name);
      assertTrue(keyBits2.equals(fixture.id1Key2));

      // Check for id1Key1Cert1, which should not exist.
      pib.removeIdentity(fixture.id1);
      assertEquals(false, pib.hasCertificate(fixture.id1Key1Cert1.getName()));

      // Add id1Key1Cert1.
      pib.addKey(fixture.id1, fixture.id1Key1Name, fixture.id1Key1.buf());
      pib.addCertificate(fixture.id1Key1Cert1);
      assertEquals(true, pib.hasCertificate(fixture.id1Key1Cert1.getName()));

      CertificateV2 cert = pib.getCertificate(fixture.id1Key1Cert1.getName());
      assertTrue(cert.wireEncode().equals(fixture.id1Key1Cert1.wireEncode()));

      // Create a fake certificate with the same name.
      CertificateV2 cert2 = fixture.id1Key2Cert1;
      cert2.setName(fixture.id1Key1Cert1.getName());
      cert2.setSignature(fixture.id1Key2Cert1.getSignature());
      pib.addCertificate(cert2);

      CertificateV2 cert3 = pib.getCertificate(fixture.id1Key1Cert1.getName());
      assertTrue(cert3.wireEncode().equals(cert2.wireEncode()));

      // Check that both the key and certificate are overwritten.
      Blob keyBits3 = pib.getKeyBits(fixture.id1Key1Name);
      assertTrue(keyBits3.equals(fixture.id1Key2));
    }
  }

  private File databaseFilePath;
}
