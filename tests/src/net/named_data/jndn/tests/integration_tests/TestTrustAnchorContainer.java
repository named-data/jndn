/**
 * Copyright (C) 2018-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/v2/trust-anchor-container.t.cpp
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
import java.io.IOException;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.pib.Pib;
import net.named_data.jndn.security.pib.PibIdentity;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.security.tpm.Tpm;
import net.named_data.jndn.security.tpm.TpmBackEnd;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.security.v2.StaticTrustAnchorGroup;
import net.named_data.jndn.security.v2.TrustAnchorContainer;
import net.named_data.jndn.security.v2.TrustAnchorGroup;
import net.named_data.jndn.util.Common;
import org.junit.Before;
import org.junit.After;
import org.junit.Test;
import static org.junit.Assert.fail;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;

public class TestTrustAnchorContainer {
  TrustAnchorContainer anchorContainer;

  File certificateDirectoryPath;
  File certificatePath1;
  File certificatePath2;

  PibIdentity identity1;
  PibIdentity identity2;

  CertificateV2 certificate1;
  CertificateV2 certificate2;
  IdentityManagementFixture fixture;

  @Before
  public void
  setUp() throws PibImpl.Error, Pib.Error, Tpm.Error, TpmBackEnd.Error, 
    KeyChain.Error, SecurityException, IOException
  {
    anchorContainer = new TrustAnchorContainer();
    fixture = new IdentityManagementFixture();

    // Create a directory and prepares two certificates.
    certificateDirectoryPath = 
      new File(IntegrationTestsCommon.getPolicyConfigDirectory(), "test-cert-dir");
    certificateDirectoryPath.mkdirs();

    certificatePath1 = new File(certificateDirectoryPath, "trust-anchor-1.cert");
    certificatePath2 = new File(certificateDirectoryPath, "trust-anchor-2.cert");

    identity1 = fixture.addIdentity(new Name("/TestAnchorContainer/First"));
    certificate1 = identity1.getDefaultKey().getDefaultCertificate();
    fixture.saveCertificateToFile(certificate1, certificatePath1.getAbsolutePath());

    identity2 = fixture.addIdentity(new Name("/TestAnchorContainer/Second"));
    certificate2 = identity2.getDefaultKey().getDefaultCertificate();
    fixture.saveCertificateToFile(certificate2, certificatePath2.getAbsolutePath());
  }

  @After
  public void
  tearDown()
  {
    certificatePath1.delete();
    certificatePath2.delete();
  }

  @Test
  public void
  testInsert() throws TrustAnchorContainer.Error, InterruptedException
  {
    // Static
    anchorContainer.insert("group1", certificate1);
    assertTrue(anchorContainer.find(certificate1.getName()) != null);
    assertTrue(anchorContainer.find(identity1.getName()) != null);
    CertificateV2 certificate = anchorContainer.find(certificate1.getName());
    try {
      // Re-inserting the same certificate should do nothing.
      anchorContainer.insert("group1", certificate1);
    } catch (Throwable ex) {
      fail("Unexpected exception: " + ex.getMessage());
    }
    // It should still be the same instance of the certificate.
    assertTrue(certificate == anchorContainer.find(certificate1.getName()));
    // Cannot add a dynamic group when the static already exists.
    try {
      anchorContainer.insert("group1", certificatePath1.getAbsolutePath(), 400.0);
      fail("Did not throw the expected exception");
    }
    catch (TrustAnchorContainer.Error ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    assertEquals(1, anchorContainer.getGroup("group1").size());
    assertEquals(1, anchorContainer.size());

    // From file
    anchorContainer.insert("group2", certificatePath2.getAbsolutePath(), 400.0);
    assertTrue(anchorContainer.find(certificate2.getName()) != null);
    assertTrue(anchorContainer.find(identity2.getName()) != null);
    try {
      anchorContainer.insert("group2", certificate2);
      fail("Did not throw the expected exception");
    }
    catch (TrustAnchorContainer.Error ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    try {
      anchorContainer.insert("group2", certificatePath2.getAbsolutePath(), 400.0);
      fail("Did not throw the expected exception");
    }
    catch (TrustAnchorContainer.Error ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }

    assertEquals(1, anchorContainer.getGroup("group2").size());
    assertEquals(2, anchorContainer.size());

    certificatePath2.delete();
    // Wait for the refresh period to expire.
    Thread.sleep(500);

    assertTrue(anchorContainer.find(identity2.getName()) == null);
    assertTrue(anchorContainer.find(certificate2.getName()) == null);
    assertEquals(0, anchorContainer.getGroup("group2").size());
    assertEquals(1, anchorContainer.size());

    TrustAnchorGroup group = anchorContainer.getGroup("group1");
    assertTrue(group instanceof StaticTrustAnchorGroup);
    StaticTrustAnchorGroup staticGroup = (StaticTrustAnchorGroup)group;
    assertEquals(1, staticGroup.size());
    staticGroup.remove(certificate1.getName());
    assertEquals(0, staticGroup.size());
    assertEquals(0, anchorContainer.size());

    try {
      anchorContainer.getGroup("non-existing-group");
      fail("Did not throw the expected exception");
    }
    catch (TrustAnchorContainer.Error ex) {}
    catch (Exception ex) { fail("Did not throw the expected exception"); }
  }

  @Test
  public void
  testDynamicAnchorFromDirectory()
    throws TrustAnchorContainer.Error, InterruptedException
  {
    certificatePath2.delete();

    anchorContainer.insert
      ("group", certificateDirectoryPath.getAbsolutePath(), 400.0, true);

    assertTrue(anchorContainer.find(identity1.getName()) != null);
    assertTrue(anchorContainer.find(identity2.getName()) == null);
    assertEquals(1, anchorContainer.getGroup("group").size());

    fixture.saveCertificateToFile(certificate2, certificatePath2.getAbsolutePath());

    // Wait for the refresh period to expire. The dynamic anchors should remain.
    Thread.sleep(500);

    assertTrue(anchorContainer.find(identity1.getName()) != null);
    assertTrue(anchorContainer.find(identity2.getName()) != null);
    assertEquals(2, anchorContainer.getGroup("group").size());

    if (certificateDirectoryPath.exists()) {
      // Delete files from a previous test.
      for (File file : certificateDirectoryPath.listFiles())
        file.delete();
    }

    // Wait for the refresh period to expire. The dynamic anchors should be gone.
    Thread.sleep(500);

    assertTrue(anchorContainer.find(identity1.getName()) == null);
    assertTrue(anchorContainer.find(identity2.getName()) == null);
    assertEquals(0, anchorContainer.getGroup("group").size());
  }

  @Test
  public void
  testFindByInterest()
    throws TrustAnchorContainer.Error, TpmBackEnd.Error, PibImpl.Error,
      KeyChain.Error, Pib.Error, CertificateV2.Error
  {
    anchorContainer.insert("group1", certificatePath1.getAbsolutePath(), 400.0);
    Interest interest = new Interest(identity1.getName());
    assertTrue(anchorContainer.find(interest) != null);
    Interest interest1 = new Interest(identity1.getName().getPrefix(-1));
    assertTrue(anchorContainer.find(interest1) != null);
    Interest interest2 = new Interest(new Name(identity1.getName()).appendVersion(1));
    assertTrue(anchorContainer.find(interest2) == null);

    CertificateV2 certificate3 =
      fixture.addCertificate(identity1.getDefaultKey(), "3");
    CertificateV2 certificate4 =
      fixture.addCertificate(identity1.getDefaultKey(), "4");
    CertificateV2 certificate5 =
      fixture.addCertificate(identity1.getDefaultKey(), "5");

    CertificateV2 certificate3Copy = new CertificateV2(certificate3);
    anchorContainer.insert("group2", certificate3Copy);
    anchorContainer.insert("group3", certificate4);
    anchorContainer.insert("group4", certificate5);

    Interest interest3 = new Interest(certificate3.getKeyName());
    CertificateV2 foundCertificate = anchorContainer.find(interest3);
    assertTrue(foundCertificate != null);
    assertTrue(interest3.getName().isPrefixOf(foundCertificate.getName()));
    assertTrue(certificate3.getName().equals(foundCertificate.getName()));

    interest3.getExclude().appendComponent
      (certificate3.getName().get(CertificateV2.ISSUER_ID_OFFSET));
    foundCertificate = anchorContainer.find(interest3);
    assertTrue(foundCertificate != null);
    assertTrue(interest3.getName().isPrefixOf(foundCertificate.getName()));
    assertTrue(!foundCertificate.getName().equals(certificate3.getName()));
  }

  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
