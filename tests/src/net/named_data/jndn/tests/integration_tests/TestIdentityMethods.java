/**
 * Copyright (C) 2015-2017 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From PyNDN unit-tests by Adeola Bannis.
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
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.KeyType;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.certificate.IdentityCertificate;
import net.named_data.jndn.security.identity.BasicIdentityStorage;
import net.named_data.jndn.security.identity.FilePrivateKeyStorage;
import net.named_data.jndn.security.identity.IdentityManager;
import net.named_data.jndn.security.identity.IdentityStorage;
import net.named_data.jndn.security.policy.PolicyManager;
import net.named_data.jndn.security.policy.SelfVerifyPolicyManager;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class TestIdentityMethods {
  private static double
  getNowSeconds() { return Common.getNowMilliseconds() / 1000.0; }

  private static String RSA_DER =
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuFoDcNtffwbfFix64fw0" +
"hI2tKMkFrc6Ex7yw0YLMK9vGE8lXOyBl/qXabow6RCz+GldmFN6E2Qhm1+AX3Zm5" +
"sj3H53/HPtzMefvMQ9X7U+lK8eNMWawpRzvBh4/36VrK/awlkNIVIQ9aXj6q6BVe" +
"zL+zWT/WYemLq/8A1/hHWiwCtfOH1xQhGqWHJzeSgwIgOOrzxTbRaCjhAb1u2TeV" +
"yx/I9H/DV+AqSHCaYbB92HDcDN0kqwSnUf5H1+osE9MR5DLBLhXdSiULSgxT3Or/" +
"y2QgsgUK59WrjhlVMPEiHHRs15NZJbL1uQFXjgScdEarohcY3dilqotineFZCeN8" +
"DwIDAQAB";

  @Before
  public void
  setUp() throws SecurityException
  {
    // Don't show INFO log messages.
    Logger.getLogger("").setLevel(Level.WARNING);

    File policyConfigDirectory = IntegrationTestsCommon.getPolicyConfigDirectory();

    databaseFilePath = new File(policyConfigDirectory, "test-public-info.db");
    databaseFilePath.delete();

    identityStorage = new BasicIdentityStorage(databaseFilePath.getAbsolutePath());
    identityManager = new IdentityManager
      (identityStorage, new FilePrivateKeyStorage());
    policyManager = new SelfVerifyPolicyManager(identityStorage);
    keyChain = new KeyChain(identityManager, policyManager);
  }

  @After
  public void
  tearDown()
  {
    databaseFilePath.delete();
  }

  @Test
  public void
  testIdentityCreateDelete() throws SecurityException
  {
    Name identityName = new Name("/TestIdentityStorage/Identity").appendVersion
      ((long)getNowSeconds());

    Name certificateName = keyChain.createIdentityAndCertificate(identityName);
    Name keyName = IdentityCertificate.certificateNameToPublicKeyName
      (certificateName);

    assertTrue
      ("Identity was not added to IdentityStorage",
       identityStorage.doesIdentityExist(identityName));
    assertTrue
      ("Key was not added to IdentityStorage",
       identityStorage.doesKeyExist(keyName));

    keyChain.deleteIdentity(identityName);
    assertFalse
      ("Identity still in IdentityStorage after identity was deleted",
       identityStorage.doesIdentityExist(identityName));
    assertFalse
      ("Key still in IdentityStorage after identity was deleted",
       identityStorage.doesKeyExist(keyName));
    assertFalse
      ("Certificate still in IdentityStorage after identity was deleted",
       identityStorage.doesCertificateExist(certificateName));

    try {
      identityManager.getDefaultCertificateNameForIdentity(identityName);
      fail("The default certificate name for the identity was not deleted");
    } catch (SecurityException ex) {}
  }

  @Test
  public void
  testKeyCreateDelete() throws SecurityException
  {
    Name identityName = new Name("/TestIdentityStorage/Identity").appendVersion
      ((long)getNowSeconds());

    Name keyName1 = keyChain.generateRSAKeyPair(identityName, true);
    keyChain.getIdentityManager().setDefaultKeyForIdentity(keyName1);

    Name keyName2 = keyChain.generateRSAKeyPair(identityName, false);

    assertTrue
      ("Default key name was changed without explicit request",
       identityManager.getDefaultKeyNameForIdentity(identityName).equals
         (keyName1));
    assertFalse
      ("Newly created key replaced default key without explicit request",
       identityManager.getDefaultKeyNameForIdentity(identityName).equals
          (keyName2));

    identityStorage.deletePublicKeyInfo(keyName2);

    assertFalse(identityStorage.doesKeyExist(keyName2));
    identityStorage.deleteIdentityInfo(identityName);
  }

  @Test
  public void
  testAutoCreateIdentity() throws SecurityException
  {
    Name keyName1 = new Name("/TestSqlIdentityStorage/KeyType/RSA/ksk-12345");
    Name identityName = keyName1.getPrefix(-1);

    byte[] decodedKey = Common.base64Decode(RSA_DER);
    identityStorage.addKey(keyName1, KeyType.RSA, new Blob(decodedKey, false));
    identityStorage.setDefaultKeyNameForIdentity(keyName1);

    assertTrue("Key was not added", identityStorage.doesKeyExist(keyName1));
    assertTrue
      ("Identity for key was not automatically created",
       identityStorage.doesIdentityExist(identityName));

    assertTrue
      ("Default key was not set on identity creation",
       identityManager.getDefaultKeyNameForIdentity(identityName).equals(keyName1));

    try {
      identityStorage.getDefaultCertificateNameForKey(keyName1);
      fail();
    } catch (SecurityException ex) {}

    // We have no private key for signing.
    try {
      identityManager.selfSign(keyName1);
      fail();
    } catch (SecurityException ex) {}

    try {
      identityStorage.getDefaultCertificateNameForKey(keyName1);
      fail();
    } catch (SecurityException ex) {}

    try {
      identityManager.getDefaultCertificateNameForIdentity(identityName);
      fail();
    } catch (SecurityException ex) {}

    Name keyName2 = identityManager.generateRSAKeyPairAsDefault(identityName);
    IdentityCertificate cert = identityManager.selfSign(keyName2);
    identityManager.addCertificateAsIdentityDefault(cert);

    Name certName1 = identityManager.getDefaultCertificateNameForIdentity(identityName);
    Name certName2 = identityStorage.getDefaultCertificateNameForKey(keyName2);

    assertTrue
      ("Key-certificate mapping and identity-certificate mapping are not consistent",
       certName1.equals(certName2));

    keyChain.deleteIdentity(identityName);
    assertFalse(identityStorage.doesKeyExist(keyName1));
  }

  @Test
  public void
  testCertificateAddDelete() throws SecurityException
  {
    Name identityName = new Name("/TestIdentityStorage/Identity").appendVersion
      ((long)getNowSeconds());

    identityManager.createIdentityAndCertificate(identityName, KeyChain.DEFAULT_KEY_PARAMS);
    Name keyName1 = identityManager.getDefaultKeyNameForIdentity(identityName);
    IdentityCertificate cert2 = identityManager.selfSign(keyName1);
    identityStorage.addCertificate(cert2);
    Name certName2 = cert2.getName();

    Name certName1 = identityManager.getDefaultCertificateNameForIdentity(identityName);
    assertFalse
      ("New certificate was set as default without explicit request",
       certName1.equals(certName2));

    identityStorage.deleteCertificateInfo(certName1);
    assertTrue(identityStorage.doesCertificateExist(certName2));
    assertFalse(identityStorage.doesCertificateExist(certName1));

    keyChain.deleteIdentity(identityName);
    assertFalse(identityStorage.doesCertificateExist(certName2));
  }

  @Test
  public void
  testStress() throws SecurityException
  {
    Name identityName = new Name("/TestSecPublicInfoSqlite3/Delete").appendVersion
      ((long)getNowSeconds());

    // ndn-cxx returns the cert name, but the IndentityManager docstring
    // specifies a key.
    Name certName1 = keyChain.createIdentityAndCertificate(identityName);
    Name keyName1 = IdentityCertificate.certificateNameToPublicKeyName(certName1);
    Name keyName2 = keyChain.generateRSAKeyPairAsDefault(identityName);

    IdentityCertificate cert2 = identityManager.selfSign(keyName2);
    Name certName2 = cert2.getName();
    identityManager.addCertificateAsDefault(cert2);

    Name keyName3 = keyChain.generateRSAKeyPairAsDefault(identityName);
    IdentityCertificate cert3 = identityManager.selfSign(keyName3);
    Name certName3 = cert3.getName();
    identityManager.addCertificateAsDefault(cert3);

    IdentityCertificate cert4 = identityManager.selfSign(keyName3);
    identityManager.addCertificateAsDefault(cert4);
    Name certName4 = cert4.getName();

    IdentityCertificate cert5 = identityManager.selfSign(keyName3);
    identityManager.addCertificateAsDefault(cert5);
    Name certName5 = cert5.getName();

    assertTrue(identityStorage.doesIdentityExist(identityName));
    assertTrue(identityStorage.doesKeyExist(keyName1));
    assertTrue(identityStorage.doesKeyExist(keyName2));
    assertTrue(identityStorage.doesKeyExist(keyName3));
    assertTrue(identityStorage.doesCertificateExist(certName1));
    assertTrue(identityStorage.doesCertificateExist(certName2));
    assertTrue(identityStorage.doesCertificateExist(certName3));
    assertTrue(identityStorage.doesCertificateExist(certName4));
    assertTrue(identityStorage.doesCertificateExist(certName5));

    identityStorage.deleteCertificateInfo(certName5);
    assertFalse(identityStorage.doesCertificateExist(certName5));
    assertTrue(identityStorage.doesCertificateExist(certName4));
    assertTrue(identityStorage.doesCertificateExist(certName3));
    assertTrue(identityStorage.doesKeyExist(keyName2));

    identityStorage.deletePublicKeyInfo(keyName3);
    assertFalse(identityStorage.doesCertificateExist(certName4));
    assertFalse(identityStorage.doesCertificateExist(certName3));
    assertFalse(identityStorage.doesKeyExist(keyName3));
    assertTrue(identityStorage.doesKeyExist(keyName2));
    assertTrue(identityStorage.doesKeyExist(keyName1));
    assertTrue(identityStorage.doesIdentityExist(identityName));

    keyChain.deleteIdentity(identityName);
    assertFalse(identityStorage.doesCertificateExist(certName2));
    assertFalse(identityStorage.doesKeyExist(keyName2));
    assertFalse(identityStorage.doesCertificateExist(certName1));
    assertFalse(identityStorage.doesKeyExist(keyName1));
    assertFalse(identityStorage.doesIdentityExist(identityName));
  }

  @Test
  public void
  testEcdsaIdentity() throws SecurityException
  {
    Name identityName = new Name("/TestSqlIdentityStorage/KeyType/ECDSA");
    Name keyName = identityManager.generateEcdsaKeyPairAsDefault(identityName);
    IdentityCertificate cert = identityManager.selfSign(keyName);
    identityManager.addCertificateAsIdentityDefault(cert);

    // Check the self-signature.
    VerifyCounter counter = new VerifyCounter();
    keyChain.verifyData(cert, counter, counter);
    assertEquals
      ("Verification callback was not used.", 1, counter.onVerifiedCallCount_);

    keyChain.deleteIdentity(identityName);
    assertFalse(identityStorage.doesKeyExist(keyName));
  }

  private File databaseFilePath;
  private IdentityStorage identityStorage;
  private IdentityManager identityManager;
  private PolicyManager policyManager;
  private KeyChain keyChain;
}
