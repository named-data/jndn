/**
 * Copyright (C) 2017 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/tpm/back-end.t.cpp
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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashSet;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encrypt.algo.EncryptAlgorithmType;
import net.named_data.jndn.encrypt.algo.EncryptParams;
import net.named_data.jndn.encrypt.algo.RsaAlgorithm;
import net.named_data.jndn.security.DigestAlgorithm;
import net.named_data.jndn.security.pib.PibKey;
import net.named_data.jndn.security.tpm.Tpm;
import net.named_data.jndn.security.tpm.TpmBackEnd;
import net.named_data.jndn.security.tpm.TpmBackEndMemory;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.security.RsaKeyParams;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.policy.PolicyManager;
import net.named_data.jndn.security.tpm.TpmBackEndFile;
import net.named_data.jndn.security.tpm.TpmKeyHandle;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.SignedBlob;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class TestTpmBackEnds {
  TpmBackEndMemory backEndMemory;
  TpmBackEndFile backEndFile;

  TpmBackEnd[] backEndList = new TpmBackEnd[2];
  
  @Before
  public void
  setUp() throws EncodingException, CertificateV2.Error
  {
    backEndMemory = new TpmBackEndMemory();

    File locationPath = new File
      (IntegrationTestsCommon.getPolicyConfigDirectory(), "ndnsec-key-file");
    if (locationPath.exists()) {
      // Delete files from a previous test.
      for (File file : locationPath.listFiles())
        file.delete();
    }
    backEndFile = new TpmBackEndFile(locationPath.getAbsolutePath());

    backEndList[0] = backEndMemory;
    backEndList[1] = backEndFile;
  }

  @After
  public void
  tearDown()
  {
  }

  @Test
  public void
  testKeyManagement() throws TpmBackEnd.Error, Tpm.Error
  {
    for (TpmBackEnd tpm : backEndList) {
      Name identityName = new Name("/Test/KeyName");
      Name.Component keyId = new Name.Component("1");
      Name keyName = PibKey.constructKeyName(identityName, keyId);

      // The key should not exist.
      assertEquals(false, tpm.hasKey(keyName));
      assertTrue(tpm.getKeyHandle(keyName) == null);

      // Create a key, which should exist.
      assertTrue(tpm.createKey(identityName, new RsaKeyParams(keyId)) != null);
      assertTrue(tpm.hasKey(keyName));
      assertTrue(tpm.getKeyHandle(keyName) != null);

      // Create a key with the same name, which should throw an error.
      try {
        tpm.createKey(identityName, new RsaKeyParams(keyId));
        fail("Did not throw the expected exception");
      }
      catch (Tpm.Error ex) {}
      catch (Exception ex) { fail("Did not throw the expected exception"); }

      // Delete the key, then it should not exist.
      tpm.deleteKey(keyName);
      assertEquals(false, tpm.hasKey(keyName));
      assertTrue(tpm.getKeyHandle(keyName) == null);
    }
  }

  @Test
  public void
  testRsaSigning() throws TpmBackEnd.Error, Tpm.Error, SecurityException
  {
    for (TpmBackEnd tpm : backEndList) {
      // Create an RSA key.
      Name identityName = new Name("/Test/KeyName");

      TpmKeyHandle key = tpm.createKey(identityName, new RsaKeyParams());
      Name keyName = key.getKeyName();

      Blob content = new Blob(new int[] { 0x01, 0x02, 0x03, 0x04});
      Blob signature = key.sign(DigestAlgorithm.SHA256, content.buf());

      Blob publicKey = key.derivePublicKey();

      // TODO: Move verify to PublicKey?
      boolean result = PolicyManager.verifySha256WithRsaSignature
        (signature, new SignedBlob(content, 0, content.size()), publicKey);
      assertEquals(true, result);

      tpm.deleteKey(keyName);
      assertEquals(false, tpm.hasKey(keyName));
    }
  }

  @Test
  public void
  testRsaDecryption() 
    throws TpmBackEnd.Error, InvalidKeySpecException, NoSuchAlgorithmException,
      NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
      BadPaddingException, Tpm.Error
  {
    for (TpmBackEnd tpm : backEndList) {
      // Create an rsa key.
      Name identityName = new Name("/Test/KeyName");

      TpmKeyHandle key = tpm.createKey(identityName, new RsaKeyParams());
      Name keyName = key.getKeyName();

      Blob content = new Blob(new int[] { 0x01, 0x02, 0x03, 0x04});

      Blob publicKey = key.derivePublicKey();

      // TODO: Move encrypt to PublicKey?
      Blob cipherText = RsaAlgorithm.encrypt
        (publicKey, content, new EncryptParams(EncryptAlgorithmType.RsaOaep));

      Blob plainText = key.decrypt(cipherText.buf());

      assertTrue(plainText.equals(content));

      tpm.deleteKey(keyName);
      assertEquals(false, tpm.hasKey(keyName));
    }
  }

/* Debug: derivePublicKey for EC is not implemented.
  @Test
  public void
  testEcdsaSigning() throws TpmBackEnd.Error, Tpm.Error, SecurityException
  {
    for (TpmBackEnd tpm : backEndList) {
      // Create an EC key.
      Name identityName = new Name("/Test/Ec/KeyName");

      TpmKeyHandle key = tpm.createKey(identityName, new EcdsaKeyParams());
      Name ecKeyName = key.getKeyName();

      Blob content = new Blob(new int[] { 0x01, 0x02, 0x03, 0x04});
      Blob signature = key.sign(DigestAlgorithm.SHA256, content.buf());

      Blob publicKey = key.derivePublicKey();

      // TODO: Move verify to PublicKey?
      boolean result = PolicyManager.verifySha256WithEcdsaSignature
        (signature, new SignedBlob(content, 0, content.size()), publicKey);
      assertEquals(true, result);

      tpm.deleteKey(ecKeyName);
      assertEquals(false, tpm.hasKey(ecKeyName));
    }
  }
*/
 
  // TODO: ImportExport

  @Test
  public void
  testRandomKeyId() throws TpmBackEnd.Error, Tpm.Error
  {
    TpmBackEnd tpm = backEndMemory;

    Name identityName = new Name("/Test/KeyName");

    HashSet<Name> keyNames = new HashSet<Name>();
    for (int i = 0; i < 100; i++) {
      TpmKeyHandle key = tpm.createKey(identityName, new RsaKeyParams());
      Name keyName = key.getKeyName();
      assertTrue(keyNames.add(keyName));
    }
  }
}
