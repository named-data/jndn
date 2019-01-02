/**
 * Copyright (C) 2017-2019 Regents of the University of California.
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
import java.nio.ByteBuffer;
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
import net.named_data.jndn.security.VerificationHelpers;
import net.named_data.jndn.security.tpm.TpmBackEndFile;
import net.named_data.jndn.security.tpm.TpmKeyHandle;
import net.named_data.jndn.security.tpm.TpmPrivateKey;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;
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

      boolean result = VerificationHelpers.verifySignature
        (content, signature, publicKey);
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

      TpmKeyHandle key = tpm.createKey(identityName, new EcKeyParams());
      Name ecKeyName = key.getKeyName();

      Blob content = new Blob(new int[] { 0x01, 0x02, 0x03, 0x04});
      Blob signature = key.sign(DigestAlgorithm.SHA256, content.buf());

      Blob publicKey = key.derivePublicKey();

      // TODO: Move verify to PublicKey?
      boolean result = VerificationHelpers.verifySignature
        (content, signature, publicKey);
      assertEquals(true, result);

      tpm.deleteKey(ecKeyName);
      assertEquals(false, tpm.hasKey(ecKeyName));
    }
  }
*/
 
  @Test
  public void
  testImportExport() throws TpmBackEnd.Error, Tpm.Error, TpmPrivateKey.Error
  {
    String privateKeyPkcs1Base64 =
      "MIIEpAIBAAKCAQEAw0WM1/WhAxyLtEqsiAJgWDZWuzkYpeYVdeeZcqRZzzfRgBQT\n" +
      "sNozS5t4HnwTZhwwXbH7k3QN0kRTV826Xobws3iigohnM9yTK+KKiayPhIAm/+5H\n" +
      "GT6SgFJhYhqo1/upWdueojil6RP4/AgavHhopxlAVbk6G9VdVnlQcQ5Zv0OcGi73\n" +
      "c+EnYD/YgURYGSngUi/Ynsh779p2U69/te9gZwIL5PuE9BiO6I39cL9z7EK1SfZh\n" +
      "OWvDe/qH7YhD/BHwcWit8FjRww1glwRVTJsA9rH58ynaAix0tcR/nBMRLUX+e3rU\n" +
      "RHg6UbSjJbdb9qmKM1fTGHKUzL/5pMG6uBU0ywIDAQABAoIBADQkckOIl4IZMUTn\n" +
      "W8LFv6xOdkJwMKC8G6bsPRFbyY+HvC2TLt7epSvfS+f4AcYWaOPcDu2E49vt2sNr\n" +
      "cASly8hgwiRRAB3dHH9vcsboiTo8bi2RFvMqvjv9w3tK2yMxVDtmZamzrrnaV3YV\n" +
      "Q+5nyKo2F/PMDjQ4eUAKDOzjhBuKHsZBTFnA1MFNI+UKj5X4Yp64DFmKlxTX/U2b\n" +
      "wzVywo5hzx2Uhw51jmoLls4YUvMJXD0wW5ZtYRuPogXvXb/of9ef/20/wU11WFKg\n" +
      "Xb4gfR8zUXaXS1sXcnVm3+24vIs9dApUwykuoyjOqxWqcHRec2QT2FxVGkFEraze\n" +
      "CPa4rMECgYEA5Y8CywomIcTgerFGFCeMHJr8nQGqY2V/owFb3k9maczPnC9p4a9R\n" +
      "c5szLxA9FMYFxurQZMBWSEG2JS1HR2mnjigx8UKjYML/A+rvvjZOMe4M6Sy2ggh4\n" +
      "SkLZKpWTzjTe07ByM/j5v/SjNZhWAG7sw4/LmPGRQkwJv+KZhGojuOkCgYEA2cOF\n" +
      "T6cJRv6kvzTz9S0COZOVm+euJh/BXp7oAsAmbNfOpckPMzqHXy8/wpdKl6AAcB57\n" +
      "OuztlNfV1D7qvbz7JuRlYwQ0cEfBgbZPcz1p18HHDXhwn57ZPb8G33Yh9Omg0HNA\n" +
      "Imb4LsVuSqxA6NwSj7cpRekgTedrhLFPJ+Ydb5MCgYEAsM3Q7OjILcIg0t6uht9e\n" +
      "vrlwTsz1mtCV2co2I6crzdj9HeI2vqf1KAElDt6G7PUHhglcr/yjd8uEqmWRPKNX\n" +
      "ddnnfVZB10jYeP/93pac6z/Zmc3iU4yKeUe7U10ZFf0KkiiYDQd59CpLef/2XScS\n" +
      "HB0oRofnxRQjfjLc4muNT+ECgYEAlcDk06MOOTly+F8lCc1bA1dgAmgwFd2usDBd\n" +
      "Y07a3e0HGnGLN3Kfl7C5i0tZq64HvxLnMd2vgLVxQlXGPpdQrC1TH+XLXg+qnlZO\n" +
      "ivSH7i0/gx75bHvj75eH1XK65V8pDVDEoSPottllAIs21CxLw3N1ObOZWJm2EfmR\n" +
      "cuHICmsCgYAtFJ1idqMoHxES3mlRpf2JxyQudP3SCm2WpGmqVzhRYInqeatY5sUd\n" +
      "lPLHm/p77RT7EyxQHTlwn8FJPuM/4ZH1rQd/vB+Y8qAtYJCexDMsbvLW+Js+VOvk\n" +
      "jweEC0nrcL31j9mF0vz5E6tfRu4hhJ6L4yfWs0gSejskeVB/w8QY4g==\n";

    for (TpmBackEnd tpm : backEndList) {
      Name keyName = new Name("/Test/KeyName/KEY/1");
      tpm.deleteKey(keyName);
      assertEquals(false, tpm.hasKey(keyName));

      TpmPrivateKey privateKey = new TpmPrivateKey();
      Blob privateKeyPkcs1Encoding = new Blob
        (Common.base64Decode(privateKeyPkcs1Base64));
      privateKey.loadPkcs1(privateKeyPkcs1Encoding.buf());

      ByteBuffer password = new Blob("password").buf();
      Blob encryptedPkcs8 = privateKey.toEncryptedPkcs8(password);

      tpm.importKey(keyName, encryptedPkcs8.buf(), password);
      assertEquals(true, tpm.hasKey(keyName));
      try {
        // Can't import the same keyName again.
        tpm.importKey(keyName, encryptedPkcs8.buf(), password);
        fail("Did not throw the expected exception");
      }
      catch (TpmBackEnd.Error ex) {}
      catch (Exception ex) { fail("Did not throw the expected exception"); }

      Blob exportedKey = tpm.exportKey(keyName, password);
      assertEquals(true, tpm.hasKey(keyName));

      TpmPrivateKey privateKey2 = new TpmPrivateKey();
      privateKey2.loadEncryptedPkcs8(exportedKey.buf(), password);
      Blob privateKey2Pkcs1Encoding = privateKey2.toPkcs1();
      assertTrue(privateKeyPkcs1Encoding.equals(privateKey2Pkcs1Encoding));

      tpm.deleteKey(keyName);
      assertEquals(false, tpm.hasKey(keyName));
      try {
        tpm.exportKey(keyName, password);
        fail("Did not throw the expected exception");
      }
      catch (TpmBackEnd.Error ex) {}
      catch (Exception ex) { fail("Did not throw the expected exception"); }
    }
  }

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
