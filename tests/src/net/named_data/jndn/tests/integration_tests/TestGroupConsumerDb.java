/**
 * Copyright (C) 2015-2017 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/consumer-db.t.cpp
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
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.der.DerDecodingException;
import net.named_data.jndn.encrypt.ConsumerDb;
import net.named_data.jndn.encrypt.Sqlite3ConsumerDb;
import net.named_data.jndn.encrypt.DecryptKey;
import net.named_data.jndn.encrypt.EncryptKey;
import net.named_data.jndn.encrypt.algo.AesAlgorithm;
import net.named_data.jndn.encrypt.algo.RsaAlgorithm;
import net.named_data.jndn.security.AesKeyParams;
import net.named_data.jndn.security.RsaKeyParams;
import net.named_data.jndn.util.Blob;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

// Note: We name this differently than TestConsumerDb so that it is not the
// first integration test to run, which doesn't work for some reason. (Maybe the
// static class initializers don't run?)
public class TestGroupConsumerDb {
  @Before
  public void
  setUp() throws ConsumerDb.Error
  {
    File policyConfigDirectory = IntegrationTestsCommon.getPolicyConfigDirectory();

    databaseFilePath = new File(policyConfigDirectory, "test.db");
    databaseFilePath.delete();
  }

  @After
  public void
  tearDown()
  {
    databaseFilePath.delete();
  }

  static void
  generateRsaKeys(Blob[] encryptionKeyBlob, Blob[] decryptionKeyBlob)
    throws NoSuchAlgorithmException, InvalidKeySpecException, DerDecodingException
  {
    RsaKeyParams params = new RsaKeyParams();
    DecryptKey decryptKey = RsaAlgorithm.generateKey(params);
    decryptionKeyBlob[0] = decryptKey.getKeyBits();
    EncryptKey encryptKey = RsaAlgorithm.deriveEncryptKey(decryptionKeyBlob[0]);
    encryptionKeyBlob[0] = encryptKey.getKeyBits();
  }

  static void
  generateAesKeys(Blob[] encryptionKeyBlob, Blob[] decryptionKeyBlob)
  {
    AesKeyParams params = new AesKeyParams();
    DecryptKey memberDecryptKey = AesAlgorithm.generateKey(params);
    decryptionKeyBlob[0] = memberDecryptKey.getKeyBits();
    EncryptKey memberEncryptKey = AesAlgorithm.deriveEncryptKey(decryptionKeyBlob[0]);
    encryptionKeyBlob[0] = memberEncryptKey.getKeyBits();
  }

  @Test
  public void
  testOperateAesDecryptionKey() throws ConsumerDb.Error
  {
    // Test construction.
    ConsumerDb database = new Sqlite3ConsumerDb(databaseFilePath.getAbsolutePath());

    // Generate key blobs.
    Blob[] encryptionKeyBlob = { null };
    Blob[] decryptionKeyBlob = { null };
    generateAesKeys(encryptionKeyBlob, decryptionKeyBlob);

    Name keyName = new Name
      ("/alice/health/samples/activity/steps/C-KEY/20150928080000/20150928090000!");
    keyName.append(new Name("FOR/alice/health/read/activity!"));
    database.addKey(keyName, decryptionKeyBlob[0]);
    Blob resultBlob = database.getKey(keyName);

    assertTrue(decryptionKeyBlob[0].equals(resultBlob));

    database.deleteKey(keyName);
    resultBlob = database.getKey(keyName);

    assertEquals(0, resultBlob.size());
  }

  @Test
  public void
  testOperateRsaDecryptionKey()
    throws ConsumerDb.Error, NoSuchAlgorithmException, InvalidKeySpecException,
      DerDecodingException
  {
    // Test construction.
    ConsumerDb database = new Sqlite3ConsumerDb(databaseFilePath.getAbsolutePath());

    // Generate key blobs.
    Blob[] encryptionKeyBlob = { null };
    Blob[] decryptionKeyBlob = { null };
    generateRsaKeys(encryptionKeyBlob, decryptionKeyBlob);

    Name keyName = new Name
      ("/alice/health/samples/activity/steps/D-KEY/20150928080000/20150928090000!");
    keyName.append(new Name("FOR/test/member/KEY/123!"));
    database.addKey(keyName, decryptionKeyBlob[0]);
    Blob resultBlob = database.getKey(keyName);

    assertTrue(decryptionKeyBlob[0].equals(resultBlob));

    database.deleteKey(keyName);
    resultBlob = database.getKey(keyName);

    assertEquals(0, resultBlob.size());
  }
  
  private File databaseFilePath;
}
