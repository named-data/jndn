/**
 * Copyright (C) 2018-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/name-based-access-control/blob/new/tests/tests/encryptor.t.cpp
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
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import net.named_data.jndn.Data;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encrypt.EncryptError;
import net.named_data.jndn.encrypt.EncryptorV2;
import net.named_data.jndn.encrypt.EncryptError.OnError;
import net.named_data.jndn.encrypt.EncryptedContent;
import net.named_data.jndn.in_memory_storage.InMemoryStorageRetaining;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.SigningInfo;
import net.named_data.jndn.security.ValidatorNull;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.util.Blob;
import org.junit.Before;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.Test;

public class TestEncryptorV2 {
  EncryptorFixture fixture_;

  static class EncryptorFixture extends IdentityManagementFixture {
    public EncryptorFixture(boolean shouldPublishData, OnError onError)
      throws KeyChain.Error, PibImpl.Error, SecurityException, IOException,
        EncodingException
    {
      // Include the code here from the NAC unit-tests class
      // EncryptorStaticDataEnvironment instead of making it a base class.
      if (shouldPublishData)
        publishData();
 
      face_ = new InMemoryStorageFace(storage_);
      validator_ = new ValidatorNull();
      encryptor_ = new EncryptorV2
        (new Name("/access/policy/identity/NAC/dataset"),
         new Name("/some/ck/prefix"),
         new SigningInfo(SigningInfo.SignerType.SHA256),
         onError, validator_, keyChain_, face_);
    }

    private void
    publishData() throws EncodingException
    {
      for (ByteBuffer buffer : EncryptStaticData.managerPackets) {
        Data data = new Data();
        data.wireDecode(buffer);
        storage_.insert(data);
      }
    }

    public final InMemoryStorageRetaining storage_ =
      new InMemoryStorageRetaining();
    public final InMemoryStorageFace face_;
    public final ValidatorNull validator_;
    public final EncryptorV2 encryptor_;
  }

  @Before
  public void
  setUp()
    throws KeyChain.Error, PibImpl.Error, SecurityException, IOException,
      EncodingException
  {
    // Turn off INFO log messages.
    Logger.getLogger("").setLevel(Level.SEVERE);

    fixture_ = new EncryptorFixture
      (true,
       new OnError() {
         public void onError(EncryptError.ErrorCode errorCode, String message) {
           fail("onError: " + message);
         }
       });
  }

  @Test
  public void
  testEncryptAndPublishCk()
    throws NoSuchAlgorithmException, NoSuchPaddingException,
      InvalidAlgorithmParameterException, IllegalBlockSizeException,
      BadPaddingException
  {
    fixture_.encryptor_.clearKekData_();
    assertEquals(false, fixture_.encryptor_.getIsKekRetrievalInProgress_());
    fixture_.encryptor_.regenerateCk();
    // Unlike the ndn-group-encrypt unit tests, we don't check
    // isKekRetrievalInProgress_ true because we use a synchronous face which
    // finishes immediately.

    Blob plainText = new Blob("Data to encrypt");
    EncryptedContent encryptedContent = fixture_.encryptor_.encrypt
      (plainText.getImmutableArray());

    Name ckPrefix = encryptedContent.getKeyLocatorName();
    assertTrue(new Name("/some/ck/prefix/CK").equals(ckPrefix.getPrefix(-1)));

    assertTrue(encryptedContent.hasInitialVector());
    assertTrue(!encryptedContent.getPayload().equals(plainText));

    // Check that the KEK Interest has been sent.
    assertTrue(fixture_.face_.sentInterests_.get(0).getName().getPrefix(6).equals
      (new Name("/access/policy/identity/NAC/dataset/KEK")));

    Data kekData = fixture_.face_.sentData_.get(0);
    assertTrue(kekData.getName().getPrefix(6).equals
      (new Name("/access/policy/identity/NAC/dataset/KEK")));
    assertEquals(7, kekData.getName().size());

    fixture_.face_.sentData_.clear();
    fixture_.face_.sentInterests_.clear();

    fixture_.face_.receive
      (new Interest(ckPrefix).setCanBePrefix(true).setMustBeFresh(true));

    Name ckName = fixture_.face_.sentData_.get(0).getName();
    assertTrue(ckName.getPrefix(4).equals(new Name("/some/ck/prefix/CK")));
    assertTrue(ckName.get(5).equals(new Name.Component("ENCRYPTED-BY")));

    Name extractedKek = ckName.getSubName(6);
    assertTrue(extractedKek.equals(kekData.getName()));

    assertEquals(false, fixture_.encryptor_.getIsKekRetrievalInProgress_());
  }

  @Test
  public void
  testKekRetrievalFailure()
    throws KeyChain.Error, PibImpl.Error, SecurityException, IOException,
      EncodingException, NoSuchAlgorithmException, NoSuchPaddingException,
      InvalidAlgorithmParameterException, IllegalBlockSizeException,
      BadPaddingException
  {
    // Replace the default fixture.
    final int nErrors[] = new int[] { 0 };
    fixture_ = new EncryptorFixture
      (false,
       new OnError() {
         public void onError(EncryptError.ErrorCode errorCode, String message) {
           ++nErrors[0];
         }
       });

    Blob plainText = new Blob("Data to encrypt");
    EncryptedContent encryptedContent = fixture_.encryptor_.encrypt
      (plainText.getImmutableArray());

    // Check that KEK interests has been sent.
    assertTrue(fixture_.face_.sentInterests_.get(0).getName().getPrefix(6).equals
      (new Name("/access/policy/identity/NAC/dataset/KEK")));

    // ... and failed to retrieve.
    assertEquals(0, fixture_.face_.sentData_.size());

    assertEquals(1, nErrors[0]);
    assertEquals(0, fixture_.face_.sentData_.size());

    // Check recovery.
    fixture_.publishData();

    fixture_.face_.delayedCallTable_.setNowOffsetMilliseconds_(73000);
    fixture_.face_.processEvents();

    Data kekData = fixture_.face_.sentData_.get(0);
    assertTrue(kekData.getName().getPrefix(6).equals
      (new Name("/access/policy/identity/NAC/dataset/KEK")));
    assertEquals(7, kekData.getName().size());
  }

  @Test
  public void
  testEnumerateDataFromInMemoryStorage()
    throws InterruptedException
  {
    Thread.sleep(200);
    fixture_.encryptor_.regenerateCk();
    Thread.sleep(200);
    fixture_.encryptor_.regenerateCk();

    assertEquals(3, fixture_.encryptor_.size());
    int nCk = 0;
    for (Object data : fixture_.encryptor_.getCache_().values()) {
      if (((Data)data).getName().getPrefix(4).equals(new Name("/some/ck/prefix/CK")))
        ++nCk;
    }
    assertEquals(3, nCk);
  }
}
