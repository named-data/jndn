/**
 * Copyright (C) 2018-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/name-based-access-control/blob/new/tests/tests/decryptor.t.cpp
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
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Data;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encrypt.DecryptorV2;
import net.named_data.jndn.encrypt.EncryptError;
import net.named_data.jndn.encrypt.EncryptedContent;
import net.named_data.jndn.in_memory_storage.InMemoryStorageRetaining;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SafeBag;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.ValidatorNull;
import net.named_data.jndn.security.pib.Pib;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.security.tpm.Tpm;
import net.named_data.jndn.security.tpm.TpmBackEnd;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.util.Blob;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class TestDecryptorV2 {
  static class DecryptorFixture extends IdentityManagementFixture {
    public DecryptorFixture(Name identityName)
      throws PibImpl.Error, Pib.Error, KeyChain.Error, SecurityException,
        IOException, EncodingException, Tpm.Error, TpmBackEnd.Error,
        CertificateV2.Error
    {
      // Include the code here from the NAC unit-tests class
      // DecryptorStaticDataEnvironment instead of making it a base class.
      for (ByteBuffer buffer : EncryptStaticData.managerPackets) {
        Data data = new Data();
        data.wireDecode(buffer);
        storage_.insert(data);
      }

      for (ByteBuffer buffer : EncryptStaticData.encryptorPackets) {
        Data data = new Data();
        data.wireDecode(buffer);
        storage_.insert(data);
      }

      // Import the "/first/user" identity.
      keyChain_.importSafeBag
        (new SafeBag(EncryptStaticData.userIdentity), 
         new Blob("password").buf());

      addIdentity(new Name("/not/authorized"));

      face_ = new InMemoryStorageFace(storage_);
      validator_ = new ValidatorNull();
      decryptor_ = new DecryptorV2
        (keyChain_.getPib().getIdentity(identityName).getDefaultKey(),
         validator_, keyChain_, face_);
    }

    public final InMemoryStorageRetaining storage_ =
      new InMemoryStorageRetaining();
    public final InMemoryStorageFace face_;
    public final ValidatorNull validator_;
    public final DecryptorV2 decryptor_;
  }

  @Before
  public void
  setUp()
  {
    // Turn off INFO log messages.
    Logger.getLogger("").setLevel(Level.SEVERE);
  }

  @Test
  public void
  testDecryptValid()
    throws PibImpl.Error, Pib.Error, SecurityException, IOException,
      EncodingException, KeyChain.Error, Tpm.Error, TpmBackEnd.Error,
      CertificateV2.Error
  {
    DecryptorFixture fixture = new DecryptorFixture(new Name("/first/user"));

    EncryptedContent encryptedContent = new EncryptedContent();
    encryptedContent.wireDecodeV2(EncryptStaticData.encryptedBlobs[0]);

    final int[] nSuccesses = new int[] { 0 };
    final int[] nFailures = new int[] { 0 };
    fixture.decryptor_.decrypt
      (encryptedContent, 
       new DecryptorV2.DecryptSuccessCallback() {
         public void onSuccess(Blob plainData) {
           ++nSuccesses[0];
           assertEquals(15, plainData.size());
           assertTrue(plainData.equals(new Blob("Data to encrypt")));
         }
       },
       new EncryptError.OnError() {
         public void onError(EncryptError.ErrorCode errorCode, String message) {
           ++nFailures[0];
         }
       });

    assertEquals(1, nSuccesses[0]);
    assertEquals(0, nFailures[0]);
  }

  @Test
  public void
  testDecryptInvalid()
    throws PibImpl.Error, Pib.Error, SecurityException, IOException,
      EncodingException, KeyChain.Error, Tpm.Error, TpmBackEnd.Error,
      CertificateV2.Error
  {
    DecryptorFixture fixture = new DecryptorFixture(new Name("/not/authorized"));

    EncryptedContent encryptedContent = new EncryptedContent();
    encryptedContent.wireDecodeV2(EncryptStaticData.encryptedBlobs[0]);

    final int[] nSuccesses = new int[] { 0 };
    final int[] nFailures = new int[] { 0 };
    fixture.decryptor_.decrypt
      (encryptedContent,
       new DecryptorV2.DecryptSuccessCallback() {
         public void onSuccess(Blob plainData) {
           ++nSuccesses[0];
         }
       },
       new EncryptError.OnError() {
         public void onError(EncryptError.ErrorCode errorCode, String message) {
           ++nFailures[0];
         }
       });

    assertEquals(0, nSuccesses[0]);
    assertEquals(1, nFailures[0]);
  }
}
