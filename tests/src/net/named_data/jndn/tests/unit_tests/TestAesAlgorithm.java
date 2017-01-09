/**
 * Copyright (C) 2015-2017 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/aes.t.cpp
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

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import net.named_data.jndn.encrypt.DecryptKey;
import net.named_data.jndn.encrypt.EncryptKey;
import net.named_data.jndn.encrypt.algo.EncryptAlgorithmType;
import net.named_data.jndn.encrypt.algo.EncryptParams;
import net.named_data.jndn.encrypt.algo.AesAlgorithm;
import net.named_data.jndn.security.AesKeyParams;
import net.named_data.jndn.util.Blob;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

public class TestAesAlgorithm {
  // Convert the int array to a ByteBuffer.
  private static ByteBuffer
  toBuffer(int[] array)
  {
    ByteBuffer result = ByteBuffer.allocate(array.length);
    for (int i = 0; i < array.length; ++i)
      result.put((byte)(array[i] & 0xff));

    result.flip();
    return result;
  }

  private static final ByteBuffer KEY = toBuffer(new int[] {
    0xdd, 0x60, 0x77, 0xec, 0xa9, 0x6b, 0x23, 0x1b,
    0x40, 0x6b, 0x5a, 0xf8, 0x7d, 0x3d, 0x55, 0x32
  });

  // plaintext: AES-Encrypt-Test
  private static final ByteBuffer PLAINTEXT = toBuffer(new int[] {
    0x41, 0x45, 0x53, 0x2d, 0x45, 0x6e, 0x63, 0x72,
    0x79, 0x70, 0x74, 0x2d, 0x54, 0x65, 0x73, 0x74
  });

  private static final ByteBuffer CIPHERTEXT_ECB = toBuffer(new int[] {
    0xcb, 0xe5, 0x6a, 0x80, 0x41, 0x24, 0x58, 0x23,
    0x84, 0x14, 0x15, 0x61, 0x80, 0xb9, 0x5e, 0xbd,
    0xce, 0x32, 0xb4, 0xbe, 0xbc, 0x91, 0x31, 0xd6,
    0x19, 0x00, 0x80, 0x8b, 0xfa, 0x00, 0x05, 0x9c
  });

  private static final ByteBuffer INITIAL_VECTOR = toBuffer(new int[] {
    0x6f, 0x53, 0x7a, 0x65, 0x58, 0x6c, 0x65, 0x75,
    0x44, 0x4c, 0x77, 0x35, 0x58, 0x63, 0x78, 0x6e
  });

  private static final ByteBuffer CIPHERTEXT_CBC_IV = toBuffer(new int[] {
    0xb7, 0x19, 0x5a, 0xbb, 0x23, 0xbf, 0x92, 0xb0,
    0x95, 0xae, 0x74, 0xe9, 0xad, 0x72, 0x7c, 0x28,
    0x6e, 0xc6, 0x73, 0xb5, 0x0b, 0x1a, 0x9e, 0xb9,
    0x4d, 0xc5, 0xbd, 0x8b, 0x47, 0x1f, 0x43, 0x00
  });

  @Test
  public void
  testEncryptionDecryption()
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
           IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
  {
    EncryptParams encryptParams = new EncryptParams
      (EncryptAlgorithmType.AesEcb, 16);

    Blob key = new Blob(KEY, false);
    DecryptKey decryptKey = new DecryptKey(key);
    EncryptKey encryptKey = AesAlgorithm.deriveEncryptKey(decryptKey.getKeyBits());

    // Check key loading and key derivation.
    assertTrue(encryptKey.getKeyBits().equals(key));
    assertTrue(decryptKey.getKeyBits().equals(key));

    Blob plainBlob = new Blob(PLAINTEXT, false);

    // Encrypt data in AES_ECB.
    Blob cipherBlob = AesAlgorithm.encrypt(encryptKey.getKeyBits(), plainBlob, encryptParams);
    assertTrue(cipherBlob.equals(new Blob(CIPHERTEXT_ECB, false)));

    // Decrypt data in AES_ECB.
    Blob receivedBlob = AesAlgorithm.decrypt(decryptKey.getKeyBits(), cipherBlob, encryptParams);
    assertTrue(receivedBlob.equals(plainBlob));

    // Encrypt/decrypt data in AES_CBC with auto-generated IV.
    encryptParams.setAlgorithmType(EncryptAlgorithmType.AesCbc);
    cipherBlob = AesAlgorithm.encrypt(encryptKey.getKeyBits(), plainBlob, encryptParams);
    receivedBlob = AesAlgorithm.decrypt(decryptKey.getKeyBits(), cipherBlob, encryptParams);
    assertTrue(receivedBlob.equals(plainBlob));

    // Encrypt data in AES_CBC with specified IV.
    Blob initialVector = new Blob(INITIAL_VECTOR, false);
    encryptParams.setInitialVector(initialVector);
    cipherBlob = AesAlgorithm.encrypt(encryptKey.getKeyBits(), plainBlob, encryptParams);
    assertTrue(cipherBlob.equals(new Blob(CIPHERTEXT_CBC_IV, false)));

    // Decrypt data in AES_CBC with specified IV.
    receivedBlob = AesAlgorithm.decrypt(decryptKey.getKeyBits(), cipherBlob, encryptParams);
    assertTrue(receivedBlob.equals(plainBlob));
  }

  @Test
  public void
  testKeyGeneration()
    throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException,
      IllegalBlockSizeException, BadPaddingException,
      InvalidAlgorithmParameterException
  {
    AesKeyParams keyParams = new AesKeyParams(128);
    DecryptKey decryptKey = AesAlgorithm.generateKey(keyParams);
    EncryptKey encryptKey = AesAlgorithm.deriveEncryptKey(decryptKey.getKeyBits());

    Blob plainBlob = new Blob(PLAINTEXT, false);

    // Encrypt/decrypt data in AES_CBC with auto-generated IV.
    EncryptParams encryptParams = new EncryptParams
      (EncryptAlgorithmType.AesEcb, 16);
    Blob cipherBlob = AesAlgorithm.encrypt
      (encryptKey.getKeyBits(), plainBlob, encryptParams);
    Blob receivedBlob = AesAlgorithm.decrypt
      (decryptKey.getKeyBits(), cipherBlob, encryptParams);
    assertTrue(receivedBlob.equals(plainBlob));
  }
}