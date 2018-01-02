/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/algo/aes https://github.com/named-data/ndn-group-encrypt
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

// (This is ported from ndn::gep::algo::Aes, and named AesAlgorithm because
// "Aes" is very short and not all the Common Client Libraries have namespaces.)

package net.named_data.jndn.encrypt.algo;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import net.named_data.jndn.encrypt.DecryptKey;
import net.named_data.jndn.encrypt.EncryptKey;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.security.AesKeyParams;
import net.named_data.jndn.util.Common;

/**
 * The AesAlgorithm class provides static methods to manipulate keys, encrypt
 * and decrypt using the AES symmetric key cipher.
 * @note This class is an experimental feature. The API may change.
 */
public class AesAlgorithm {
  /**
   * Generate a new random decrypt key for AES based on the given params.
   * @param params The key params with the key size (in bits).
   * @return The new decrypt key.
   */
  public static DecryptKey
  generateKey(AesKeyParams params)
  {
    // Convert the key bit size to bytes.
    ByteBuffer key = ByteBuffer.allocate(params.getKeySize() / 8);
    Common.getRandom().nextBytes(key.array());

    DecryptKey decryptKey = new DecryptKey(new Blob(key, false));
    return decryptKey;
  }

  /**
   * Derive a new encrypt key from the given decrypt key value.
   * @param keyBits The key value of the decrypt key.
   * @return The new encrypt key.
   */
  public static EncryptKey
  deriveEncryptKey(Blob keyBits)
  {
    return new EncryptKey(keyBits);
  }

  /**
   * Decrypt the encryptedData using the keyBits according the encrypt params.
   * @param keyBits The key value.
   * @param encryptedData The data to decrypt.
   * @param params This decrypts according to params.getAlgorithmType() and
   * other params as needed such as params.getInitialVector().
   * @return The decrypted data.
   */
  public static Blob
  decrypt(Blob keyBits, Blob encryptedData, EncryptParams params)
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
           IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
  {
    if (params.getAlgorithmType() == EncryptAlgorithmType.AesEcb) {
      Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
      cipher.init
        (Cipher.DECRYPT_MODE,
         new SecretKeySpec(keyBits.getImmutableArray(), "AES"));
      return new Blob(cipher.doFinal(encryptedData.getImmutableArray()), false);
    }
    else if (params.getAlgorithmType() == EncryptAlgorithmType.AesCbc) {
      if (params.getInitialVector().size() != BLOCK_SIZE)
        throw new Error("incorrect initial vector size");

      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
      cipher.init
        (Cipher.DECRYPT_MODE,
         new SecretKeySpec(keyBits.getImmutableArray(), "AES"),
         new IvParameterSpec(params.getInitialVector().getImmutableArray()));
      return new Blob(cipher.doFinal(encryptedData.getImmutableArray()), false);
    }
    else
      throw new Error("unsupported encryption mode");
  }

  /**
   * Encrypt the plainData using the keyBits according the encrypt params.
   * @param keyBits The key value.
   * @param plainData The data to encrypt.
   * @param params This encrypts according to params.getAlgorithmType() and
   * other params as needed such as params.getInitialVector().
   * @return The encrypted data.
   */
  public static Blob
  encrypt(Blob keyBits, Blob plainData, EncryptParams params)
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
           IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
  {
    if (params.getAlgorithmType() == EncryptAlgorithmType.AesEcb) {
      Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
      cipher.init
        (Cipher.ENCRYPT_MODE,
         new SecretKeySpec(keyBits.getImmutableArray(), "AES"));
      return new Blob(cipher.doFinal(plainData.getImmutableArray()), false);
    }
    else if (params.getAlgorithmType() == EncryptAlgorithmType.AesCbc) {
      if (params.getInitialVector().size() != BLOCK_SIZE)
        throw new Error("incorrect initial vector size");

      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
      cipher.init
        (Cipher.ENCRYPT_MODE,
         new SecretKeySpec(keyBits.getImmutableArray(), "AES"),
         new IvParameterSpec(params.getInitialVector().getImmutableArray()));
      return new Blob(cipher.doFinal(plainData.getImmutableArray()), false);
    }
    else
      throw new Error("unsupported encryption mode");
  }

  public static final int BLOCK_SIZE = 16;
}
