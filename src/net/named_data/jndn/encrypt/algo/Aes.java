/**
 * Copyright (C) 2015 Regents of the University of California.
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

package net.named_data.jndn.encrypt.algo;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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

public class Aes {
  public static DecryptKey
  generateKey(AesKeyParams params)
  {
    // Converting the key bit size to bytes.
    ByteBuffer key = ByteBuffer.allocate(params.getKeySize() * 8);
    random_.nextBytes(key.array());

    DecryptKey decryptKey = new DecryptKey(new Blob(key, false));
    return decryptKey;
  }

  public static EncryptKey
  deriveEncryptKey(Blob keyBits)
  {
    return new EncryptKey(keyBits);
  }

  public static Blob
  decrypt(Blob keyBits, Blob encryptedData, EncryptParams params)
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
           IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
  {
    if (params.getEncryptionMode().equals(EncryptionMode.ECB_AES)) {
      Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
      cipher.init
        (Cipher.DECRYPT_MODE,
         new SecretKeySpec(keyBits.getImmutableArray(), "AES"));
      return new Blob(cipher.doFinal(encryptedData.getImmutableArray()));
    }
    else if (params.getEncryptionMode().equals(EncryptionMode.CBC_AES)) {
      if (params.getInitialVector().size() != BLOCK_SIZE)
        throw new Error("incorrect initial vector size");

      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
      cipher.init
        (Cipher.DECRYPT_MODE,
         new SecretKeySpec(keyBits.getImmutableArray(), "AES"),
         new IvParameterSpec(params.getInitialVector().getImmutableArray()));
      return new Blob(cipher.doFinal(encryptedData.getImmutableArray()));
    }
    else
      throw new Error("unsupported encryption mode");
  }

  public static Blob
  encrypt(Blob keyBits, Blob plainData, EncryptParams params)
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
           IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
  {
    if (params.getEncryptionMode().equals(EncryptionMode.ECB_AES)) {
      Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
      cipher.init
        (Cipher.ENCRYPT_MODE,
         new SecretKeySpec(keyBits.getImmutableArray(), "AES"));
      return new Blob(cipher.doFinal(plainData.getImmutableArray()));
    }
    else if (params.getEncryptionMode().equals(EncryptionMode.CBC_AES)) {
      if (params.getInitialVector().size() != BLOCK_SIZE)
        throw new Error("incorrect initial vector size");
      
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
      cipher.init
        (Cipher.ENCRYPT_MODE,
         new SecretKeySpec(keyBits.getImmutableArray(), "AES"),
         new IvParameterSpec(params.getInitialVector().getImmutableArray()));
      return new Blob(cipher.doFinal(plainData.getImmutableArray()));
    }
    else
      throw new Error("unsupported encryption mode");
  }

  private static final int BLOCK_SIZE = 16;
  // TODO: Move this to a common utility?
  private static final SecureRandom random_ = new SecureRandom();
}
