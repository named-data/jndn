/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/encryptor https://github.com/named-data/ndn-group-encrypt
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
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import net.named_data.jndn.Data;
import net.named_data.jndn.KeyLocator;
import net.named_data.jndn.KeyLocatorType;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.TlvWireFormat;
import net.named_data.jndn.encrypt.EncryptedContent;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

/**
 * Encryptor has static constants and utility methods for encryption, such as
 * encryptData.
 */
public class Encryptor {
  public static final Name.Component NAME_COMPONENT_FOR = new Name.Component("FOR");
  public static final Name.Component NAME_COMPONENT_READ = new Name.Component("READ");
  public static final Name.Component NAME_COMPONENT_SAMPLE = new Name.Component("SAMPLE");
  public static final Name.Component NAME_COMPONENT_ACCESS = new Name.Component("ACCESS");
  public static final Name.Component NAME_COMPONENT_E_KEY = new Name.Component("E-KEY");
  public static final Name.Component NAME_COMPONENT_D_KEY = new Name.Component("D-KEY");
  public static final Name.Component NAME_COMPONENT_C_KEY = new Name.Component("C-KEY");

  /**
   * Prepare an encrypted data packet by encrypting the payload using the key
   * according to the params. In addition, this prepares the encoded
   * EncryptedContent with the encryption result using keyName and params. The
   * encoding is set as the content of the data packet. If params defines an
   * asymmetric encryption algorithm and the payload is larger than the maximum
   * plaintext size, this encrypts the payload with a symmetric key that is
   * asymmetrically encrypted and provided as a nonce in the content of the data
   * packet. The packet's /{dataName}/ is updated to be
   * /{dataName}/FOR/{keyName}
   * @param data The data packet which is updated.
   * @param payload The payload to encrypt.
   * @param keyName The key name for the EncryptedContent.
   * @param key The encryption key value.
   * @param params The parameters for encryption.
   */
  public static void
  encryptData
    (Data data, Blob payload, Name keyName, Blob key, EncryptParams params)
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
      IllegalBlockSizeException, BadPaddingException,
      InvalidAlgorithmParameterException, InvalidKeySpecException
  {
    data.getName().append(NAME_COMPONENT_FOR).append(keyName);

    EncryptAlgorithmType algorithmType = params.getAlgorithmType();

    if (algorithmType == EncryptAlgorithmType.AesCbc ||
        algorithmType == EncryptAlgorithmType.AesEcb) {
      EncryptedContent content = encryptSymmetric(payload, key, keyName, params);
      data.setContent(content.wireEncode(TlvWireFormat.get()));
    }
    else if (algorithmType == EncryptAlgorithmType.RsaPkcs ||
             algorithmType == EncryptAlgorithmType.RsaOaep) {
      // Java doesn't have a direct way to get the maximum plain text size, so
      // try to encrypt the payload first and catch the error if it is too big.
      try {
        EncryptedContent content = encryptAsymmetric
          (payload, key, keyName, params);
        data.setContent(content.wireEncode(TlvWireFormat.get()));
        return;
      } catch (IllegalBlockSizeException ex) {
        // The payload is larger than the maximum plaintext size. Continue.
      } catch (ArrayIndexOutOfBoundsException ex) {
        // The payload is larger than the maximum plaintext size. Continue.
        // (This is the exception thrown on Android.)
      }

      // 128-bit nonce.
      ByteBuffer nonceKeyBuffer = ByteBuffer.allocate(16);
      Common.getRandom().nextBytes(nonceKeyBuffer.array());
      Blob nonceKey = new Blob(nonceKeyBuffer, false);

      Name nonceKeyName = new Name(keyName);
      nonceKeyName.append("nonce");

      EncryptParams symmetricParams = new EncryptParams
        (EncryptAlgorithmType.AesCbc, AesAlgorithm.BLOCK_SIZE);

      EncryptedContent nonceContent = encryptSymmetric
        (payload, nonceKey, nonceKeyName, symmetricParams);

      EncryptedContent payloadContent = encryptAsymmetric
        (nonceKey, key, keyName, params);

      Blob nonceContentEncoding = nonceContent.wireEncode();
      Blob payloadContentEncoding = payloadContent.wireEncode();
      ByteBuffer content = ByteBuffer.allocate
        (nonceContentEncoding.size() + payloadContentEncoding.size());
      content.put(payloadContentEncoding.buf());
      content.put(nonceContentEncoding.buf());
      content.flip();

      data.setContent(new Blob(content, false));
    }
    else
      throw new Error("Unsupported encryption method");
  }

  /**
   * Encrypt the payload using the symmetric key according to params, and return
   * an EncryptedContent.
   * @param payload The data to encrypt.
   * @param key The key value.
   * @param keyName The key name for the EncryptedContent key locator.
   * @param params The parameters for encryption.
   * @return A new EncryptedContent.
   */
  private static EncryptedContent
  encryptSymmetric(Blob payload, Blob key, Name keyName, EncryptParams params)
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
      IllegalBlockSizeException, BadPaddingException,
      InvalidAlgorithmParameterException
  {
    EncryptAlgorithmType algorithmType = params.getAlgorithmType();
    Blob initialVector = params.getInitialVector();
    KeyLocator keyLocator = new KeyLocator();
    keyLocator.setType(KeyLocatorType.KEYNAME);
    keyLocator.setKeyName(keyName);

    if (algorithmType == EncryptAlgorithmType.AesCbc ||
        algorithmType == EncryptAlgorithmType.AesEcb) {
      if (algorithmType == EncryptAlgorithmType.AesCbc) {
        if (initialVector.size() != AesAlgorithm.BLOCK_SIZE)
          throw new Error("incorrect initial vector size");
      }

      Blob encryptedPayload = AesAlgorithm.encrypt(key, payload, params);

      EncryptedContent result = new EncryptedContent();
      result.setAlgorithmType(algorithmType);
      result.setKeyLocator(keyLocator);
      result.setPayload(encryptedPayload);
      result.setInitialVector(initialVector);
      return result;
    }
    else
      throw new Error("Unsupported encryption method");
  }

  /**
   * Encrypt the payload using the asymmetric key according to params, and
   * return an EncryptedContent.
   * @param payload The data to encrypt. The size should be within range of the
   * key.
   * @param key The key value.
   * @param keyName The key name for the EncryptedContent key locator.
   * @param params The parameters for encryption.
   * @return A new EncryptedContent.
   */
  private static EncryptedContent
  encryptAsymmetric(Blob payload, Blob key, Name keyName, EncryptParams params)
    throws InvalidKeySpecException, NoSuchAlgorithmException,
           NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
           BadPaddingException
  {
    EncryptAlgorithmType algorithmType = params.getAlgorithmType();
    KeyLocator keyLocator = new KeyLocator();
    keyLocator.setType(KeyLocatorType.KEYNAME);
    keyLocator.setKeyName(keyName);

    if (algorithmType == EncryptAlgorithmType.RsaPkcs ||
        algorithmType == EncryptAlgorithmType.RsaOaep) {
      Blob encryptedPayload = RsaAlgorithm.encrypt(key, payload, params);

      EncryptedContent result = new EncryptedContent();
      result.setAlgorithmType(algorithmType);
      result.setKeyLocator(keyLocator);
      result.setPayload(encryptedPayload);
      return result;
    }
    else
      throw new Error("Unsupported encryption method");
  }
}
