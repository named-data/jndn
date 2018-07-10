/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/algo/rsa https://github.com/named-data/ndn-group-encrypt
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

// (This is ported from ndn::gep::algo::Rsa, and named RsaAlgorithm because
// "Rsa" is very short and not all the Common Client Libraries have namespaces.)

package net.named_data.jndn.encrypt.algo;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import net.named_data.jndn.encrypt.DecryptKey;
import net.named_data.jndn.encrypt.EncryptKey;
import net.named_data.jndn.security.RsaKeyParams;
import net.named_data.jndn.security.tpm.TpmPrivateKey;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.UnrecognizedKeyFormatException;
import net.named_data.jndn.security.certificate.PublicKey;

/**
 * The RsaAlgorithm class provides static methods to manipulate keys, encrypt
 * and decrypt using RSA.
 * @note This class is an experimental feature. The API may change.
 */
public class RsaAlgorithm {
  /**
   * Generate a new random decrypt key for RSA based on the given params.
   * @param params The key params with the key size (in bits).
   * @return The new decrypt key (PKCS8-encoded private key).
   */
  public static DecryptKey
  generateKey(RsaKeyParams params) throws SecurityException
  {
    TpmPrivateKey privateKey;
    try {
      privateKey = TpmPrivateKey.generatePrivateKey(params);
    } catch (IllegalArgumentException ex) {
      throw new SecurityException("generateKey: Error in generatePrivateKey: " + ex);
    } catch (TpmPrivateKey.Error ex) {
      throw new SecurityException("generateKey: Error in generatePrivateKey: " + ex);
    }

    try {
      return new DecryptKey(privateKey.toPkcs8());
    } catch (TpmPrivateKey.Error ex) {
      throw new SecurityException("generateKey: Error in toPkcs8: " + ex);
    }
  }

  /**
   * Derive a new encrypt key from the given decrypt key value.
   * @param keyBits The key value of the decrypt key (PKCS8-encoded private
   * key).
   * @return The new encrypt key (DER-encoded public key).
   */
  public static EncryptKey
  deriveEncryptKey(Blob keyBits) throws SecurityException
  {
    TpmPrivateKey privateKey = new TpmPrivateKey();
    try {
      privateKey.loadPkcs8(keyBits.buf());
    } catch (TpmPrivateKey.Error ex) {
      throw new SecurityException("deriveEncryptKey: Error in loadPkcs8: " + ex);
    }

    try {
      return new EncryptKey(privateKey.derivePublicKey());
    } catch (TpmPrivateKey.Error ex) {
      throw new SecurityException("deriveEncryptKey: Error in derivePublicKey: " + ex);
    }
  }

  /**
   * Decrypt the encryptedData using the keyBits according the encrypt params.
   * @param keyBits The key value (PKCS8-encoded private key).
   * @param encryptedData The data to decrypt.
   * @param params This decrypts according to params.getAlgorithmType().
   * @return The decrypted data.
   */
  public static Blob
  decrypt(Blob keyBits, Blob encryptedData, EncryptParams params)
    throws SecurityException
  {
    TpmPrivateKey privateKey = new TpmPrivateKey();
    try {
      privateKey.loadPkcs8(keyBits.buf());
    } catch (TpmPrivateKey.Error ex) {
      throw new SecurityException("decrypt: Error in loadPkcs8: " + ex);
    }

    try {
      return privateKey.decrypt(encryptedData.buf(), params.getAlgorithmType());
    } catch (TpmPrivateKey.Error ex) {
      throw new SecurityException("decrypt: Error in decrypt: " + ex);
    }
  }

  /**
   * Encrypt the plainData using the keyBits according the encrypt params.
   * @param keyBits The key value (DER-encoded public key).
   * @param plainData The data to encrypt.
   * @param params This encrypts according to params.getAlgorithmType().
   * @return The encrypted data.
   */
  public static Blob
  encrypt(Blob keyBits, Blob plainData, EncryptParams params)
    throws InvalidKeySpecException, NoSuchAlgorithmException,
           NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
           BadPaddingException
  {
    try {
      return new PublicKey(keyBits).encrypt
        (plainData, params.getAlgorithmType());
    } catch (UnrecognizedKeyFormatException ex) {
      throw new InvalidKeyException(ex.getMessage());
    }
  }
}
