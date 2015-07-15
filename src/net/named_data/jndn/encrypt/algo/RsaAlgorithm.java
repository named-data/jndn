/**
 * Copyright (C) 2015 Regents of the University of California.
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
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import net.named_data.jndn.encrypt.DecryptKey;
import net.named_data.jndn.encrypt.EncryptKey;
import net.named_data.jndn.security.RsaKeyParams;
import net.named_data.jndn.util.Blob;

/**
 * The RsaAlgorithm class provides static methods to manipulate keys, encrypt
 * and decrypt using RSA.
 * @note This class is an experimental feature. The API may change.
 */
public class RsaAlgorithm {
  static {
    try {
      keyFactory_ = KeyFactory.getInstance("RSA");
    } catch (NoSuchAlgorithmException ex) {
      Logger.getLogger(RsaAlgorithm.class.getName()).log(Level.SEVERE, null, ex);
    }
  }
  
  /**
   * Generate a new random decrypt key for AES based on the given params.
   * @param params The key params with the key size (in bits).
   * @return The new decrypt key (PKCS8-encoded private key).
   */
  public static DecryptKey
  generateKey(RsaKeyParams params) throws NoSuchAlgorithmException
  {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(params.getKeySize());
    KeyPair pair = generator.generateKeyPair();

    return new DecryptKey(new Blob(pair.getPrivate().getEncoded()));
  }

  /**
   * Derive a new encrypt key from the given decrypt key value.
   * @param keyBits The key value of the decrypt key (PKCS8-encoded private
   * key).
   * @return The new encrypt key (DER-encoded public key).
   */
  public static EncryptKey
  deriveEncryptKey(Blob keyBits) throws InvalidKeySpecException
  {
    RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey)keyFactory_.generatePrivate
      (new PKCS8EncodedKeySpec(keyBits.getImmutableArray()));

    PublicKey publicKey = keyFactory_.generatePublic(new RSAPublicKeySpec
      (privateKey.getModulus(), privateKey.getPublicExponent()));

    return new EncryptKey(new Blob(publicKey.getEncoded()));
  }

  /**
   * Decrypt the encryptedData using the keyBits according the encrypt params.
   * @param keyBits The key value (PKCS8-encoded private key).
   * @param encryptedData The data to decrypt.
   * @param params This decrypts according to params.getPaddingScheme().
   * @return The decrypted data.
   */
  public static Blob
  decrypt(Blob keyBits, Blob encryptedData, EncryptParams params)
    throws InvalidKeySpecException, NoSuchAlgorithmException,
           NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
           BadPaddingException
  {
    PrivateKey privateKey = keyFactory_.generatePrivate
      (new PKCS8EncodedKeySpec(keyBits.getImmutableArray()));

    String transformation;
    if (params.getPaddingScheme() == PaddingScheme.PKCS1v15)
      transformation = "RSA/ECB/PKCS1Padding";
    else if (params.getPaddingScheme() == PaddingScheme.OAEP_SHA)
      transformation = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    else
      throw new Error("unsupported padding scheme");

    Cipher cipher = Cipher.getInstance(transformation);
    cipher.init(Cipher.DECRYPT_MODE, privateKey);
    return new Blob(cipher.doFinal(encryptedData.getImmutableArray()));
  }

  /**
   * Encrypt the plainData using the keyBits according the encrypt params.
   * @param keyBits The key value (DER-encoded public key).
   * @param plainData The data to encrypt.
   * @param params This encrypts according to params.getPaddingScheme().
   * @return The encrypted data.
   */
  public static Blob
  encrypt(Blob keyBits, Blob plainData, EncryptParams params)
    throws InvalidKeySpecException, NoSuchAlgorithmException,
           NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
           BadPaddingException
  {
    PublicKey publicKey = keyFactory_.generatePublic
      (new X509EncodedKeySpec(keyBits.getImmutableArray()));

    String transformation;
    if (params.getPaddingScheme() == PaddingScheme.PKCS1v15)
      transformation = "RSA/ECB/PKCS1Padding";
    else if (params.getPaddingScheme() == PaddingScheme.OAEP_SHA)
      transformation = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    else
      throw new Error("unsupported padding scheme");

    Cipher cipher = Cipher.getInstance(transformation);
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    return new Blob(cipher.doFinal(plainData.getImmutableArray()));
  }

  // TODO: Move this to a common utility?
  private static final SecureRandom random_ = new SecureRandom();
  private static KeyFactory keyFactory_;
}
