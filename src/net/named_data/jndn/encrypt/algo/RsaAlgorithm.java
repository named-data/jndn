/**
 * Copyright (C) 2015-2016 Regents of the University of California.
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

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import net.named_data.jndn.encoding.der.DerDecodingException;
import net.named_data.jndn.encoding.der.DerNode;
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
   * Generate a new random decrypt key for RSA based on the given params.
   * @param params The key params with the key size (in bits).
   * @return The new decrypt key (PKCS8-encoded private key).
   */
  public static DecryptKey
  generateKey(RsaKeyParams params) throws NoSuchAlgorithmException
  {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(params.getKeySize());
    KeyPair pair = generator.generateKeyPair();

    return new DecryptKey(new Blob(pair.getPrivate().getEncoded(), false));
  }

  /**
   * Derive a new encrypt key from the given decrypt key value.
   * @param keyBits The key value of the decrypt key (PKCS8-encoded private
   * key).
   * @return The new encrypt key (DER-encoded public key).
   */
  public static EncryptKey
  deriveEncryptKey(Blob keyBits)
    throws InvalidKeySpecException, DerDecodingException
  {
    // Decode the PKCS #8 private key. (We don't use RSAPrivateCrtKey because
    // the Android library doesn't have an easy way to decode into it.)
    DerNode parsedNode = DerNode.parse(keyBits.buf(), 0);
    List pkcs8Children = parsedNode.getChildren();
    List algorithmIdChildren = DerNode.getSequence(pkcs8Children, 1).getChildren();
    String oidString = ((DerNode.DerOid)algorithmIdChildren.get(0)).toVal().toString();
    Blob rsaPrivateKeyDer = ((DerNode)pkcs8Children.get(2)).getPayload();

    final String RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1";
    if (!oidString.equals(RSA_ENCRYPTION_OID))
      throw new DerDecodingException("The PKCS #8 private key is not RSA_ENCRYPTION");

    // Decode the PKCS #1 RSAPrivateKey.
    parsedNode = DerNode.parse(rsaPrivateKeyDer.buf(), 0);
    List rsaPrivateKeyChildren = parsedNode.getChildren();
    Blob modulus = ((DerNode)rsaPrivateKeyChildren.get(1)).getPayload();
    Blob publicExponent = ((DerNode)rsaPrivateKeyChildren.get(2)).getPayload();

    java.security.PublicKey publicKey = keyFactory_.generatePublic(new RSAPublicKeySpec
      (new BigInteger(modulus.getImmutableArray()),
       new BigInteger(publicExponent.getImmutableArray())));

    return new EncryptKey(new Blob(publicKey.getEncoded(), false));
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
    throws InvalidKeySpecException, NoSuchAlgorithmException,
           NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
           BadPaddingException
  {
    PrivateKey privateKey = keyFactory_.generatePrivate
      (new PKCS8EncodedKeySpec(keyBits.getImmutableArray()));

    String transformation;
    if (params.getAlgorithmType() == EncryptAlgorithmType.RsaPkcs)
      transformation = "RSA/ECB/PKCS1Padding";
    else if (params.getAlgorithmType() == EncryptAlgorithmType.RsaOaep)
      transformation = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    else
      throw new Error("unsupported padding scheme");

    Cipher cipher = Cipher.getInstance(transformation);
    cipher.init(Cipher.DECRYPT_MODE, privateKey);
    return new Blob(cipher.doFinal(encryptedData.getImmutableArray()), false);
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
    java.security.PublicKey publicKey = keyFactory_.generatePublic
      (new X509EncodedKeySpec(keyBits.getImmutableArray()));

    String transformation;
    if (params.getAlgorithmType() == EncryptAlgorithmType.RsaPkcs)
      transformation = "RSA/ECB/PKCS1Padding";
    else if (params.getAlgorithmType() == EncryptAlgorithmType.RsaOaep)
      transformation = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    else
      throw new Error("unsupported padding scheme");

    Cipher cipher = Cipher.getInstance(transformation);
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    return new Blob(cipher.doFinal(plainData.getImmutableArray()), false);
  }

  private static KeyFactory keyFactory_;
}
