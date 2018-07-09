/**
 * Copyright (C) 2013-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From code in ndn-cxx by Yingdi Yu <yingdi@cs.ucla.edu>
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

package net.named_data.jndn.security.certificate;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
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
import net.named_data.jndn.encrypt.algo.EncryptAlgorithmType;
import net.named_data.jndn.security.DigestAlgorithm;
import net.named_data.jndn.security.KeyType;
import net.named_data.jndn.security.UnrecognizedDigestAlgorithmException;
import net.named_data.jndn.security.UnrecognizedKeyFormatException;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

public class PublicKey {
  static {
    try {
      keyFactory_ = KeyFactory.getInstance("RSA");
    } catch (NoSuchAlgorithmException ex) {
      Logger.getLogger(PublicKey.class.getName()).log(Level.SEVERE, null, ex);
    }
  }

  public PublicKey()
  {
    keyType_ = null;
    keyDer_ = new Blob();
  }

  /**
   * Create a new PublicKey by decoding the keyDer. Set the key type from the
   * decoding.
   * @param keyDer The blob of the SubjectPublicKeyInfo DER.
   * @throws UnrecognizedKeyFormatException if can't decode the key DER.
   */
  public PublicKey(Blob keyDer) throws UnrecognizedKeyFormatException
  {
    keyDer_ = keyDer;

    // Get the public key OID.
    String oidString = null;
    try {
      DerNode parsedNode = DerNode.parse(keyDer.buf(), 0);
      List rootChildren = parsedNode.getChildren();
      List algorithmIdChildren =
        DerNode.getSequence(rootChildren, 0).getChildren();
      oidString = "" + ((DerNode)algorithmIdChildren.get(0)).toVal();
    }
    catch (DerDecodingException ex) {
      throw new UnrecognizedKeyFormatException
        ("PublicKey: Error decoding the public key: " +
         ex.getMessage());
    }

    // Verify that the we can decode.
    if (oidString.equals(RSA_ENCRYPTION_OID)) {
      keyType_ = KeyType.RSA;

      KeyFactory keyFactory = null;
      try {
        keyFactory = KeyFactory.getInstance("RSA");
      }
      catch (NoSuchAlgorithmException exception) {
        // Don't expect this to happen.
        throw new UnrecognizedKeyFormatException
          ("RSA is not supported: " + exception.getMessage());
      }

      try {
        keyFactory.generatePublic
          (new X509EncodedKeySpec(keyDer.getImmutableArray()));
      }
      catch (InvalidKeySpecException exception) {
        // Don't expect this to happen.
        throw new UnrecognizedKeyFormatException
          ("X509EncodedKeySpec is not supported for RSA: " + exception.getMessage());
      }
    }
    else if (oidString.equals(EC_ENCRYPTION_OID)) {
      keyType_ = KeyType.EC;

      KeyFactory keyFactory = null;
      try {
        keyFactory = KeyFactory.getInstance("EC");
      }
      catch (NoSuchAlgorithmException exception) {
        // Don't expect this to happen.
        throw new UnrecognizedKeyFormatException
          ("EC is not supported: " + exception.getMessage());
      }

      try {
        keyFactory.generatePublic
          (new X509EncodedKeySpec(keyDer.getImmutableArray()));
      }
      catch (InvalidKeySpecException exception) {
        // Don't expect this to happen.
        throw new UnrecognizedKeyFormatException
          ("X509EncodedKeySpec is not supported for EC: " + exception.getMessage());
      }
    }
    else
      throw new UnrecognizedKeyFormatException(
        "PublicKey: Unrecognized OID " + oidString);
  }

  /**
   * Encode the public key into DER.
   * @return the encoded DER syntax tree.
   */
  public final DerNode
  toDer() throws DerDecodingException
  {
    return DerNode.parse(keyDer_.buf());
  }

  public KeyType
  getKeyType() { return keyType_; }

  /*
   * Get the digest of the public key.
   * @param digestAlgorithm The digest algorithm.
   */
  public final Blob
  getDigest(DigestAlgorithm digestAlgorithm) throws UnrecognizedDigestAlgorithmException
  {
    if (digestAlgorithm == DigestAlgorithm.SHA256) {
      return new Blob(Common.digestSha256(keyDer_.buf()), false);
    }
    else
      throw new UnrecognizedDigestAlgorithmException("Wrong format!");
  }

  /*
   * Get the digest of the public key using DigestAlgorithm.SHA256.
   */
  public final Blob
  getDigest()
  {
    try {
      return getDigest(DigestAlgorithm.SHA256);
    }
    catch (UnrecognizedDigestAlgorithmException ex) {
      // We don't expect this exception.
      throw new Error("UnrecognizedDigestAlgorithmException " + ex.getMessage());
    }
  }

  /*
   * Get the raw bytes of the public key in DER format.
   */
  public final Blob
  getKeyDer() { return keyDer_; }

  /**
   * Encrypt the plainData using the keyBits according the encrypt algorithm type.
   * @param plainData The data to encrypt.
   * @param algorithmType This encrypts according to the algorithm type, e.g.,
   * RsaOaep.
   * @return The encrypted data.
   */
  public Blob
  encrypt(byte[] plainData, EncryptAlgorithmType algorithmType)
    throws InvalidKeySpecException, NoSuchAlgorithmException,
           NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
           BadPaddingException
  {
    java.security.PublicKey publicKey = keyFactory_.generatePublic
      (new X509EncodedKeySpec(keyDer_.getImmutableArray()));

    String transformation;
    if (algorithmType == EncryptAlgorithmType.RsaPkcs) {
      if (keyType_ != KeyType.RSA)
        throw new Error("The key type must be RSA");

      transformation = "RSA/ECB/PKCS1Padding";
    }
    else if (algorithmType == EncryptAlgorithmType.RsaOaep) {
      if (keyType_ != KeyType.RSA)
        throw new Error("The key type must be RSA");

      transformation = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    }
    else
      throw new Error("unsupported padding scheme");

    Cipher cipher = Cipher.getInstance(transformation);
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    return new Blob(cipher.doFinal(plainData), false);
  }

  /**
   * Encrypt the plainData using the keyBits according the encrypt algorithm type.
   * @param plainData The data to encrypt.
   * @param algorithmType This encrypts according to the algorithm type, for
   * example RsaOaep.
   * @return The encrypted data.
   */
  public Blob
  encrypt(Blob plainData, EncryptAlgorithmType algorithmType)
    throws InvalidKeySpecException, NoSuchAlgorithmException,
           NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
           BadPaddingException
  {
    return encrypt(plainData.getImmutableArray(), algorithmType);
  }

  private static String RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1";
  private static String EC_ENCRYPTION_OID = "1.2.840.10045.2.1";

  private final KeyType keyType_;
  private final Blob keyDer_;   /**< PublicKeyInfo in DER */
  private static KeyFactory keyFactory_;
}
