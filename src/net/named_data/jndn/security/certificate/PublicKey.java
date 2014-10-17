/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From code in NDN-CPP by Yingdi Yu <yingdi@cs.ucla.edu>
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

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import net.named_data.jndn.encoding.der.DerDecodingException;
import net.named_data.jndn.encoding.der.DerNode;
import net.named_data.jndn.security.DigestAlgorithm;
import net.named_data.jndn.security.KeyType;
import net.named_data.jndn.security.UnrecognizedDigestAlgorithmException;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

public class PublicKey {
  public PublicKey() 
  {
    keyType_ = null;
    keyDer_ = new Blob();
  }
  
  /**
   * Create a new PublicKey with the given values.
   * @param keyType The KeyType, such as KeyType.RSA.
   * @param keyDer The blob of the PublicKeyInfo in terms of DER.
   */
  public PublicKey(KeyType keyType, Blob keyDer)
  {
    keyType_ = keyType;
    keyDer_ = keyDer;
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

  /**
   * Decode the public key from DER blob.
   * @param keyType The KeyType, such as KeyType.RSA.
   * @param keyDer The DER blob.
   * @return The decoded public key.
   * @throws SecurityException if can't decode the key DER.
   */
  public static PublicKey
  fromDer(KeyType keyType, Blob keyDer) throws SecurityException
  {
    if (keyType == KeyType.RSA) {
      KeyFactory keyFactory = null;
      try {
        keyFactory = KeyFactory.getInstance("RSA");
      }
      catch (NoSuchAlgorithmException exception) {
        // Don't expect this to happen.
        throw new SecurityException
          ("RSA is not supported: " + exception.getMessage());
      }

      try {
        keyFactory.generatePublic
          (new X509EncodedKeySpec(keyDer.getImmutableArray()));
      }
      catch (InvalidKeySpecException exception) {
        // Don't expect this to happen.
        throw new SecurityException
          ("X509EncodedKeySpec is not supported for RSA: " + exception.getMessage());
      }
    }
    else if (keyType == KeyType.EC) {
      KeyFactory keyFactory = null;
      try {
        keyFactory = KeyFactory.getInstance("EC");
      }
      catch (NoSuchAlgorithmException exception) {
        // Don't expect this to happen.
        throw new SecurityException
          ("EC is not supported: " + exception.getMessage());
      }

      try {
        keyFactory.generatePublic
          (new X509EncodedKeySpec(keyDer.getImmutableArray()));
      }
      catch (InvalidKeySpecException exception) {
        // Don't expect this to happen.
        throw new SecurityException
          ("X509EncodedKeySpec is not supported for EC: " + exception.getMessage());
      }
    }
    else
      throw new SecurityException("PublicKey.fromDer: Unrecognized keyType");

    return new PublicKey(keyType, keyDer);
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
      return new Blob(Common.digestSha256(keyDer_.buf()));
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

  private final KeyType keyType_;
  private final Blob keyDer_;   /**< PublicKeyInfo in DER */
}
