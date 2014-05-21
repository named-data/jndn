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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

package net.named_data.jndn.security.certificate;

import net.named_data.jndn.encoding.OID;
import net.named_data.jndn.encoding.der.DerNode;
import net.named_data.jndn.security.DigestAlgorithm;
import net.named_data.jndn.security.UnrecognizedDigestAlgorithmException;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

public class PublicKey {
  /**
   * Create a new PublicKey with the given values.
   * @param algorithm The algorithm of the public key.
   * @param keyDer The blob of the PublicKeyInfo in terms of DER.
   */
  public PublicKey(OID algorithm, Blob keyDer)
  {
    algorithm_ = algorithm;
    keyDer_ = keyDer;
  }

  /**
   * Encode the public key into DER.
   * @return the encoded DER syntax tree.
   */
  public final DerNode
  toDer()
  {
    throw new UnsupportedOperationException
      ("PublicKey.toDer is not implemented");
  }

  /**
   * Decode the public key from DER blob.
   * @param keyDer The DER blob.
   * @return The decoded public key.
   */
  public static PublicKey
  fromDer(Blob keyDer)
  {
    // TODO: Do a test decode and use RSA_OID.
    return new PublicKey(null, keyDer);
  }

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
    
  private final OID algorithm_; /**< Algorithm */
  private final Blob keyDer_;   /**< PublicKeyInfo in DER */
}
