/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From code in NDN-CPP by Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.security.certificate;

import net.named_data.jndn.encoding.OID;
import net.named_data.jndn.encoding.der.DerNode;
import net.named_data.jndn.security.DigestAlgorithm;
import net.named_data.jndn.util.Blob;

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
    // new X509EncodedKeySpec(publicKeyDer.array());
    throw new UnsupportedOperationException
      ("PublicKey.fromDer is not implemented");
  }

  /*
   * Get the digest of the public key.
   * @param digestAlgorithm The digest algorithm.
   */
  public final Blob 
  getDigest(DigestAlgorithm digestAlgorithm)
  {
    throw new UnsupportedOperationException
      ("PublicKey.getDigest is not implemented");
  }

  /*
   * Get the digest of the public key using DigestAlgorithm.SHA256.
   */
  public final Blob 
  getDigest()
  {
    return getDigest(DigestAlgorithm.SHA256);
  }

  /*
   * Get the raw bytes of the public key in DER format.
   */
  public final Blob 
  getKeyDer() { return keyDer_; }
    
  private final OID algorithm_; /**< Algorithm */
  private final Blob keyDer_;   /**< PublicKeyInfo in DER */
}
