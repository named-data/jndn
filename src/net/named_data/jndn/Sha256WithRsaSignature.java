/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn;

import net.named_data.jndn.util.Blob;

/**
 * A Sha256WithRsaSignature extends Signature and holds the signature bits and other info representing a
 * SHA256-with-RSA signature in a data packet.
 */
public class Sha256WithRsaSignature extends Signature {
  public final Blob 
  getDigestAlgorithm() { return digestAlgorithm_; }

  public final Blob 
  getWitness() { return witness_; }

  public final Blob 
  getSignature() { return signature_; }
  
  public final PublisherPublicKeyDigest 
  getPublisherPublicKeyDigest() { return publisherPublicKeyDigest_; }
  
  public final KeyLocator 
  getKeyLocator() { return keyLocator_; }

  public final void 
  setDigestAlgorithm(Blob digestAlgorithm) { digestAlgorithm_ = (digestAlgorithm == null ? new Blob() : digestAlgorithm); }
  
  public final void 
  setWitness(Blob witness) { witness_ = (witness == null ? new Blob() : witness); }

  public final void 
  setSignature(Blob signature) { signature_ = (signature == null ? new Blob() : signature); }

  public final void 
  setPublisherPublicKeyDigest(PublisherPublicKeyDigest publisherPublicKeyDigest) 
  { 
    publisherPublicKeyDigest_ = (publisherPublicKeyDigest == null ? new PublisherPublicKeyDigest() : publisherPublicKeyDigest); 
  }
  
  public final void 
  setKeyLocator(KeyLocator keyLocator) { keyLocator_ = (keyLocator == null ? new KeyLocator() : keyLocator); }

  private Blob digestAlgorithm_ = new Blob(); /**< if empty, the default is 2.16.840.1.101.3.4.2.1 (sha-256) */
  private Blob witness_ = new Blob();
  private Blob signature_ = new Blob();
  private PublisherPublicKeyDigest publisherPublicKeyDigest_ = new PublisherPublicKeyDigest();
  private KeyLocator keyLocator_ = new KeyLocator();
}
