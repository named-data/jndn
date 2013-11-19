/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn;

import net.named_data.jndn.util.Blob;

/**
 * A PublisherPublicKeyDigest holds the publisher public key digest value, if any.
 * We make a separate class since this is used by multiple other classes.
 */
public class PublisherPublicKeyDigest {
  public final Blob 
  getPublisherPublicKeyDigest() { return publisherPublicKeyDigest_; }

  public final void 
  setPublisherPublicKeyDigest(Blob value) 
  {
    if (value != null)
      publisherPublicKeyDigest_ = value; 
    else
      publisherPublicKeyDigest_ = new Blob();
  }

  /**
   * Clear the publisherPublicKeyDigest.
   */
  public final void 
  clear()
  {
    publisherPublicKeyDigest_ = new Blob();
  }

  private Blob publisherPublicKeyDigest_ = new Blob();
}
