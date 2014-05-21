/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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

package net.named_data.jndn;

import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.ChangeCountable;

/**
 * A PublisherPublicKeyDigest holds the publisher public key digest value, if 
 * any.
 * We make a separate class since this is used by multiple other classes.
 */
public class PublisherPublicKeyDigest implements ChangeCountable {
  /**
   * Create a new PublisherPublicKeyDigest with an empty value.
   */
  public PublisherPublicKeyDigest()
  {  
  }

  /**
   * Create a new PublisherPublicKeyDigest with a copy of the value in the given 
   * publisherPublicKeyDigest.
   * @param publisherPublicKeyDigest The PublisherPublicKeyDigest to copy.
   */
  public PublisherPublicKeyDigest
    (PublisherPublicKeyDigest publisherPublicKeyDigest)
  {  
    publisherPublicKeyDigest_ = 
      publisherPublicKeyDigest.publisherPublicKeyDigest_;
  }

  public final Blob 
  getPublisherPublicKeyDigest() { return publisherPublicKeyDigest_; }

  public final void 
  setPublisherPublicKeyDigest(Blob publisherPublicKeyDigest) 
  {
    publisherPublicKeyDigest_ = (publisherPublicKeyDigest == null ? 
      new Blob() : publisherPublicKeyDigest);
    ++changeCount_;
  }

  /**
   * Clear the publisherPublicKeyDigest.
   */
  public final void 
  clear()
  {
    publisherPublicKeyDigest_ = new Blob();
    ++changeCount_;
  }

  /**
   * Get the change count, which is incremented each time this object is 
   * changed.
   * @return The change count.
   */
  public final long 
  getChangeCount() { return changeCount_; }

  private Blob publisherPublicKeyDigest_ = new Blob();
  private long changeCount_ = 0;
}
