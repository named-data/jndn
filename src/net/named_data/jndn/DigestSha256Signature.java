/**
 * Copyright (C) 2014-2016 Regents of the University of California.
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
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU Lesser General Public License is in the file COPYING.
 */

package net.named_data.jndn;

import net.named_data.jndn.util.Blob;

/**
 * A DigestSha256Signature extends Signature and holds the signature bits (which
 * are only the SHA256 digest) and an empty SignatureInfo for a data packet or
 * signed interest.
 */
public class DigestSha256Signature extends Signature {
  /**
   * Create a new DigestSha256Signature with default values.
   */
  public DigestSha256Signature()
  {
  }

  /**
   * Create a new DigestSha256Signature with a copy of the fields in the given
   * signature object.
   * @param signature The signature object to copy.
   */
  public DigestSha256Signature(DigestSha256Signature signature)
  {
    signature_ = signature.signature_;
  }

  /**
   * Return a new DigestSha256Signature which is a deep copy of this
   * DigestSha256Signature.
   * @return A new DigestSha256Signature.
   * @throws CloneNotSupportedException
   */
  public Object clone() throws CloneNotSupportedException
  {
    return new DigestSha256Signature(this);
  }

  /**
   * Get the signature bytes.
   * @return The signature bytes. If not specified, the value isNull().
   */
  public final Blob
  getSignature() { return signature_; }

  /**
   * Set the signature bytes to the given value.
   * @param signature A Blob with the signature bytes.
   */
  public final void
  setSignature(Blob signature)
  {
    signature_ = (signature == null ? new Blob() : signature);
    ++changeCount_;
  }

  /**
   * Get the change count, which is incremented each time this object
   * (or a child object) is changed.
   * @return The change count.
   */
  public final long
  getChangeCount()
  {
    return changeCount_;
  }

  private Blob signature_ = new Blob();
  private long changeCount_ = 0;
}
