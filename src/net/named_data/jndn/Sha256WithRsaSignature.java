/**
 * Copyright (C) 2013-2016 Regents of the University of California.
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

import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.ChangeCounter;

/**
 * A Sha256WithRsaSignature extends Signature and holds the signature bits and
 * other info representing a
 * SHA256-with-RSA signature in a data packet.
 */
public class Sha256WithRsaSignature extends Signature {
  /**
   * Create a new Sha256WithRsaSignature with default values.
   */
  public Sha256WithRsaSignature()
  {
  }

  /**
   * Create a new Sha256WithRsaSignature with a copy of the fields in the given
   * signature object.
   * @param signature The signature object to copy.
   */
  public Sha256WithRsaSignature(Sha256WithRsaSignature signature)
  {
    signature_ = signature.signature_;
    keyLocator_.set(new KeyLocator(signature.getKeyLocator()));
  }

  /**
   * Return a new Signature which is a deep copy of this signature.
   * @return A new Sha256WithRsaSignature.
   * @throws CloneNotSupportedException
   */
  public Object clone() throws CloneNotSupportedException
  {
    return new Sha256WithRsaSignature(this);
  }

  /**
   * Get the signature bytes.
   * @return The signature bytes. If not specified, the value isNull().
   */
  public final Blob
  getSignature() { return signature_; }

  public final KeyLocator
  getKeyLocator() { return (KeyLocator)keyLocator_.get(); }

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

  public final void
  setKeyLocator(KeyLocator keyLocator)
  {
    keyLocator_.set
      ((keyLocator == null ? new KeyLocator() : new KeyLocator(keyLocator)));
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
    // Make sure each of the checkChanged is called.
    boolean changed = keyLocator_.checkChanged();
    if (changed)
      // A child object has changed, so update the change count.
      ++changeCount_;

    return changeCount_;
  }

  private Blob signature_ = new Blob();
  private final ChangeCounter keyLocator_ = new ChangeCounter(new KeyLocator());
  private long changeCount_ = 0;
}
