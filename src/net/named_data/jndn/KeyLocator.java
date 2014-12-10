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
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU Lesser General Public License is in the file COPYING.
 */

package net.named_data.jndn;

import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.ChangeCountable;
import net.named_data.jndn.util.ChangeCounter;

public class KeyLocator implements ChangeCountable {
  /**
   * Create a new KeyLocator with default values.
   */
  public KeyLocator()
  {
  }

  /**
   * Create a new KeyLocator with a copy of the fields in keyLocator.
   * @param keyLocator The KeyLocator to copy.
   */
  public KeyLocator(KeyLocator keyLocator)
  {
    type_ = keyLocator.type_;
    keyData_ = keyLocator.keyData_;
    keyName_.set(new Name(keyLocator.getKeyName()));
    keyNameType_ = keyLocator.keyNameType_;
  }

  public final KeyLocatorType
  getType() { return type_; }

  public final Blob
  getKeyData() { return keyData_; }

  public final Name
  getKeyName() { return (Name)keyName_.get(); }

  public final KeyNameType
  getKeyNameType() { return keyNameType_; }

  public final void
  setType(KeyLocatorType type)
  {
    type_ = type;
    ++changeCount_;
  }

  public final void
  setKeyData(Blob keyData)
  {
    keyData_ = (keyData == null ? new Blob() : keyData);
    ++changeCount_;
  }

  public final void
  setKeyName(Name keyName)
  {
    keyName_.set((keyName == null ? new Name() : keyName));
    ++changeCount_;
  }

  public final void
  setKeyNameType(KeyNameType keyNameType)
  {
    keyNameType_ = keyNameType;
    ++changeCount_;
  }

  /**
   * Clear fields and reset to default values.
   */
  public final void
  clear()
  {
    type_ = KeyLocatorType.NONE;
    keyData_ = new Blob();
    keyName_.set(new Name());
    keyNameType_ = KeyNameType.NONE;
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
    if (keyName_.checkChanged())
      // A child object has changed, so update the change count.
      ++changeCount_;

    return changeCount_;
  }

  private KeyLocatorType type_ = KeyLocatorType.NONE;
  private Blob keyData_ = new Blob(); /**< A Blob for the key data as follows:
    *   If type_ is KeyLocatorType.KEY, the key data.
    *   If type_ is KeyLocatorType.CERTIFICATE, the certificate data.
    *   If type_ is KeyLocatorType.KEY_LOCATOR_DIGEST, the digest data.
    *   If type_ is KeyLocatorType.KEYNAME and keyNameType_ is KeyNameType.PUBLISHER_PUBLIC_KEY_DIGEST, the publisher public key digest.
    *   If type_ is KeyLocatorType.KEYNAME and keyNameType_ is KeyNameType.PUBLISHER_CERTIFICATE_DIGEST, the publisher certificate digest.
    *   If type_ is KeyLocatorType.KEYNAME and keyNameType_ is KeyNameType.PUBLISHER_ISSUER_KEY_DIGEST, the publisher issuer key digest.
    *   If type_ is KeyLocatorType.KEYNAME and keyNameType_ is KeyNameType.PUBLISHER_ISSUER_CERTIFICATE_DIGEST, the publisher issuer certificate digest.
    */
  private final ChangeCounter keyName_ =
    new ChangeCounter(new Name()); /**< The key name (only used if
                                        type_ KeyLocatorType.KEYNAME.) */
  /** @deprecated The use of a digest attached to the KeyName is deprecated. */
  private KeyNameType keyNameType_ =
    KeyNameType.NONE; /**< The type of data for keyName_. (only used if
                           type_ is KeyLocatorType.KEYNAME.) */
  private long changeCount_ = 0;
}
