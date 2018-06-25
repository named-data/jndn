/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/pib/identity.cpp
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

package net.named_data.jndn.security.pib;

import java.nio.ByteBuffer;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.pib.detail.PibIdentityImpl;
import net.named_data.jndn.util.Common;

/**
 * PibIdentity is at the top level in PIB's Identity-Key-Certificate hierarchy.
 * An identity has a Name, and contains zero or more keys, at most one of which
 * is set as the default key of this identity.  Properties of a key can be
 * accessed after obtaining a PibKey object.
 */
public class PibIdentity {
  /*
   * Get the name of the identity.
   * @return The name of the identity. You must not change the Name object. If
   * you need to change it then make a copy.
   * @throws AssertionError if the backend implementation instance is invalid.
   */
  public final Name
  getName() { return lockImpl().getName(); }

  /**
   * Get the key with name keyName.
   * @param keyName The name of the key.
   * @return The PibKey object.
   * @throws AssertionError if the backend implementation instance is invalid.
   * @throws IllegalArgumentException if keyName does not match the identity name.
   * @throws Pib.Error if the key does not exist.
   */
  public final PibKey
  getKey(Name keyName) throws Pib.Error, PibImpl.Error
  {
    return lockImpl().getKey(keyName);
  }

  /**
   * Get the default key of this Identity.
   * @return The default PibKey.
   * @throws AssertionError if the backend implementation instance is invalid.
   * @throws Pib.Error if the default key has not been set.
   */
  public final PibKey
  getDefaultKey() throws Pib.Error, PibImpl.Error
  {
    return lockImpl().getDefaultKey();
  }

  /**
   * Create a PibIdentity which uses the impl backend implementation. This
   * constructor should only be called by PibIdentityContainer.
   */
  public PibIdentity(PibIdentityImpl impl)
  {
    impl_ = impl;
  }

  /**
   * Add the key. If a key with the same name already exists, overwrite the key.
   * If no default key for the identity has been set, then set the added key as
   * default for the identity. This should only be called by KeyChain.
   * @param key The public key bits. This copies the array.
   * @param keyName The name of the key. This copies the name.
   * @return The PibKey object.
   */
  public final PibKey
  addKey_(ByteBuffer key, Name keyName) throws PibImpl.Error, Pib.Error
  {
    return lockImpl().addKey(key, keyName);
  }

  /**
   * Remove the key with keyName and its related certificates. If the key does
   * not exist, do nothing. This should only be called by KeyChain.
   * @param keyName The name of the key.
   */
  public final void
  removeKey_(Name keyName) throws PibImpl.Error
  {
    lockImpl().removeKey(keyName);
  }

  /**
   * Set the key with name keyName as the default key of the identity. This
   * should only be called by KeyChain.
   * @param keyName The name of the key. This copies the name.
   * @return The PibKey object of the default key.
   * @throws IllegalArgumentException if the name of the key does not match the
   * identity name.
   * @throws Pib.Error if the key does not exist.
   */
  public final PibKey
  setDefaultKey_(Name keyName) throws Pib.Error, PibImpl.Error
  {
    return lockImpl().setDefaultKey(keyName);
  }

  /**
   * Add a key with name keyName and set it as the default key of the identity.
   * This should only be called by KeyChain.
   * @param key The array of encoded key bytes.
   * @param keyName The name of the key, which is copied.
   * @return The PibKey object of the default key.
   * @throws IllegalArgumentException if the name of the key does not match the
   * identity name.
   * @throws Pib.Error if a key with the same name already exists.
   */
  public final PibKey
  setDefaultKey_(ByteBuffer key, Name keyName) throws PibImpl.Error, Pib.Error
  {
    return lockImpl().setDefaultKey(key, keyName);
  }

  /**
   * Get the PibKeyContainer in the PibIdentityImpl. This should only be called
   * by KeyChain.
   */
  public final PibKeyContainer
  getKeys_() { return lockImpl().getKeys_(); }

  /**
   * Check the validity of the impl_ instance.
   * @return The PibIdentityImpl when the instance is valid.
   * @throws AssertionError if the backend implementation instance is invalid.
   */
  private PibIdentityImpl
  lockImpl()
  {
    if (impl_ == null)
      throw new AssertionError("Invalid Identity instance");

    return impl_;
  }

  private final PibIdentityImpl impl_;

  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
