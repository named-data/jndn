/**
 * Copyright (C) 2017 Regents of the University of California.
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

import net.named_data.jndn.Name;
import net.named_data.jndn.security.pib.detail.PibIdentityImpl;

/**
 * PibIdentity is at the top level in PIB's Identity-Key-Certificate hierarchy.
 * An identity has a Name, and contains zero or more keys, at most one of which
 * is set as the default key of this identity.  Properties of a key can be
 * accessed after obtaining a Key object.
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
}
