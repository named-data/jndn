/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/pib/detail/identity-impl.cpp
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

package net.named_data.jndn.security.pib.detail;

import java.nio.ByteBuffer;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.pib.Pib;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.security.pib.PibKey;
import net.named_data.jndn.security.pib.PibKeyContainer;
import net.named_data.jndn.util.Common;

/**
 * PibIdentityImpl provides the backend implementation for PibIdentity. A
 * PibIdentity has only one backend instance, but may have multiple frontend
 * handles. Each frontend handle is associated with the only one backend
 * PibIdentityImpl.
 */
public class PibIdentityImpl {
  /**
   * Create a PibIdentityImpl with identityName.
   * @param identityName The name of the identity, which is copied.
   * @param pibImpl The Pib backend implementation.
   * @param needInit If true and the identity does not exist in the pibImpl back
   * end, then create it (and If no default identity has been set, identityName
   * becomes the default). If false, then throw Pib.Error if the identity does
   * not exist in the pibImpl back end.
   * @throws Pib.Error if the identity does not exist in the pibImpl back end
   * and needInit is false.
   */
  public PibIdentityImpl(Name identityName, PibImpl pibImpl, boolean needInit)
    throws PibImpl.Error, Pib.Error
  {
    // Copy the Name.
    identityName_ = new Name(identityName);
    keys_ = new PibKeyContainer(identityName, pibImpl);
    pibImpl_ = pibImpl;

    if (pibImpl == null)
      throw new AssertionError("The pibImpl is null");

    if (needInit)
      pibImpl_.addIdentity(identityName_);
    else {
      if (!pibImpl_.hasIdentity(identityName_))
        throw new Pib.Error
          ("Identity " + identityName_.toUri() + " does not exist");
    }
  }

  /*
   * Get the name of the identity.
   * @return The name of the identity. You must not change the Name object. If
   * you need to change it then make a copy.
   */
  public final Name
  getName() { return identityName_; }

  /**
   * Add the key. If a key with the same name already exists, overwrite the key.
   * If no default key for the identity has been set, then set the added key as
   * default for the identity.
   * @param key The public key bits. This copies the buffer.
   * @param keyName The name of the key. This copies the name.
   * @return The PibKey object.
   */
  public final PibKey
  addKey(ByteBuffer key, Name keyName) throws PibImpl.Error, Pib.Error
  {
    // BOOST_ASSERT(keys_.isConsistent());

    return keys_.add(key, keyName);
  }

  /**
   * Remove the key with keyName and its related certificates. If the key does
   * not exist, do nothing.
   * @param keyName The name of the key.
   */
  public final void
  removeKey(Name keyName) throws PibImpl.Error
  {
    // BOOST_ASSERT(keys_.isConsistent());

    if (defaultKey_ != null && defaultKey_.getName().equals(keyName))
      defaultKey_ = null;

    keys_.remove(keyName);
  }

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
    // BOOST_ASSERT(keys_.isConsistent());

    return keys_.get(keyName);
  }

  /**
   * Set the key with name keyName as the default key of the identity.
   * @param keyName The name of the key. This copies the name.
   * @return The PibKey object of the default key.
   * @throws IllegalArgumentException if the name of the key does not match the
   * identity name.
   * @throws Pib.Error if the key does not exist.
   */
  public final PibKey
  setDefaultKey(Name keyName) throws Pib.Error, PibImpl.Error
  {
    // BOOST_ASSERT(keys_.isConsistent());

    defaultKey_ = keys_.get(keyName);
    pibImpl_.setDefaultKeyOfIdentity(identityName_, keyName);
    return defaultKey_;
  }

  /**
   * Add a key with name keyName and set it as the default key of the identity.
   * @param key The buffer of encoded key bytes.
   * @param keyName The name of the key, which is copied.
   * @return The PibKey object of the default key.
   * @throws IllegalArgumentException if the name of the key does not match the
   * identity name.
   * @throws Pib.Error if a key with the same name already exists.
   */
  public final PibKey
  setDefaultKey(ByteBuffer key, Name keyName) throws PibImpl.Error, Pib.Error
  {
    addKey(key, keyName);
    return setDefaultKey(keyName);
  }

  /**
   * Get the default key of this Identity.
   * @return The default PibKey.
   * @throws Pib.Error if the default key has not been set.
   */
  public final PibKey
  getDefaultKey() throws Pib.Error, PibImpl.Error
  {
    // BOOST_ASSERT(keys_.isConsistent());

    if (defaultKey_ == null)
      defaultKey_ = keys_.get
        (pibImpl_.getDefaultKeyOfIdentity(identityName_));

    // BOOST_ASSERT(pibImpl_->getDefaultKeyOfIdentity(identityName_) == defaultKey_.getName());

    return defaultKey_;
  }

  /**
   * Get the PibKeyContainer. This should only be called by PibIdentity.
   */
  public PibKeyContainer
  getKeys_() { return keys_; }

  private final Name identityName_;
  private PibKey defaultKey_ = null;

  private final PibKeyContainer keys_;

  private final PibImpl pibImpl_;

  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
