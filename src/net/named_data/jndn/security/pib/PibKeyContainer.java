/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/pib/key-container.cpp
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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.pib.detail.PibKeyImpl;
import net.named_data.jndn.util.Common;

/**
 * A PibKeyContainer is used to search/enumerate the keys of an identity.
 * (A PibKeyContainer object can only be created by PibIdentity.)
 */
public class PibKeyContainer {
  /**
   * Get the number of keys in the container.
   * @return The number of keys.
   */
  public final int
  size() { return keyNames_.size(); }

  /**
   * Add a key with name keyName into the container. If a key with the same name
   * already exists, this replaces it.
   * @param key The buffer of encoded key bytes.
   * @param keyName The name of the key, which is copied.
   * @return The PibKey object.
   * @throws IllegalArgumentException if the name of the key does not match the
   * identity name.
   */
  public final PibKey
  add(ByteBuffer key, Name keyName) throws PibImpl.Error, Pib.Error
  {
    if (!identityName_.equals(PibKey.extractIdentityFromKeyName(keyName)))
      throw new IllegalArgumentException
        ("The key name `" + keyName.toUri() +
         "` does not match the identity name `" + identityName_.toUri() + "`");

    // Copy the Name.
    keyNames_.add(new Name(keyName));
    keys_.put(new Name(keyName), new PibKeyImpl(keyName, key, pibImpl_));

    return get(keyName);
  }

  /**
   * Remove the key with name keyName from the container, and its related
   * certificates. If the key does not exist, do nothing.
   * @param keyName The name of the key.
   * @throws IllegalArgumentException if keyName does not match the identity name.
   */
  public final void
  remove(Name keyName) throws PibImpl.Error
  {
    if (!identityName_.equals(PibKey.extractIdentityFromKeyName(keyName)))
      throw new IllegalArgumentException
        ("Key name `" + keyName.toUri() + "` does not match identity `" +
         identityName_.toUri() + "`");

    keyNames_.remove(keyName);
    keys_.remove(keyName);
    pibImpl_.removeKey(keyName);
  }

  /**
   * Get the key with name keyName from the container.
   * @param keyName The name of the key.
   * @return The PibKey object.
   * @throws IllegalArgumentException if keyName does not match the identity name.
   * @throws Pib.Error if the key does not exist.
   */
  public final PibKey
  get(Name keyName) throws Pib.Error, PibImpl.Error
  {
    if (!identityName_.equals(PibKey.extractIdentityFromKeyName(keyName)))
      throw new IllegalArgumentException
        ("Key name `" + keyName.toUri() + "` does not match identity `" +
         identityName_.toUri() + "`");

    PibKeyImpl pibKeyImpl = keys_.get(keyName);

    if (pibKeyImpl == null) {
      pibKeyImpl =new PibKeyImpl(keyName, pibImpl_);
      // Copy the Name.
      keys_.put(new Name(keyName), pibKeyImpl);
    }

    return new PibKey(pibKeyImpl);
  }

  /**
   * Get the names of all the keys in the container.
   * @return A new list of Name.
   */
  public final ArrayList<Name>
  getKeyNames()
  {
    ArrayList<Name> result = new ArrayList<Name>();

    for (Name name : keys_.keySet())
      // Copy the Name.
      result.add(new Name(name));

    return result;
  }

  /**
   * Check if the container is consistent with the backend storage.
   * @return True if the container is consistent, false otherwise.
   * @note This method is heavy-weight and should be used in a debugging mode
   * only.
   */
  public final boolean
  isConsistent() throws PibImpl.Error
  {
    return keyNames_.equals(pibImpl_.getKeysOfIdentity(identityName_));
  }

  /**
   * Create a PibKeyContainer for an identity with identityName. This
   * constructor should only be called by PibIdentityImpl.
   * @param identityName The name of the identity, which is copied.
   * @param pibImpl The PIB backend implementation.
   */
  public PibKeyContainer(Name identityName, PibImpl pibImpl)
    throws PibImpl.Error
  {
    // Copy the Name.
    identityName_ = new Name(identityName);
    pibImpl_ = pibImpl;

    if (pibImpl == null)
      throw new AssertionError("The pibImpl is null");

    keyNames_ = pibImpl_.getKeysOfIdentity(identityName);
  }

  /**
   * Get the keys_ map, which should only be used for testing.
   */
  public final HashMap<Name, PibKeyImpl>
  getKeys_() { return keys_; }

  private final Name identityName_;
  private final HashSet<Name> keyNames_;
  // Cache of loaded PibKeyImpl objects.
  private final HashMap<Name, PibKeyImpl> keys_ = new HashMap<Name, PibKeyImpl>();

  private final PibImpl pibImpl_;

  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
