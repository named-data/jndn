/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/pib/identity-container.cpp
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

import java.util.HashMap;
import java.util.HashSet;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.pib.detail.PibIdentityImpl;
import net.named_data.jndn.util.Common;

/**
 * A PibIdentityContainer is used to search/enumerate the identities in a PIB.
 * (A PibIdentityContainer object can only be created by the Pib class.)
 */
public class PibIdentityContainer {
  /**
   * Get the number of identities in the container.
   * @return The number of identities.
   */
  public final int
  size() { return identityNames_.size(); }

  /**
   * Add an identity with name identityName into the container. Create the
   * identity if it does not exist.
   * @param identityName The name of the identity, which is copied.
   * @return The PibIdentity object.
   */
  public final PibIdentity
  add(Name identityName) throws PibImpl.Error, Pib.Error
  {
    if (!identityNames_.contains(identityName)) {
      Name identityNameCopy = new Name(identityName);
      identityNames_.add(identityNameCopy);
      identities_.put
        (identityNameCopy, new PibIdentityImpl(identityName, pibImpl_, true));
    }

    return get(identityName);
  }

  /**
   * Remove the identity with name identityName from the container, and its
   * related keys and certificates. If the default identity is being removed,
   * no default identity will be selected.  If the identity does not exist, do
   * nothing.
   * @param identityName The name of the identity.
   */
  public final void
  remove(Name identityName) throws PibImpl.Error
  {
    identityNames_.remove(identityName);
    identities_.remove(identityName);
    pibImpl_.removeIdentity(identityName);
  }

  /**
   * Get the identity with name identityName from the container.
   * @param identityName The name of the identity.
   * @return The PibIdentity object.
   * @throws Pib.Error if the identity does not exist.
   */
  public final PibIdentity
  get(Name identityName) throws PibImpl.Error, Pib.Error
  {
    PibIdentityImpl pibIdentityImpl = identities_.get(identityName);

    if (pibIdentityImpl == null) {
      pibIdentityImpl = new PibIdentityImpl(identityName, pibImpl_, false);
      // Copy the Name.
      identities_.put(new Name(identityName), pibIdentityImpl);
    }

    return new PibIdentity(pibIdentityImpl);
  }

  /**
   * Reset the state of the container. This method removes all loaded identities
   * and retrieves identity names from the PIB implementation.
   */
  void
  reset() throws PibImpl.Error
  {
    identities_.clear();
    identityNames_ = pibImpl_.getIdentities();
  }

  /**
   * Check if the container is consistent with the backend storage.
   * @return True if the container is consistent, false otherwise.
   * @note This method is heavy-weight and should be used in a debugging mode
   * only.
   */
  boolean
  isConsistent() throws PibImpl.Error
  {
    return identityNames_.equals(pibImpl_.getIdentities());
  }

  /**
   * Create a PibIdentityContainer using to use the pibImpl backend
   * implementation. This constructor should only be called by the Pib class.
   * @param pibImpl The PIB backend implementation.
   */
  public PibIdentityContainer(PibImpl pibImpl) throws PibImpl.Error
  {
    pibImpl_ = pibImpl;

    if (pibImpl == null)
      throw new AssertionError("The pibImpl is null");

    identityNames_ = pibImpl_.getIdentities();
  }

  /**
   * Get the identities_ map, which should only be used for testing.
   */
  public final HashMap<Name, PibIdentityImpl>
  getIdentities_() { return identities_; }

  private HashSet<Name> identityNames_;
  // Cache of loaded PibIdentityImpl objects.
  private final HashMap<Name, PibIdentityImpl> identities_ =
    new HashMap<Name, PibIdentityImpl>();

  private final PibImpl pibImpl_;

  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
