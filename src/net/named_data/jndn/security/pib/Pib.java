/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/pib/pib.cpp
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
import net.named_data.jndn.util.Common;

/**
 * In general, a PIB (Public Information Base) stores the public portion of a
 * user's cryptography keys. The format and location of stored information is
 * indicated by the PIB locator. A PIB is designed to work with a TPM (Trusted
 * Platform Module) which stores private keys. There is a one-to-one association
 * between a PIB and a TPM, and therefore the TPM locator is recorded by the PIB
 * to enforce this association and prevent one from operating on mismatched PIB
 * and TPM.
 *
 * Information in the PIB is organized in a hierarchy of
 * Identity-Key-Certificate. At the top level, this Pib class provides access to
 * identities, and allows setting a default identity. Properties of an identity
 * (such as PibKey objects) can be accessed after obtaining a PibIdentity object.
 * (Likewise, CertificateV2 objects can be obtained from a PibKey object.)
 *
 * Note: A Pib instance is created and managed only by the KeyChain, and is
 * returned by the KeyChain getPib() method.
 */
public class Pib {
  /**
   * A Pib.Error extends Exception and represents a semantic error in PIB
   * processing.
   * Note that even though this is called "Error" to be consistent with the
   * other libraries, it extends the Java Exception class, not Error.
   */
  public static class Error extends Exception {
    public Error(String message)
    {
      super(message);
    }
  }

  /**
   * Get the scheme of the PIB locator.
   * @return The scheme string.
   */
  public final String
  getScheme() { return scheme_; }

  /**
   * Get the PIB locator.
   * @return The PIB locator.
   */
  public final String
  getPibLocator() {return scheme_ + ":" + location_; }

  /**
   * Set the corresponding TPM information to tpmLocator.
   * If the tpmLocator is different from the existing one, the PIB will be reset.
   * Otherwise, nothing will be changed.
   */
  public final void
  setTpmLocator(String tpmLocator) throws PibImpl.Error
  {
    if (tpmLocator.equals(pibImpl_.getTpmLocator()))
      return;

    reset_();
    pibImpl_.setTpmLocator(tpmLocator);
  }

  /**
   * Get the TPM Locator.
   * @throws Pib.Error if the TPM locator is empty.
   */
  public final String
  getTpmLocator() throws Pib.Error, PibImpl.Error
  {
    String tpmLocator = pibImpl_.getTpmLocator();
    if (tpmLocator.equals(""))
      throw new Error("TPM info does not exist");

    return tpmLocator;
  }

  /**
   * Get the identity with name identityName.
   * @param identityName The name of the identity.
   * @return The PibIdentity object.
   * @throws Pib.Error if the identity does not exist.
   */
  public final PibIdentity
  getIdentity(Name identityName) throws PibImpl.Error, Pib.Error
  {
    // BOOST_ASSERT(identities_.isConsistent());

    return identities_.get(identityName);
  }

  /**
   * Get the default identity.
   * @return The PibIdentity object.
   * @throws Pib.Error if there is no default identity.
   */
  public final PibIdentity
  getDefaultIdentity() throws PibImpl.Error, Error
  {
    // BOOST_ASSERT(identities_.isConsistent());

    if (defaultIdentity_ == null)
      defaultIdentity_ = identities_.get(pibImpl_.getDefaultIdentity());

    // BOOST_ASSERT(pibImpl_->getDefaultIdentity() == defaultIdentity_->getName());

    return defaultIdentity_;
  }

  /*
   * Create a Pib instance. This constructor should only be called by KeyChain.
   * @param scheme The scheme for the PIB.
   * @param location The location for the PIB.
   * @param pibImpl The PIB backend implementation.
   */
  public Pib(String scheme, String location, PibImpl pibImpl)
    throws PibImpl.Error
  {
    scheme_ = scheme;
    location_ = location;
    identities_ = new PibIdentityContainer(pibImpl);
    pibImpl_ = pibImpl;

    if (pibImpl == null)
      throw new AssertionError("The pibImpl is null");
  }

  /**
   * Reset the content in the PIB, including a reset of the TPM locator.
   * This should only be called by KeyChain.
   */
  public final void
  reset_() throws PibImpl.Error
  {
    pibImpl_.clearIdentities();
    pibImpl_.setTpmLocator("");
    defaultIdentity_ = null;
    identities_.reset();
  }

  /**
   * Add an identity with name identityName. Create the identity if it does not
   * exist.
   * This should only be called by KeyChain.
   * @param identityName The name of the identity, which is copied.
   * @return The PibIdentity object.
   */
  public final PibIdentity
  addIdentity_(Name identityName) throws PibImpl.Error, Pib.Error
  {
    // BOOST_ASSERT(identities_.isConsistent());

    return identities_.add(identityName);
  }

  /**
   * Remove the identity with name identityName, and its related keys and
   * certificates. If the default identity is being removed, no default identity
   * will be selected.  If the identity does not exist, do nothing.
   * This should only be called by KeyChain.
   * @param identityName The name of the identity.
   */
  public final void
  removeIdentity_(Name identityName) throws PibImpl.Error
  {
    // BOOST_ASSERT(identities_.isConsistent());

    if (defaultIdentity_ != null &&
      defaultIdentity_.getName().equals(identityName))
      defaultIdentity_ = null;

    identities_.remove(identityName);
  }

  /**
   * Set the identity with name identityName as the default identity.
   * Create the identity if it does not exist.
   * This should only be called by KeyChain.
   * @param identityName The name of the identity.
   * @return The PibIdentity object of the default identity.
   */
  public final PibIdentity
  setDefaultIdentity_(Name identityName) throws PibImpl.Error, Error
  {
    // BOOST_ASSERT(identities_.isConsistent());

    defaultIdentity_ = identities_.add(identityName);

    pibImpl_.setDefaultIdentity(identityName);
    return defaultIdentity_;
  }

  /**
   * Get the PibIdentityContainer. This should only be called by KeyChain.
   */
  public final PibIdentityContainer
  getIdentities_() { return identities_; }

  private final String scheme_;
  private final String location_;

  private PibIdentity defaultIdentity_ = null;

  private final PibIdentityContainer identities_;

  private final PibImpl pibImpl_;

  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
