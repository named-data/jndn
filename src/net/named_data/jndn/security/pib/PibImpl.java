/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/pib/pib-impl.cpp
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
import java.util.HashSet;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.util.Blob;

/**
 * PibImpl is an abstract base class for the PIB implementation used by the Pib
 * class. This class defines the interface that an actual PIB implementation
 * should provide, for example PibMemory.
 */
public abstract class PibImpl {
  /**
   * A PibImpl.Error extends Exception and represents a non-semantic error in
   * PIB implementation processing. A subclass of PibImpl may throw a subclass
   * of this class when there's a non-semantic error, such as a storage problem.
   * Note that even though this is called "Error" to be consistent with the
   * other libraries, it extends the Java Exception class, not Error.
   */
  public static class Error extends Exception {
    public Error(String message)
    {
      super(message);
    }
  }

  // TpmLocator management.

  /**
   * Set the corresponding TPM information to tpmLocator. This method does not
   * reset the contents of the PIB.
   * @param tpmLocator The TPM locator string.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public abstract void
  setTpmLocator(String tpmLocator) throws PibImpl.Error;

  /**
   * Get the TPM Locator.
   * @return The TPM locator string.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public abstract String
  getTpmLocator() throws PibImpl.Error;

  // Identity management.

  /**
   * Check for the existence of an identity.
   * @param identityName The name of the identity.
   * @return True if the identity exists, otherwise false.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public abstract boolean
  hasIdentity(Name identityName) throws PibImpl.Error;

  /**
   * Add the identity. If the identity already exists, do nothing. If no default
   * identity has been set, set the added identity as the default.
   * @param identityName The name of the identity to add. This copies the name.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public abstract void
  addIdentity(Name identityName) throws PibImpl.Error;

  /**
   * Remove the identity and its related keys and certificates. If the default
   * identity is being removed, no default identity will be selected.  If the
   * identity does not exist, do nothing.
   * @param identityName The name of the identity to remove.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public abstract void
  removeIdentity(Name identityName) throws PibImpl.Error;

  /**
   * Erase all certificates, keys, and identities.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public abstract void
  clearIdentities() throws PibImpl.Error;

  /**
   * Get the names of all the identities.
   * @return The set of identity names. The Name objects are fresh copies.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public abstract HashSet<Name>
  getIdentities() throws PibImpl.Error;

  /**
   * Set the identity with the identityName as the default identity. If the
   * identity with identityName does not exist, then it will be created.
   * @param identityName The name for the default identity. This copies the name.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public abstract void
  setDefaultIdentity(Name identityName) throws PibImpl.Error;

  /**
   * Get the default identity.
   * @return The name of the default identity, as a fresh copy.
   * @throws Pib.Error for no default identity.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public abstract Name
  getDefaultIdentity() throws Pib.Error, PibImpl.Error;

  // Key management.

  /**
   * Check for the existence of a key with keyName.
   * @param keyName The name of the key.
   * @return True if the key exists, otherwise false. Return false if the
   * identity does not exist.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public abstract boolean
  hasKey(Name keyName) throws PibImpl.Error;

  /**
   * Add the key. If a key with the same name already exists, overwrite the key.
   * If the identity does not exist, it will be created. If no default key for
   * the identity has been set, then set the added key as the default for the
   * identity.  If no default identity has been set, identity becomes the
   * default.
   * @param identityName The name of the identity that the key belongs to. This
   * copies the name.
   * @param keyName The name of the key. This copies the name.
   * @param key The public key bits. This copies the array.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public abstract void
  addKey(Name identityName, Name keyName, ByteBuffer key) throws PibImpl.Error;

  /**
   * Remove the key with keyName and its related certificates. If the key does
   * not exist, do nothing.
   * @param keyName The name of the key.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public abstract void
  removeKey(Name keyName) throws PibImpl.Error;

  /**
   * Get the key bits of a key with name keyName.
   * @param keyName The name of the key.
   * @return The key bits.
   * @throws Pib.Error if the key does not exist.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public abstract Blob
  getKeyBits(Name keyName) throws Pib.Error, PibImpl.Error;

  /**
   * Get all the key names of the identity with the name identityName. The
   * returned key names can be used to create a KeyContainer. With a key name
   * and a backend implementation, one can create a Key front end instance.
   * @param identityName The name of the identity.
   * @return The set of key names. The Name objects are fresh copies. If the
   * identity does not exist, return an empty set.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public abstract HashSet<Name>
  getKeysOfIdentity(Name identityName) throws PibImpl.Error;

  /**
   * Set the key with keyName as the default key for the identity with name
   * identityName.
   * @param identityName The name of the identity. This copies the name.
   * @param keyName The name of the key. This copies the name.
   * @throws Pib.Error if the key does not exist.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public abstract void
  setDefaultKeyOfIdentity(Name identityName, Name keyName)
    throws Pib.Error, PibImpl.Error;

  /**
   * Get the name of the default key for the identity with name identityName.
   * @param identityName The name of the identity.
   * @return The name of the default key, as a fresh copy.
   * @throws Pib.Error if there is no default key or if the identity does not
   * exist.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public abstract Name
  getDefaultKeyOfIdentity(Name identityName) throws Pib.Error, PibImpl.Error;

  // Certificate management.

  /**
   * Check for the existence of a certificate with name certificateName.
   * @param certificateName The name of the certificate.
   * @return True if the certificate exists, otherwise false.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public abstract boolean
  hasCertificate(Name certificateName) throws PibImpl.Error;

  /**
   * Add the certificate. If a certificate with the same name (without implicit
   * digest) already exists, then overwrite the certificate. If the key or
   * identity does not exist, they will be created. If no default certificate
   * for the key has been set, then set the added certificate as the default for
   * the key. If no default key was set for the identity, it will be set as
   * default key for the identity. If no default identity was selected, the
   * certificate's identity becomes the default.
   * @param certificate The certificate to add. This copies the object.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public abstract void
  addCertificate(CertificateV2 certificate) throws PibImpl.Error;

  /**
   * Remove the certificate with name certificateName. If the certificate does
   * not exist, do nothing.
   * @param certificateName The name of the certificate.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public abstract void
  removeCertificate(Name certificateName) throws PibImpl.Error;

  /**
   * Get the certificate with name certificateName.
   * @param certificateName The name of the certificate.
   * @return A copy of the certificate.
   * @throws Pib.Error if the certificate does not exist.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public abstract CertificateV2
  getCertificate(Name certificateName) throws Pib.Error, PibImpl.Error;

  /**
   * Get a list of certificate names of the key with id keyName. The returned
   * certificate names can be used to create a PibCertificateContainer. With a
   * certificate name and a backend implementation, one can obtain the
   * certificate.
   * @param keyName The name of the key.
   * @return The set of certificate names. The Name objects are fresh copies. If
   * the key does not exist, return an empty set.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public abstract HashSet<Name>
  getCertificatesOfKey(Name keyName) throws PibImpl.Error;

  /**
   * Set the cert with name certificateName as the default for the key with
   * keyName.
   * @param keyName The name of the key.
   * @param certificateName The name of the certificate. This copies the name.
   * @throws Pib.Error if the certificate with name certificateName does not
   * exist.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public abstract void
  setDefaultCertificateOfKey(Name keyName, Name certificateName)
    throws Pib.Error, PibImpl.Error;

  /**
   * Get the default certificate for the key with eyName.
   * @param keyName The name of the key.
   * @return A copy of the default certificate.
   * @throws Pib.Error if the default certificate does not exist.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public abstract CertificateV2
  getDefaultCertificateOfKey(Name keyName) throws Pib.Error, PibImpl.Error;
}
