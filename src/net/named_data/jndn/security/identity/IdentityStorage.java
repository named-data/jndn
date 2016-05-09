/**
 * Copyright (C) 2014-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From code in ndn-cxx by Yingdi Yu <yingdi@cs.ucla.edu>
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

package net.named_data.jndn.security.identity;

import java.util.ArrayList;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.KeyType;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.certificate.IdentityCertificate;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

/**
 * IdentityStorage is a base class for the storage of identity, public keys and
 * certificates. Private keys are stored in PrivateKeyStorage.
 * This is an abstract base class.  A subclass must implement the methods.
 */
public abstract class IdentityStorage {
  /**
   * Check if the specified identity already exists.
   * @param identityName The identity name.
   * @return True if the identity exists, otherwise false.
   */
  public abstract boolean
  doesIdentityExist(Name identityName) throws SecurityException;

  /**
   * Add a new identity. Do nothing if the identity already exists.
   * @param identityName The identity name to be added.
   */
  public abstract void
  addIdentity(Name identityName) throws SecurityException;

  /**
   * Revoke the identity.
   * @return True if the identity was revoked, false if not.
   */
  public abstract boolean
  revokeIdentity() throws SecurityException;

  /**
   * Generate a name for a new key belonging to the identity.
   * @param identityName The identity name.
   * @param useKsk If true, generate a KSK name, otherwise a DSK name.
   * @return The generated key name.
   */
  public final Name
  getNewKeyName(Name identityName, boolean useKsk) throws SecurityException
  {
    long timestamp = (long)Math.floor(Common.getNowMilliseconds());
    while (timestamp <= lastTimestamp_)
      // Make the timestamp unique.
      timestamp += 1;
    lastTimestamp_ = timestamp;

    // Get the number of seconds as a string.
    String timeString = "" + timestamp;

    String keyIdStr;
    if (useKsk)
      keyIdStr = ("ksk-" + timeString);
    else
      keyIdStr = ("dsk-" + timeString);

    Name keyName = new Name(identityName).append(keyIdStr);

    if (doesKeyExist(keyName))
      throw new SecurityException("Key name already exists");

    return keyName;
  }

  /**
   * Check if the specified key already exists.
   * @param keyName The name of the key.
   * @return true if the key exists, otherwise false.
   */
  public abstract boolean
  doesKeyExist(Name keyName) throws SecurityException;

  /**
   * Add a public key to the identity storage. Also call addIdentity to ensure
   * that the identityName for the key exists. However, if the key already
   * exists, do nothing.
   * @param keyName The name of the public key to be added.
   * @param keyType Type of the public key to be added.
   * @param publicKeyDer A blob of the public key DER to be added.
   */
  public abstract void
  addKey(Name keyName, KeyType keyType, Blob publicKeyDer) throws SecurityException;

  /**
   * Get the public key DER blob from the identity storage.
   * @param keyName The name of the requested public key.
   * @return The DER Blob.
   * @throws SecurityException if the key doesn't exist.
   */
  public abstract Blob
  getKey(Name keyName) throws SecurityException;

  /**
   * Activate a key.  If a key is marked as inactive, its private part will not
   * be used in packet signing.
   * @param keyName The name of the key.
   */
  public abstract void
  activateKey(Name keyName) throws SecurityException;

  /**
   * Deactivate a key. If a key is marked as inactive, its private part will not
   * be used in packet signing.
   * @param keyName The name of the key.
   */
  public abstract void
  deactivateKey(Name keyName) throws SecurityException;

  /**
   * Check if the specified certificate already exists.
   * @param certificateName The name of the certificate.
   * @return True if the certificate exists, otherwise false.
   */
  public abstract boolean
  doesCertificateExist(Name certificateName) throws SecurityException;

  /**
   * Add a certificate to the identity storage. Also call addKey to ensure that
   * the certificate key exists. If the certificate is already installed, don't
   * replace it.
   * @param certificate The certificate to be added.  This makes a copy of the
   * certificate.
   */
  public abstract void
  addCertificate(IdentityCertificate certificate) throws SecurityException;

  /**
   * Get a certificate from the identity storage.
   * @param certificateName The name of the requested certificate.
   * @return The requested certificate.
   * @throws SecurityException if the certificate doesn't exist.
   */
  public abstract IdentityCertificate
  getCertificate(Name certificateName) throws SecurityException;

  /**
   * Get the TPM locator associated with this storage.
   * @return The TPM locator.
   * @throws SecurityException if the TPM locator doesn't exist.
   */
  public abstract String
  getTpmLocator() throws SecurityException;

  /*****************************************
   *           Get/Set Default             *
   *****************************************/

  /**
   * Get the default identity.
   * @return The name of default identity.
   * @throws SecurityException if the default identity is not set.
   */
  public abstract Name
  getDefaultIdentity() throws SecurityException;

  /**
   * Get the default key name for the specified identity.
   * @param identityName The identity name.
   * @return The default key name.
   * @throws SecurityException if the default key name for the identity is not set.
   */
  public abstract Name
  getDefaultKeyNameForIdentity(Name identityName) throws SecurityException;

  /**
   * Get the default certificate name for the specified identity.
   * @param identityName The identity name.
   * @return The default certificate name.
   * @throws SecurityException if the default key name for the identity is not
   * set or the default certificate name for the key name is not set.
   */
  public final Name
  getDefaultCertificateNameForIdentity(Name identityName) throws SecurityException
  {
    Name keyName = getDefaultKeyNameForIdentity(identityName);
    return getDefaultCertificateNameForKey(keyName);
  }

  /**
   * Get the default certificate name for the specified key.
   * @param keyName The key name.
   * @return The default certificate name.
   * @throws SecurityException if the default certificate name for the key name
   * is not set.
   */
  public abstract Name
  getDefaultCertificateNameForKey(Name keyName) throws SecurityException;

  /**
   * Append all the identity names to the nameList.
   * @param nameList Append result names to nameList.
   * @param isDefault If true, add only the default identity name. If false, add
   * only the non-default identity names.
   */
  public abstract void
  getAllIdentities(ArrayList nameList, boolean isDefault)
    throws SecurityException;

  /**
   * Append all the key names of a particular identity to the nameList.
   * @param identityName The identity name to search for.
   * @param nameList Append result names to nameList.
   * @param isDefault If true, add only the default key name. If false, add only
   * the non-default key names.
   */
  public abstract void
  getAllKeyNamesOfIdentity
    (Name identityName, ArrayList nameList, boolean isDefault) throws SecurityException;

  /**
   * Append all the certificate names of a particular key name to the nameList.
   * @param keyName The key name to search for.
   * @param nameList Append result names to nameList.
   * @param isDefault If true, add only the default certificate name. If false,
   * add only the non-default certificate names.
   */
  public abstract void
  getAllCertificateNamesOfKey
    (Name keyName, ArrayList nameList, boolean isDefault) throws SecurityException;
  /**
   * Set the default identity.  If the identityName does not exist, then clear
   * the default identity so that getDefaultIdentity() throws an exception.
   * @param identityName The default identity name.
   */
  public abstract void
  setDefaultIdentity(Name identityName) throws SecurityException;

  /**
   * Set a key as the default key of an identity. The identity name is inferred
   * from keyName.
   * @param keyName The name of the key.
   * @param identityNameCheck The identity name to check that the keyName
   * contains the same identity name. If an empty name, it is ignored.
   */
  public abstract void
  setDefaultKeyNameForIdentity(Name keyName, Name identityNameCheck) throws SecurityException;

  /**
   * Set the default key name for the specified identity.
   * @param keyName The key name.
   */
  public final void
  setDefaultKeyNameForIdentity(Name keyName) throws SecurityException
  {
    setDefaultKeyNameForIdentity(keyName, new Name());
  }

  /**
   * Set the default key name for the specified identity.
   * @param keyName The key name.
   * @param certificateName The certificate name.
   */
  public abstract void
  setDefaultCertificateNameForKey(Name keyName, Name certificateName) throws SecurityException;

  /**
   * Get the certificate of the default identity.
   * @return The requested certificate. If not found, return null.
   */
  public final IdentityCertificate
  getDefaultCertificate() throws SecurityException
  {
    Name certName;
    try {
      certName = getDefaultCertificateNameForIdentity(getDefaultIdentity());
    } catch (SecurityException ex) {
      // The default is not defined.
      return null;
    }

    return getCertificate(certName);
  }

  /*****************************************
   *            Delete Methods             *
   *****************************************/

  /**
   * Delete a certificate.
   * @param certificateName The certificate name.
   */
  public abstract void
  deleteCertificateInfo(Name certificateName) throws SecurityException;

  /**
   * Delete a public key and related certificates.
   * @param keyName The key name.
   */
  public abstract void
  deletePublicKeyInfo(Name keyName) throws SecurityException;

  /**
   * Delete an identity and related public keys and certificates.
   * @param identity The identity name.
   */
  public abstract void
  deleteIdentityInfo(Name identity) throws SecurityException;

  private static long lastTimestamp_ =
    (long)Math.floor(Common.getNowMilliseconds());
}
