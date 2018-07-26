/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/pib/pib-memory.cpp
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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.util.Blob;

/**
 * PibMemory extends PibImpl and is used by the Pib class as an in-memory
 * implementation of a PIB. All the contents in the PIB are stored in memory and
 * have the same lifetime as the PibMemory instance.
 */
public class PibMemory extends PibImpl {
  public static String
  getScheme() { return "pib-memory"; }

  // TpmLocator management.

  /**
   * Set the corresponding TPM information to tpmLocator. This method does not
   * reset the contents of the PIB.
   * @param tpmLocator The TPM locator string.
   */
  public void
  setTpmLocator(String tpmLocator) throws PibImpl.Error
  {
    tpmLocator_ = tpmLocator;
  }

  /**
   * Get the TPM Locator.
   * @return The TPM locator string.
   */
  public String
  getTpmLocator() throws PibImpl.Error
  {
    return tpmLocator_;
  }

  // Identity management.

  /**
   * Check for the existence of an identity.
   * @param identityName The name of the identity.
   * @return True if the identity exists, otherwise false.
   */
  public boolean
  hasIdentity(Name identityName) throws PibImpl.Error
  {
    return identityNames_.contains(identityName);
  }

  /**
   * Add the identity. If the identity already exists, do nothing. If no default
   * identity has been set, set the added identity as the default.
   * @param identityName The name of the identity to add. This copies the name.
   */
  public void
  addIdentity(Name identityName) throws PibImpl.Error
  {
    Name identityNameCopy = new Name(identityName);
    identityNames_.add(identityNameCopy);

    if (defaultIdentityName_ == null)
      defaultIdentityName_ = identityNameCopy;
  }

  /**
   * Remove the identity and its related keys and certificates. If the default
   * identity is being removed, no default identity will be selected.  If the
   * identity does not exist, do nothing.
   * @param identityName The name of the identity to remove.
   */
  public void
  removeIdentity(Name identityName) throws PibImpl.Error
  {
    identityNames_.remove(identityName);
    if (defaultIdentityName_ != null && identityName.equals(defaultIdentityName_))
      defaultIdentityName_ = null;

    for (Name keyName : getKeysOfIdentity(identityName))
      removeKey(keyName);
  }

  /**
   * Erase all certificates, keys, and identities.
   */
  public void
  clearIdentities() throws PibImpl.Error
  {
    defaultIdentityName_ = null;
    identityNames_.clear();
    defaultKeyNames_.clear();
    keys_.clear();
    defaultCertificateNames_.clear();
    certificates_.clear();
  }

  /**
   * Get the names of all the identities.
   * @return The set of identity names. The Name objects are fresh copies.
   */
  public HashSet<Name>
  getIdentities() throws PibImpl.Error
  {
    // Copy the Name objects.
    HashSet<Name> result = new HashSet<Name>();
    for (Name name : identityNames_)
      result.add(new Name(name));

    return result;
  }

  /**
   * Set the identity with the identityName as the default identity. If the
   * identity with identityName does not exist, then it will be created.
   * @param identityName The name for the default identity. This copies the name.
   */
  public void
  setDefaultIdentity(Name identityName) throws PibImpl.Error
  {
    addIdentity(identityName);
    // Copy the name.
    defaultIdentityName_ = new Name(identityName);
  }

  /**
   * Get the default identity.
   * @return The name of the default identity, as a fresh copy.
   * @throws Pib.Error for no default identity.
   */
  public Name
  getDefaultIdentity() throws Pib.Error, PibImpl.Error
  {
    if (defaultIdentityName_ != null)
      // Copy the name.
      return new Name(defaultIdentityName_);

    throw new Pib.Error("No default identity");
  }

  // Key management.

  /**
   * Check for the existence of a key with keyName.
   * @param keyName The name of the key.
   * @return True if the key exists, otherwise false. Return false if the
   * identity does not exist.
   */
  public boolean
  hasKey(Name keyName) throws PibImpl.Error
  {
    return keys_.containsKey(keyName);
  }

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
   */
  public void
  addKey(Name identityName, Name keyName, ByteBuffer key) throws PibImpl.Error
  {
    addIdentity(identityName);

    Name keyNameCopy = new Name(keyName);
    keys_.put(keyNameCopy, new Blob(key, true));

    if (!defaultKeyNames_.containsKey(identityName))
      // Copy the identityName.
      defaultKeyNames_.put(new Name(identityName), keyNameCopy);
  }

  /**
   * Remove the key with keyName and its related certificates. If the key does
   * not exist, do nothing.
   * @param keyName The name of the key.
   */
  public void
  removeKey(Name keyName) throws PibImpl.Error
  {
    Name identityName = PibKey.extractIdentityFromKeyName(keyName);

    keys_.remove(keyName);
    defaultKeyNames_.remove(identityName);

    for (Name certificateName : getCertificatesOfKey(keyName))
      removeCertificate(certificateName);
  }

  /**
   * Get the key bits of a key with name keyName.
   * @param keyName The name of the key.
   * @return The key bits.
   * @throws Pib.Error if the key does not exist.
   */
  public Blob
  getKeyBits(Name keyName) throws Pib.Error, PibImpl.Error
  {
    if (!hasKey(keyName))
      throw new Pib.Error("Key `" + keyName.toUri() + "` not found");

    Blob key = keys_.get(keyName);
    if (key == null)
      // We don't expect this since we just checked hasKey.
      throw new Pib.Error("keyName not found");
    return key;
  }

  /**
   * Get all the key names of the identity with the name identityName. The
   * returned key names can be used to create a KeyContainer. With a key name
   * and a backend implementation, one can create a Key front end instance.
   * @param identityName The name of the identity.
   * @return The set of key names. The Name objects are fresh copies. If the
   * identity does not exist, return an empty set.
   */
  public HashSet<Name>
  getKeysOfIdentity(Name identityName) throws PibImpl.Error
  {
    HashSet<Name> ids = new HashSet<Name>();
    for (Name keyName : keys_.keySet()) {
      if (identityName.equals(PibKey.extractIdentityFromKeyName(keyName)))
        // Copy the name.
        ids.add(new Name(keyName));
    }

    return ids;
  }

  /**
   * Set the key with keyName as the default key for the identity with name
   * identityName.
   * @param identityName The name of the identity. This copies the name.
   * @param keyName The name of the key. This copies the name.
   * @throws Pib.Error if the key does not exist.
   */
  public void
  setDefaultKeyOfIdentity(Name identityName, Name keyName)
    throws Pib.Error, PibImpl.Error
  {
    if (!hasKey(keyName))
      throw new Pib.Error("Key `" + keyName.toUri() + "` not found");

    // Copy the Names.
    defaultKeyNames_.put(new Name(identityName), new Name(keyName));
  }

  /**
   * Get the name of the default key for the identity with name identityName.
   * @param identityName The name of the identity.
   * @return The name of the default key, as a fresh copy.
   * @throws Pib.Error if there is no default key or if the identity does not
   * exist.
   */
  public Name
  getDefaultKeyOfIdentity(Name identityName) throws Pib.Error, PibImpl.Error
  {
    Name defaultKey = defaultKeyNames_.get(identityName);
    if (defaultKey == null)
      throw new Pib.Error
        ("No default key for identity `" + identityName.toUri() + "`");

    // Copy the name.
    return new Name(defaultKey);
  }

  // Certificate management.

  /**
   * Check for the existence of a certificate with name certificateName.
   * @param certificateName The name of the certificate.
   * @return True if the certificate exists, otherwise false.
   */
  public boolean
  hasCertificate(Name certificateName) throws PibImpl.Error
  {
    return certificates_.containsKey(certificateName);
  }

  /**
   * Add the certificate. If a certificate with the same name (without implicit
   * digest) already exists, then overwrite the certificate. If the key or
   * identity does not exist, they will be created. If no default certificate
   * for the key has been set, then set the added certificate as the default for
   * the key. If no default key was set for the identity, it will be set as the
   * default key for the identity. If no default identity was selected, the
   * certificate's identity becomes the default.
   * @param certificate The certificate to add. This copies the object.
   */
  public void
  addCertificate(CertificateV2 certificate) throws PibImpl.Error
  {
    Name certificateNameCopy = new Name(certificate.getName());
    // getKeyName already makes a new Name.
    Name keyNameCopy = certificate.getKeyName();
    Name identity = certificate.getIdentity();

    addKey(identity, keyNameCopy, certificate.getContent().buf());

    try {
      certificates_.put(certificateNameCopy, new CertificateV2(certificate));
    } catch (CertificateV2.Error ex) {
      // We don't expect an error in the copy constructor.
      throw new PibImpl.Error(ex.getMessage());
    }
    if (!defaultCertificateNames_.containsKey(keyNameCopy))
      defaultCertificateNames_.put(keyNameCopy, certificateNameCopy);
  }

  /**
   * Remove the certificate with name certificateName. If the certificate does
   * not exist, do nothing.
   * @param certificateName The name of the certificate.
   */
  public void
  removeCertificate(Name certificateName) throws Error
  {
    certificates_.remove(certificateName);
    Name keyName = CertificateV2.extractKeyNameFromCertName(certificateName);
    Name defaultCertificateName = defaultCertificateNames_.get(keyName);
    if (defaultCertificateName != null &&
        defaultCertificateName.equals(certificateName))
      defaultCertificateNames_.remove(keyName);
  }

  /**
   * Get the certificate with name certificateName.
   * @param certificateName The name of the certificate.
   * @return A copy of the certificate.
   * @throws Pib.Error if the certificate does not exist.
   */
  public CertificateV2
  getCertificate(Name certificateName) throws Pib.Error, Error
  {
    if (!hasCertificate(certificateName))
      throw new Pib.Error
        ("Certificate `" + certificateName.toUri() +  "` does not exist");

    try {
      return new CertificateV2(certificates_.get(certificateName));
    } catch (CertificateV2.Error ex) {
      // We don't expect an error in the copy constructor.
      throw new PibImpl.Error(ex.getMessage());
    }
  }

  /**
   * Get a list of certificate names of the key with id keyName. The returned
   * certificate names can be used to create a PibCertificateContainer. With a
   * certificate name and a backend implementation, one can obtain the
   * certificate.
   * @param keyName The name of the key.
   * @return The set of certificate names. The Name objects are fresh copies. If
   * the key does not exist, return an empty set.
   */
  public HashSet<Name>
  getCertificatesOfKey(Name keyName) throws Error
  {
    HashSet<Name> certificateNames = new HashSet<Name>();
    for (Name certificateName : certificates_.keySet()) {
      if (CertificateV2.extractKeyNameFromCertName
          (certificates_.get(certificateName).getName()).equals(keyName))
        // Copy the Name.
        certificateNames.add(new Name(certificateName));
    }

    return certificateNames;
  }

  /**
   * Set the cert with name certificateName as the default for the key with
   * keyName.
   * @param keyName The name of the key.
   * @param certificateName The name of the certificate. This copies the name.
   * @throws Pib.Error if the certificate with name certificateName does not
   * exist.
   */
  public void
  setDefaultCertificateOfKey(Name keyName, Name certificateName)
    throws Pib.Error, Error
  {
    if (!hasCertificate(certificateName))
      throw new Pib.Error
        ("Certificate `" + certificateName.toUri() +  "` does not exist");

    // Copy the Names.
    defaultCertificateNames_.put(new Name(keyName), new Name(certificateName));
  }

  /**
   * Get the default certificate for the key with eyName.
   * @param keyName The name of the key.
   * @return A copy of the default certificate.
   * @throws Pib.Error if the default certificate does not exist.
   */
  public CertificateV2
  getDefaultCertificateOfKey(Name keyName) throws Pib.Error, Error
  {
    Name certificateName = defaultCertificateNames_.get(keyName);
    if (certificateName == null)
      throw new Pib.Error
        ("No default certificate for key `" + keyName.toUri() + "`");

    CertificateV2 certificate = certificates_.get(certificateName);
    if (certificate == null)
      // We don't expect this since we just checked defaultCertificateNames_.
      throw new Pib.Error("certificate not found");
    try {
      return new CertificateV2(certificate);
    } catch (CertificateV2.Error ex) {
      // We don't expect an error in the copy constructor.
      throw new PibImpl.Error(ex.getMessage());
    }
  }

  private String tpmLocator_ = "";

  private Name defaultIdentityName_ = null;

  private final HashSet<Name> identityNames_ = new HashSet<Name>();

  // identity => default key Name.
  private final HashMap<Name, Name> defaultKeyNames_ = new HashMap<Name, Name>();

  // keyName => keyBits.
  private final HashMap<Name, Blob> keys_ = new HashMap<Name, Blob>();

  // keyName => default certificate Name.
  private final HashMap<Name, Name> defaultCertificateNames_ =
    new HashMap<Name, Name>();

  // certificate Name => certificate.
  private final HashMap<Name, CertificateV2> certificates_ =
    new HashMap<Name, CertificateV2>();
}
