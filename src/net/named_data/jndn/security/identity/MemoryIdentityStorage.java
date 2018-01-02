/**
 * Copyright (C) 2014-2018 Regents of the University of California.
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

package net.named_data.jndn.security.identity;

import java.util.ArrayList;
import java.util.HashMap;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.security.KeyType;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.certificate.IdentityCertificate;
import net.named_data.jndn.util.Blob;

/**
 * MemoryIdentityStorage extends IdentityStorage and implements its methods to
 * store identity, public key and certificate objects in memory. The application
 * must get the objects through its own means and add the objects to the
 * MemoryIdentityStorage object. To use permanent file-based storage, see
 * BasicIdentityStorage.
 */
public class MemoryIdentityStorage extends IdentityStorage {
  /**
   * Check if the specified identity already exists.
   * @param identityName The identity name.
   * @return True if the identity exists, otherwise false.
   */
  public boolean
  doesIdentityExist(Name identityName)
  {
    return identityStore_.containsKey(identityName.toUri());
  }

  /**
   * Add a new identity. Do nothing if the identity already exists.
   * @param identityName The identity name to be added.
   */
  public void
  addIdentity(Name identityName) throws SecurityException
  {
    String identityUri = identityName.toUri();
    if (identityStore_.containsKey(identityUri))
      return;

    identityStore_.put(identityUri, new IdentityRecord());
  }

  /**
   * Revoke the identity.
   * @return True if the identity was revoked, false if not.
   */
  public boolean
  revokeIdentity()
  {
    throw new UnsupportedOperationException
      ("MemoryIdentityStorage.revokeIdentity not implemented");
  }

  /**
   * Check if the specified key already exists.
   * @param keyName The name of the key.
   * @return true if the key exists, otherwise false.
   */
  public boolean
  doesKeyExist(Name keyName) throws SecurityException
  {
    return keyStore_.containsKey(keyName.toUri());
  }

  /**
   * Add a public key to the identity storage. Also call addIdentity to ensure
   * that the identityName for the key exists. However, if the key already
   * exists, do nothing.
   * @param keyName The name of the public key to be added.
   * @param keyType Type of the public key to be added.
   * @param publicKeyDer A blob of the public key DER to be added.
   */
  public void
  addKey(Name keyName, KeyType keyType, Blob publicKeyDer) throws SecurityException
  {
    if (keyName.size() == 0)
      return;

    if (doesKeyExist(keyName))
      return;

    Name identityName = keyName.getSubName(0, keyName.size() - 1);

    addIdentity(identityName);

    keyStore_ .put(keyName.toUri(), new KeyRecord(keyType, publicKeyDer));
  }

  /**
   * Get the public key DER blob from the identity storage.
   * @param keyName The name of the requested public key.
   * @return The DER Blob.
   * @throws SecurityException if the key doesn't exist.
   */
  public Blob
  getKey(Name keyName) throws SecurityException
  {
    if (keyName.size() == 0)
      throw new SecurityException("MemoryIdentityStorage.getKey: Empty keyName");

    KeyRecord keyRecord = (KeyRecord)keyStore_.get(keyName.toUri());
    if (keyRecord == null)
      throw new SecurityException
        ("MemoryIdentityStorage.getKey: The key does not exist");

    return keyRecord.getKeyDer();
  }

  /**
   * Activate a key.  If a key is marked as inactive, its private part will not
   * be used in packet signing.
   * @param keyName The name of the key.
   */
  public void
  activateKey(Name keyName)
  {
    throw new UnsupportedOperationException
      ("MemoryIdentityStorage.activateKey not implemented");
  }

  /**
   * Deactivate a key. If a key is marked as inactive, its private part will not
   * be used in packet signing.
   * @param keyName The name of the key.
   */
  public void
  deactivateKey(Name keyName)
  {
    throw new UnsupportedOperationException
      ("MemoryIdentityStorage.deactivateKey not implemented");
  }

  /**
   * Check if the specified certificate already exists.
   * @param certificateName The name of the certificate.
   * @return True if the certificate exists, otherwise false.
   */
  public boolean
  doesCertificateExist(Name certificateName)
  {
    return certificateStore_.containsKey(certificateName.toUri());
  }

  /**
   * Add a certificate to the identity storage. Also call addKey to ensure that
   * the certificate key exists. If the certificate is already installed, don't
   * replace it.
   * @param certificate The certificate to be added.  This makes a copy of the
   * certificate.
   */
  public void
  addCertificate(IdentityCertificate certificate) throws SecurityException
  {
    Name certificateName = certificate.getName();
    Name keyName = certificate.getPublicKeyName();

    addKey(keyName, certificate.getPublicKeyInfo().getKeyType(),
           certificate.getPublicKeyInfo().getKeyDer());

    if (doesCertificateExist(certificateName))
      return;

    // Insert the certificate.
    certificateStore_.put(certificateName.toUri(), certificate.wireEncode());
  }

  /**
   * Get a certificate from the identity storage.
   * @param certificateName The name of the requested certificate.
   * @return The requested certificate.
   * @throws SecurityException if the certificate doesn't exist.
   */
  public IdentityCertificate
  getCertificate(Name certificateName) throws SecurityException
  {
    Blob certificateDer = (Blob)certificateStore_.get(certificateName.toUri());
    if (certificateDer == null)
      throw new SecurityException
        ("MemoryIdentityStorage.getKey: The certificate does not exist");

    IdentityCertificate certificate = new IdentityCertificate();
    try {
      certificate.wireDecode(certificateDer);
    }
    catch (EncodingException ex) {
      throw new SecurityException
        ("MemoryIdentityStorage.getKey: The certificate cannot be decoded");
    }
    return certificate;
  }

  /**
   * Get the TPM locator associated with this storage.
   * @return The TPM locator.
   * @throws SecurityException if the TPM locator doesn't exist.
   */
  public final String
  getTpmLocator() throws SecurityException { return "tpm-memory:"; }

  /*****************************************
   *           Get/Set Default             *
   *****************************************/

  /**
   * Get the default identity.
   * @return The name of default identity.
   * @throws SecurityException if the default identity is not set.
   */
  public Name
  getDefaultIdentity() throws SecurityException
  {
    if (defaultIdentity_.length() == 0)
      throw new SecurityException("MemoryIdentityStorage.getDefaultIdentity: The default identity is not defined");

    return new Name(defaultIdentity_);
  }

  /**
   * Get the default key name for the specified identity.
   * @param identityName The identity name.
   * @return The default key name.
   * @throws SecurityException if the default key name for the identity is not set.
   */
  public Name
  getDefaultKeyNameForIdentity(Name identityName) throws SecurityException
  {
    String identity = identityName.toUri();
    if(identityStore_.containsKey(identity)){
      if(((IdentityRecord)identityStore_.get(identity)).hasDefaultKey()){
        return ((IdentityRecord)identityStore_.get(identity)).getDefaultKey();
      }
      else{
        throw new SecurityException("No default key set.");
      }
    }
    else{
      throw new SecurityException("Identity not found.");
    }
  }

  /**
   * Get the default certificate name for the specified key.
   * @param keyName The key name.
   * @return The default certificate name.
   * @throws SecurityException if the default certificate name for the key name
   * is not set.
   */
  public Name
  getDefaultCertificateNameForKey(Name keyName) throws SecurityException
  {
    String key = keyName.toUri();
    if(keyStore_.containsKey(key)){
      if(((KeyRecord)keyStore_.get(key)).hasDefaultCertificate()){
        return ((KeyRecord)keyStore_.get(key)).getDefaultCertificate();
      }
      else{
        throw new SecurityException("No default certificate set.");
      }
    }
    else{
      throw new SecurityException("Key not found.");
    }
  }

  /**
   * Append all the identity names to the nameList.
   * @param nameList Append result names to nameList.
   * @param isDefault If true, add only the default identity name. If false, add
   * only the non-default identity names.
   */
  public void
  getAllIdentities(ArrayList nameList, boolean isDefault)
  {
    throw new UnsupportedOperationException
      ("MemoryIdentityStorage.getAllIdentities not implemented");
  }

  /**
   * Append all the key names of a particular identity to the nameList.
   * @param identityName The identity name to search for.
   * @param nameList Append result names to nameList.
   * @param isDefault If true, add only the default key name. If false, add only
   * the non-default key names.
   */
  public void
  getAllKeyNamesOfIdentity
    (Name identityName, ArrayList nameList, boolean isDefault)
  {
    throw new UnsupportedOperationException
      ("MemoryIdentityStorage.getAllKeyNamesOfIdentity not implemented");
  }

  /**
   * Append all the certificate names of a particular key name to the nameList.
   * @param keyName The key name to search for.
   * @param nameList Append result names to nameList.
   * @param isDefault If true, add only the default certificate name. If false,
   * add only the non-default certificate names.
   */
  public void
  getAllCertificateNamesOfKey
    (Name keyName, ArrayList nameList, boolean isDefault) throws SecurityException
  {
    throw new UnsupportedOperationException
      ("MemoryIdentityStorage.getAllCertificateNamesOfKey not implemented");
  }

  /**
   * Set the default identity.  If the identityName does not exist, then clear
   * the default identity so that getDefaultIdentity() throws an exception.
   * @param identityName The default identity name.
   */
  public void
  setDefaultIdentity(Name identityName)
  {
    String identityUri = identityName.toUri();
    if (identityStore_.containsKey(identityUri))
      defaultIdentity_ = identityUri;
    else
      // The identity doesn't exist, so clear the default.
      defaultIdentity_ = "";
  }

  /**
   * Set a key as the default key of an identity. The identity name is inferred
   * from keyName.
   * @param keyName The name of the key.
   * @param identityNameCheck The identity name to check that the keyName
   * contains the same identity name. If an empty name, it is ignored.
   */
  public void
  setDefaultKeyNameForIdentity(Name keyName, Name identityNameCheck)
    throws SecurityException
  {
    Name identityName = keyName.getPrefix(-1);

    if (identityNameCheck.size() > 0 && !identityNameCheck.equals(identityName))
      throw new SecurityException
        ("The specified identity name does not match the key name");

    String identity = identityName.toUri();
    if(identityStore_.containsKey(identity)){
      ((IdentityRecord)identityStore_.get(identity)).setDefaultKey
        (new Name(keyName));
    }
  }

  /**
   * Set the default key name for the specified identity.
   * @param keyName The key name.
   * @param certificateName The certificate name.
   */
  public void
  setDefaultCertificateNameForKey(Name keyName, Name certificateName)
  {
    String key = keyName.toUri();
    if(keyStore_.containsKey(key)){
      ((KeyRecord)keyStore_.get(key)).setDefaultCertificate
        (new Name(certificateName));
    }
  }

  /*****************************************
   *            Delete Methods             *
   *****************************************/

  /**
   * Delete a certificate.
   * @param certificateName The certificate name.
   */
  public void
  deleteCertificateInfo(Name certificateName) throws SecurityException
  {
    throw new UnsupportedOperationException
      ("MemoryIdentityStorage.deleteCertificateInfo is not implemented");
  }

  /**
   * Delete a public key and related certificates.
   * @param keyName The key name.
   */
  public void
  deletePublicKeyInfo(Name keyName) throws SecurityException
  {
    throw new UnsupportedOperationException
      ("MemoryIdentityStorage.deletePublicKeyInfo is not implemented");
  }

  /**
   * Delete an identity and related public keys and certificates.
   * @param identity The identity name.
   */
  public void
  deleteIdentityInfo(Name identity) throws SecurityException
  {
    throw new UnsupportedOperationException
      ("MemoryIdentityStorage.deleteIdentityInfo is not implemented");
  }

  private static class IdentityRecord {

    void setDefaultKey(Name key){ defaultKey_ = key; }

    boolean hasDefaultKey(){ return defaultKey_ != null; }

    Name getDefaultKey(){ return defaultKey_; }

    private Name defaultKey_;
  };

  private static class KeyRecord {
    public KeyRecord(KeyType keyType, Blob keyDer)
    {
      keyType_ = keyType;
      keyDer_ = keyDer;
    }

    KeyType getKeyType() { return keyType_; }

    Blob getKeyDer() { return keyDer_; }

    void setDefaultCertificate(Name certificate){ defaultCertificate_ =
            certificate; }

    boolean hasDefaultCertificate(){ return defaultCertificate_ != null; }

    Name getDefaultCertificate(){ return defaultCertificate_; }

    private KeyType keyType_;
    private Blob keyDer_;
    private Name defaultCertificate_;
  };

 // Use HashMap without generics so it works with older Java compilers.
  private final HashMap identityStore_ =
    new HashMap(); /**< The map key is the identityName.toUri(). The value is an IdentityRecord. */
  private String defaultIdentity_ =
    ""; /**< The default identity in identityStore_, or "" if not defined. */
  private final HashMap keyStore_ =
    new HashMap(); /**< The map key is the keyName.toUri(). The value is a KeyRecord. */
  private final HashMap certificateStore_ =
    new HashMap(); /**< The map key is the certificateName.toUri(). The value is the certificate Blob. */
}
