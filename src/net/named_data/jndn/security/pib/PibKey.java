/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/pib/key.cpp
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
import net.named_data.jndn.security.KeyType;
import net.named_data.jndn.security.pib.detail.PibKeyImpl;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.util.Blob;

/**
 * The PibKey class provides access to a key at the second level in the PIB's
 * Identity-Key-Certificate hierarchy. A PibKey object has a Name
 * (identity + "KEY" + keyId), and contains one or more CertificateV2
 * objects, one of which is set as the default certificate of this key.
 * A certificate can be directly accessed by getting a CertificateV2 object.
 */
public class PibKey {
  /*
   * Get the key name.
   * @return The key name. You must not modify the Name object. If you need to
   * modify it, make a copy.
   * @throws AssertionError if the backend implementation instance is invalid.
   */
  public final Name
  getName() { return lockImpl().getName(); }

  /**
   * Get the name of the identity this key belongs to.
   * @return The name of the identity. You must not modify the Key object. If
   * you need to modify it, make a copy.
   * @throws AssertionError if the backend implementation instance is invalid.
   */
  public final Name
  getIdentityName() { return lockImpl().getIdentityName(); }

  /**
   * Get the key type.
   * @return The key type.
   * @throws AssertionError if the backend implementation instance is invalid.
   */
  public final KeyType
  getKeyType() { return lockImpl().getKeyType(); }

  /**
   * Get the public key encoding.
   * @return The public key encoding.
   * @throws AssertionError if the backend implementation instance is invalid.
   */
  public final Blob
  getPublicKey() { return lockImpl().getPublicKey(); }

  /**
   * Get the certificate with name certificateName.
   * @param certificateName The name of the certificate.
   * @return A copy of the CertificateV2 object.
   * @throws AssertionError if certificateName does not match the key name, or
   *   if the backend implementation instance is invalid.
   * @throws Pib.Error if the certificate does not exist.
   */
  public final CertificateV2
  getCertificate(Name certificateName) throws Pib.Error, PibImpl.Error
  {
    return lockImpl().getCertificate(certificateName);
  }

  /**
   * Get the default certificate for this Key.
   * @return A copy of the default certificate.
   * @throws AssertionError if the backend implementation instance is invalid.
   * @throws Pib.Error If the default certificate does not exist.
   */
  public final CertificateV2
  getDefaultCertificate() throws Pib.Error, PibImpl.Error
  {
    return lockImpl().getDefaultCertificate();
  }

  /**
   * Construct a key name based on the appropriate naming conventions.
   * @param identityName The name of the identity.
   * @param keyId The key ID name component.
   * @return The constructed name as a new Name.
   */
  public static Name
  constructKeyName(Name identityName, Name.Component keyId)
  {
    Name keyName = new Name(identityName);
    keyName.append(CertificateV2.KEY_COMPONENT).append(keyId);

    return keyName;
  }

  /**
   * Check if keyName follows the naming conventions for a key name.
   * @param keyName The name of the key.
   * @return True if keyName follows the naming conventions, otherwise false.
   */
  public static boolean
  isValidKeyName(Name keyName)
  {
    return (keyName.size() > CertificateV2.MIN_KEY_NAME_LENGTH &&
            keyName.get(-CertificateV2.MIN_KEY_NAME_LENGTH).equals
              (CertificateV2.KEY_COMPONENT));
  }

  /**
   * Extract the identity namespace from keyName.
   * @param keyName The name of the key.
   * @return The identity name as a new Name.
   */
  public static Name
  extractIdentityFromKeyName(Name keyName)
  {
    if (!isValidKeyName(keyName))
      throw new IllegalArgumentException
        ("Key name `" + keyName.toUri() +
         "` does not follow the naming conventions");

    // Trim everything after and including "KEY".
    return keyName.getPrefix(-CertificateV2.MIN_KEY_NAME_LENGTH);
  }

  /**
   * Create a PibKey which uses the impl backend implementation. This
   * constructor should only be called by PibKeyContainer.
   */
  public PibKey(PibKeyImpl impl)
  {
    impl_ = impl;
  }

  /**
   * Add the certificate. If a certificate with the same name (without implicit
   * digest) already exists, then overwrite the certificate. If no default
   * certificate for the key has been set, then set the added certificate as
   * default for the key.
   * This should only be called by KeyChain.
   * @param certificate The certificate to add. This copies the object.
   * @throws IllegalArgumentException if the name of the certificate does not
   * match the key name.
   */
  public final void
  addCertificate_(CertificateV2 certificate)
    throws CertificateV2.Error, PibImpl.Error
  {
    lockImpl().addCertificate(certificate);
  }

  /**
   * Remove the certificate with name certificateName. If the certificate does
   * not exist, do nothing.
   * This should only be called by KeyChain.
   * @param certificateName The name of the certificate.
   * @throws IllegalArgumentException if certificateName does not match the key
   * name.
   */
  public final void
  removeCertificate_(Name certificateName) throws PibImpl.Error
  {
    lockImpl().removeCertificate(certificateName);
  }

  /**
   * Set the existing certificate with name certificateName as the default
   * certificate.
   * This should only be called by KeyChain.
   * @param certificateName The name of the certificate.
   * @return The default certificate.
   * @throws IllegalArgumentException if certificateName does not match the key
   * name
   * @throws Pib.Error if the certificate does not exist.
   */
  public final CertificateV2
  setDefaultCertificate_(Name certificateName) throws Pib.Error, PibImpl.Error
  {
    return lockImpl().setDefaultCertificate(certificateName);
  }

  /**
   * Add the certificate and set it as the default certificate of the key.
   * If a certificate with the same name (without implicit digest) already
   * exists, then overwrite the certificate.
   * This should only be called by KeyChain.
   * @param certificate The certificate to add. This copies the object.
   * @throws IllegalArgumentException if the name of the certificate does not
   * match the key name.
   * @return The default certificate.
   */
  public final CertificateV2
  setDefaultCertificate_(CertificateV2 certificate)
    throws CertificateV2.Error, PibImpl.Error, Pib.Error
  {
    return lockImpl().setDefaultCertificate(certificate);
  }

  /**
   * Get the PibCertificateContainer in the PibKeyImpl. This should only be
   * called by KeyChain.
   * @return The PibCertificateContainer.
   */
  public final PibCertificateContainer
  getCertificates_()
  {
    return lockImpl().getCertificates_();
  }

  /**
   * Check the validity of the impl_ instance.
   * @return The PibKeyImpl when the instance is valid.
   * @throws AssertionError if the backend implementation instance is invalid.
   */
  private PibKeyImpl
  lockImpl()
  {
    if (impl_ == null)
      throw new AssertionError("Invalid key instance");

    return impl_;
  }

  private final PibKeyImpl impl_;
}
