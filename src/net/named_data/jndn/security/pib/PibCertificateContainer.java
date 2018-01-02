/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/pib/certificate-container.cpp
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
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.util.Common;

/**
 * A PibCertificateContainer is used to search/enumerate the certificates of a
 * key. (A PibCertificateContainer object can only be created by PibKey.)
 */
public class PibCertificateContainer {
  /**
   * Get the number of certificates in the container.
   * @return The number of certificates.
   */
  public final int
  size() { return certificateNames_.size(); }

  /**
   * Add certificate into the container. If the certificate already exists,
   * this replaces it.
   * @param certificate The certificate to add. This copies the object.
   * @throws IllegalArgumentException if the name of the certificate does not
   * match the key name.
   */
  public final void
  add(CertificateV2 certificate) throws CertificateV2.Error, PibImpl.Error
  {
    if (!keyName_.equals(certificate.getKeyName()))
      throw new IllegalArgumentException
        ("The certificate name `" + certificate.getKeyName().toUri() +
         "` does not match the key name");

    Name certificateName = new Name(certificate.getName());
    certificateNames_.add(certificateName);
    // Copy the certificate.
    certificates_.put(certificateName,  new CertificateV2(certificate));
    pibImpl_.addCertificate(certificate);
  }

  /**
   * Remove the certificate with name certificateName from the container. If the
   * certificate does not exist, do nothing.
   * @param certificateName The name of the certificate.
   * @throws IllegalArgumentException if certificateName does not match the key
   * name.
   */
  public final void
  remove(Name certificateName) throws PibImpl.Error
  {
    if (!CertificateV2.isValidName(certificateName) ||
        !CertificateV2.extractKeyNameFromCertName(certificateName).equals(keyName_))
      throw new IllegalArgumentException
        ("Certificate name `" + certificateName.toUri() +
          "` is invalid or does not match key name");

    certificateNames_.remove(certificateName);
    certificates_.remove(certificateName);
    pibImpl_.removeCertificate(certificateName);
  }

  /**
   * Get the certificate with certificateName from the container.
   * @param certificateName The name of the certificate.
   * @return A copy of the certificate.
   * @throws IllegalArgumentException if certificateName does not match the key
   * name
   * @throws Pib.Error if the certificate does not exist.
   */
  public final CertificateV2
  get(Name certificateName) throws Pib.Error, PibImpl.Error
  {
    CertificateV2 cachedCertificate = certificates_.get(certificateName);

    if (cachedCertificate != null) {
      try {
        // Make a copy.
        // TODO: Copy is expensive. Can we just tell the caller not to modify it?
        return new CertificateV2(cachedCertificate);
      } catch (CertificateV2.Error ex) {
        // We don't expect this for the copy constructor.
        throw new Pib.Error("Error copying certificate: " + ex);
      }
    }

    // Get from the PIB and cache.
    if (!CertificateV2.isValidName(certificateName) ||
        !CertificateV2.extractKeyNameFromCertName(certificateName).equals(keyName_))
      throw new IllegalArgumentException
        ("Certificate name `" + certificateName.toUri() +
         "` is invalid or does not match key name");

    CertificateV2 certificate = pibImpl_.getCertificate(certificateName);
    // Copy the certificate Name.
    certificates_.put(new Name(certificateName), certificate);
    try {
      // Make a copy.
      // TODO: Copy is expensive. Can we just tell the caller not to modify it?
      return new CertificateV2(certificate);
    } catch (CertificateV2.Error ex) {
      // We don't expect this for the copy constructor.
      throw new Pib.Error("Error copying certificate: " + ex);
    }
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
    return certificateNames_.equals(pibImpl_.getCertificatesOfKey(keyName_));
  }

  /**
   * Create a PibCertificateContainer for a key with keyName. This constructor
   * should only be called by PibKeyImpl.
   * @param keyName The name of the key, which is copied.
   * @param pibImpl The PIB backend implementation.
   */
  public PibCertificateContainer(Name keyName, PibImpl pibImpl)
    throws PibImpl.Error
  {
    keyName_ = new Name(keyName);
    pibImpl_ = pibImpl;

    if (pibImpl == null)
      throw new AssertionError("The pibImpl is null");

    certificateNames_ = pibImpl_.getCertificatesOfKey(keyName);
  }

  /**
   * Get the certificates_ map, which should only be used for testing.
   */
  public final HashMap<Name, CertificateV2>
  getCertificates_() { return certificates_; }

  private final Name keyName_;
  private HashSet<Name> certificateNames_;
  // Cache of loaded certificates.
  private final HashMap<Name, CertificateV2> certificates_ =
    new HashMap<Name, CertificateV2>();

  private final PibImpl pibImpl_;

  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
