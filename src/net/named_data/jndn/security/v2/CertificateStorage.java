/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/certificate-storage.hpp
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

package net.named_data.jndn.security.v2;

import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;

/**
 * The CertificateStorage class stores trusted anchors and has a verified
 * certificate cache, and an unverified certificate cache.
 */
public class CertificateStorage {
  /**
   * Find a trusted certificate in the trust anchor container or in the
   * verified cache.
   * @param interestForCertificate The Interest for the certificate.
   * @return The found certificate, or null if not found.
   */
  public final CertificateV2
  findTrustedCertificate(Interest interestForCertificate)
  {
    CertificateV2 certificate = trustAnchors_.find(interestForCertificate);
    if (certificate != null)
      return certificate;

    certificate = verifiedCertificateCache_.find(interestForCertificate);
    return certificate;
  }

  /**
   * Check if the certificate with the given name prefix exists in the verified
   * cache, the unverified cache, or in the set of trust anchors.
   * @param certificatePrefix The certificate name prefix.
   * @return True if the certificate is known.
   */
  public final boolean
  isCertificateKnown(Name certificatePrefix)
  {
    return trustAnchors_.find(certificatePrefix) != null ||
           verifiedCertificateCache_.find(certificatePrefix) != null ||
           unverifiedCertificateCache_.find(certificatePrefix) != null;
  }

  /**
   * Cache the unverified certificate for a period of time (5 minutes).
   * @param certificate The certificate packet, which is copied.
   */
  public final void
  cacheUnverifiedCertificate(CertificateV2 certificate)
    throws CertificateV2.Error
  {
    unverifiedCertificateCache_.insert(certificate);
  }

  /**
   * Get the trust anchor container.
   * @return The trust anchor container.
   */
  public final TrustAnchorContainer
  getTrustAnchors() { return trustAnchors_; }

  /**
   * Get the verified certificate cache.
   * @return The verified certificate cache.
   */
  public final CertificateCacheV2
  getVerifiedCertificateCache() { return verifiedCertificateCache_; }

  /**
   * Get the unverified certificate cache.
   * @return The unverified certificate cache.
   */
  public final CertificateCacheV2
  getUnverifiedCertificateCache() { return unverifiedCertificateCache_; }

  /**
   * Load a static trust anchor. Static trust anchors are permanently associated
   * with the validator and never expire.
   * @param groupId The certificate group id.
   * @param certificate The certificate to load as a trust anchor, which is
   * copied.
   */
  public final void
  loadAnchor(String groupId, CertificateV2 certificate)
    throws TrustAnchorContainer.Error
  {
    trustAnchors_.insert(groupId, certificate);
  }

  /**
   * Load dynamic trust anchors. Dynamic trust anchors are associated with the
   * validator for as long as the underlying trust anchor file (or set of files)
   * exists.
   * @param groupId The certificate group id, which must not be empty.
   * @param path The path to load the trust anchors.
   * @param refreshPeriod  The refresh time in milliseconds for the anchors
   * under path. This must be positive. The relevant trust anchors will only be
   * updated when find is called.
   * @param isDirectory If true, then path is a directory. If false, it is a
   * single file.
   * @throws IllegalArgumentException If refreshPeriod is not positive.
   * @throws TrustAnchorContainer.Error a group with groupId already exists
   */
  public final void
  loadAnchor
    (String groupId, String path, double refreshPeriod, boolean isDirectory)
    throws TrustAnchorContainer.Error
  {
    trustAnchors_.insert(groupId, path, refreshPeriod, isDirectory);
  }

  /**
   * Load dynamic trust anchors. Dynamic trust anchors are associated with the
   * validator for as long as the underlying trust anchor file (or set of files)
   * exists.
   * @param groupId The certificate group id, which must not be empty.
   * @param path The path of the single file to load the trust anchors.
   * @param refreshPeriod  The refresh time in milliseconds for the anchors
   * under path. This must be positive. The relevant trust anchors will only be
   * updated when find is called.
   * @throws IllegalArgumentException If refreshPeriod is not positive.
   * @throws TrustAnchorContainer.Error a group with groupId already exists
   */
  public final void
  loadAnchor(String groupId, String path, double refreshPeriod)
    throws TrustAnchorContainer.Error
  {
    loadAnchor(groupId, path, refreshPeriod, false);
  }

  /**
   * Remove any previously loaded static or dynamic trust anchors.
   */
  public final void
  resetAnchors() { trustAnchors_.clear(); }

  /**
   * Cache the verified certificate a period of time (1 hour).
   * @param certificate The certificate object, which is copied.
   */
  public final void
  cacheVerifiedCertificate(CertificateV2 certificate) throws CertificateV2.Error
  {
    verifiedCertificateCache_.insert(certificate);
  }

  /**
   * Remove any cached verified certificates.
   */
  public final void
  resetVerifiedCertificates() { verifiedCertificateCache_.clear(); }

  /**
   * Set the offset when the cache insert() and refresh() get the current time,
   * which should only be used for testing.
   * @param nowOffsetMilliseconds The offset in milliseconds.
   */
  public final void
  setCacheNowOffsetMilliseconds_(double nowOffsetMilliseconds)
  {
    verifiedCertificateCache_.setNowOffsetMilliseconds_(nowOffsetMilliseconds);
    unverifiedCertificateCache_.setNowOffsetMilliseconds_(nowOffsetMilliseconds);
  }

  protected TrustAnchorContainer trustAnchors_ = new TrustAnchorContainer();
  protected CertificateCacheV2 verifiedCertificateCache_ =
    new CertificateCacheV2(3600 * 1000.0);
  protected CertificateCacheV2 unverifiedCertificateCache_ =
    new CertificateCacheV2(300 * 1000.0);
}
