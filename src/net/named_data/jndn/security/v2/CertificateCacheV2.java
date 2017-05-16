/**
 * Copyright (C) 2017 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/certificate-cache.cpp
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

import java.util.Map;
import java.util.TreeMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;

/**
 * A CertificateCacheV2 holds other user's verified certificates in security v2
 * format CertificateV2. A certificate is removed no later than its NotAfter
 * time, or maxLifetime after it has been added to the cache.
 */
public class CertificateCacheV2 {
  /**
   * Create a CertificateCacheV2.
   * @param maxLifetimeMilliseconds The maximum time that certificates can live
   * inside the cache, in milliseconds. If omitted, use getDefaultLifetime().
   */
  public CertificateCacheV2(double maxLifetimeMilliseconds)
  {
    maxLifetimeMilliseconds_ = maxLifetimeMilliseconds;
  }

  /**
   * Create a CertificateCacheV2. Set the maximum time that certificates can
   * live inside the cache to getDefaultLifetime().
   */
  public CertificateCacheV2()
  {
    maxLifetimeMilliseconds_ = getDefaultLifetime();
  }

  /**
   * Insert the certificate into the cache. The inserted certificate will be
   * removed no later than its NotAfter time, or maxLifetimeMilliseconds given
   * to the constructor.
   * @param certificate The certificate object, which is copied.
   */
  public final void
  insert(CertificateV2 certificate) throws CertificateV2.Error
  {
    // TODO: Implement certificatesByTime_ to support refresh(). There can be
    // multiple certificate for the same removalTime, and adding the same
    // certificate again should update the removalTime.

    CertificateV2 certificateCopy = new CertificateV2(certificate);
    certificatesByName_.put(certificateCopy.getName(), certificateCopy);
  }

  /**
   * Find the certificate by the given key name.
   * @param certificatePrefix The certificate prefix for searching for the
   * certificate.
   * @return The found certificate, or null if not found. You must not modify
   * the returned object. If you need to modify it, then make a copy.
   */
  public final CertificateV2
  find(Name certificatePrefix)
  {
    if (certificatePrefix.size() > 0 &&
        certificatePrefix.get(-1).isImplicitSha256Digest())
      logger_.log(Level.FINE,
        "Certificate search using a name with an implicit digest is not yet supported");

    // TODO: refresh();

    Map.Entry<Name, CertificateV2> entry =
      certificatesByName_.ceilingEntry(certificatePrefix);
    if (entry == null ||
        !certificatePrefix.isPrefixOf(entry.getValue().getName()))
      return null;
    return entry.getValue();
  }

  /**
   * Find the certificate by the given interest.
   * @param interest The input interest object.
   * @return The found certificate which matches the interest, or null if not
   * found. You must not modify the returned object. If you need to modify it,
   * then make a copy.
   * @note ChildSelector is not supported.
   */
  public final CertificateV2
  find(Interest interest) throws EncodingException
  {
    if (interest.getChildSelector() >= 0)
      logger_.log(Level.FINE,
        "Certificate search using a ChildSelector is not supported. Searching as if this selector not specified");

    if (interest.getName().size() > 0 &&
        interest.getName().get(-1).isImplicitSha256Digest())
      logger_.log(Level.FINE,
        "Certificate search using a name with an implicit digest is not yet supported");

    // TODO: const_cast<CertificateCacheV2*>(this)->refresh();

    Name firstKey = certificatesByName_.ceilingKey(interest.getName());
    if (firstKey == null)
      return null;

    for (Name key : certificatesByName_.navigableKeySet().tailSet(firstKey)) {
      CertificateV2 certificate = certificatesByName_.get(key);
      if (!interest.getName().isPrefixOf(certificate.getName()))
        break;

      if (interest.matchesData(certificate))
        return certificate;
    }

    return null;
  }

  /**
   * Remove the certificate whose name equals the given name. If no such
   * certificate is in the cache, do nothing.
   * @param certificateName The name of the certificate.
   */
  public final void
  deleteCertificate(Name certificateName)
  {
    certificatesByName_.remove(certificateName);
    // TODO: Delete from certificatesByTime_.
  }

  /**
   * Clear all certificates from the cache.
   */
  public final void
  reset()
  {
    certificatesByName_.clear();
    // TODO: certificatesByTime_.clear();
  }

  /**
   * Get the default maximum lifetime (1 hour).
   * @return The lifetime in milliseconds.
   */
  public static double
  getDefaultLifetime() { return 3600.0 * 1000; }

  private final TreeMap<Name, CertificateV2> certificatesByName_ =
    new TreeMap<Name, CertificateV2>();
  double maxLifetimeMilliseconds_;
  private static final Logger logger_ = Logger.getLogger(CertificateCacheV2.class.getName());
}
