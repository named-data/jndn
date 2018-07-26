/**
 * Copyright (C) 2017-2018 Regents of the University of California.
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

import java.util.ArrayList;
import java.util.TreeMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encrypt.Schedule;
import net.named_data.jndn.util.Common;

/**
 * A CertificateCacheV2 holds other user's verified certificates in security v2
 * format CertificateV2. A certificate is removed no later than its NotAfter
 * time, or maxLifetime after it has been added to the cache.
 */
public class CertificateCacheV2 {
  /**
   * Create a CertificateCacheV2.
   * @param maxLifetimeMilliseconds The maximum time that certificates can live
   * inside the cache, in milliseconds.
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
    double notAfterTime = certificate.getValidityPeriod().getNotAfter();
    // nowOffsetMilliseconds_ is only used for testing.
    double now = Common.getNowMilliseconds() + nowOffsetMilliseconds_;
    if (notAfterTime < now) {
      logger_.log(Level.FINE, "Not adding {0}: already expired at {1}",
        new Object[] {certificate.getName().toUri(),
                      Schedule.toIsoString(notAfterTime)});
      return;
    }

    double removalTime =
      Math.min(notAfterTime, now + maxLifetimeMilliseconds_);
    if (removalTime < nextRefreshTime_)
      // We need to run refresh() sooner.)
      nextRefreshTime_ = removalTime;

    double removalHours = (removalTime - now) / (3600 * 1000.0);
    logger_.log(Level.FINE, "Adding {0}, will remove in {1} hours",
      new Object[] {certificate.getName().toUri(), removalHours});
    CertificateV2 certificateCopy = new CertificateV2(certificate);
    certificatesByName_.put
      (certificateCopy.getName(), new Entry(certificateCopy, removalTime));
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

    refresh();

    Name entryKey = (Name)certificatesByName_.ceilingKey(certificatePrefix);
    if (entryKey == null)
      return null;

    CertificateV2 certificate =
      ((Entry)certificatesByName_.get(entryKey)).certificate_;
    if (!certificatePrefix.isPrefixOf(certificate.getName()))
      return null;
    return certificate;
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
  find(Interest interest)
  {
    if (interest.getChildSelector() >= 0)
      logger_.log(Level.FINE,
        "Certificate search using a ChildSelector is not supported. Searching as if this selector not specified");

    if (interest.getName().size() > 0 &&
        interest.getName().get(-1).isImplicitSha256Digest())
      logger_.log(Level.FINE,
        "Certificate search using a name with an implicit digest is not yet supported");

    refresh();

    Name firstKey = (Name)certificatesByName_.ceilingKey(interest.getName());
    if (firstKey == null)
      return null;

    for (Object key : certificatesByName_.navigableKeySet().tailSet(firstKey)) {
      CertificateV2 certificate = ((Entry)certificatesByName_.get
        ((Name)key)).certificate_;
      if (!interest.getName().isPrefixOf(certificate.getName()))
        break;

      try {
        if (interest.matchesData(certificate))
          return certificate;
      } catch (EncodingException ex) {
        // We don't expect this. Promote to Error.
        throw new Error("Error in Interest.matchesData: " + ex);
      }
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
    // This may be the certificate to be removed at nextRefreshTime_ by refresh(),
    // but just allow refresh() to run instead of update nextRefreshTime_ now.
  }

  /**
   * Clear all certificates from the cache.
   */
  public final void
  clear()
  {
    certificatesByName_.clear();
    nextRefreshTime_ = Double.MAX_VALUE;
  }

  /**
   * Get the default maximum lifetime (1 hour).
   * @return The lifetime in milliseconds.
   */
  public static double
  getDefaultLifetime() { return 3600.0 * 1000; }

  /**
   * Set the offset when insert() and refresh() get the current time, which
   * should only be used for testing.
   * @param nowOffsetMilliseconds The offset in milliseconds.
   */
  public final void
  setNowOffsetMilliseconds_(double nowOffsetMilliseconds)
  {
    nowOffsetMilliseconds_ = nowOffsetMilliseconds;
  }

  /**
   * CertificateCacheV2.Entry is the value of the certificatesByName_ map.
   */
  private static class Entry {
    /**
     * Create a new CertificateCacheV2.Entry with the given values.
     * @param certificate The certificate.
     * @param removalTime The removal time for this entry  as milliseconds since
     * Jan 1, 1970 UTC.
     */
    public Entry(CertificateV2 certificate, double removalTime)
    {
      certificate_ = certificate;
      removalTime_ = removalTime;
    }

    public final CertificateV2 certificate_;
    public final double removalTime_;
  };

  /**
   * Remove all outdated certificate entries.
   */
  private void
  refresh()
  {
    // nowOffsetMilliseconds_ is only used for testing.
    double now = Common.getNowMilliseconds() + nowOffsetMilliseconds_;
    if (now < nextRefreshTime_)
      return;

    // We recompute nextRefreshTime_.
    double nextRefreshTime = Double.MAX_VALUE;
    // Keep a separate list of entries to erase since we can't erase while iterating.
    ArrayList<Name> namesToErase = new ArrayList<Name>();
    for (Object key : certificatesByName_.keySet()) {
      Name name = (Name)key;
      Entry entry = (Entry)certificatesByName_.get(name);

      if (entry.removalTime_ <= now)
        namesToErase.add(name);
      else
        nextRefreshTime = Math.min(nextRefreshTime, entry.removalTime_);
    }

    nextRefreshTime_ = nextRefreshTime;
    // Now actually erase.
    for (int i = 0; i < namesToErase.size(); ++i)
      certificatesByName_.remove(namesToErase.get(i));
  }

  // Name => CertificateCacheV2.Entry..
  private final TreeMap certificatesByName_ = new TreeMap();
  private double nextRefreshTime_ = Double.MAX_VALUE;
  private final double maxLifetimeMilliseconds_;
  private static final Logger logger_ =
    Logger.getLogger(CertificateCacheV2.class.getName());
  private double nowOffsetMilliseconds_ = 0;

  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}

