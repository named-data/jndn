/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/trust-anchor-group.cpp
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

import java.io.File;
import java.util.HashSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Name;
import net.named_data.jndn.util.Common;

/**
 * The DynamicTrustAnchorGroup class extends TrustAnchorGroup to implement a
 * dynamic trust anchor group.
 */
public class DynamicTrustAnchorGroup extends TrustAnchorGroup {
  /**
   * Create a dynamic trust anchor group.
   *
   * This loads all the certificates from the path and will refresh certificates
   * every refreshPeriod milliseconds.
   *
   * Note that refresh is not scheduled, but is performed upon each "find"
   * operations.
   *
   * When isDirectory is false and the path doesn't point to a valid certificate
   * (the file doesn't exist or the content is not a valid certificate), then
   * the dynamic anchor group will be empty until the file gets created. If the
   * file disappears or gets corrupted, the anchor group becomes empty.
   *
   * When isDirectory is true and the path doesn't point to a valid folder, the
   * folder is empty, or it doesn't contain valid certificates, then the group
   * will be empty until certificate files are placed in the folder. If the
   * folder is removed, becomes empty, or no longer contains valid certificates,
   * then the anchor group becomes empty.
   *
   * Upon refresh, the existing certificates are not changed.
   *
   * @param certificateContainer A certificate container into which trust
   * anchors from the group will be added.
   * @param id The group id.
   * @param path The file path for trust anchor(s), which could be a directory
   * or a file. If it is a directory, all the certificates in the directory will
   * be loaded.
   * @param refreshPeriod  The refresh time in milliseconds for the anchors
   * under path. This must be positive.
   * @param isDirectory If true, then path is a directory. If false, it is a
   * single file.
   * @throws IllegalArgumentException If refreshPeriod is not positive.
   */
  public DynamicTrustAnchorGroup
    (CertificateContainerInterface certificateContainer, String id, String path,
     double refreshPeriod, boolean isDirectory)
  {
    super(certificateContainer, id);
    isDirectory_ = isDirectory;
    path_ = path;
    refreshPeriod_ = refreshPeriod;
    expireTime_ = 0;
    if (refreshPeriod <= 0)
      throw new IllegalArgumentException
        ("Refresh period for the dynamic group must be positive");

    logger_.log(Level.INFO,
      "Create a dynamic trust anchor group " + id + " for file/dir " +
      path + " with refresh time " + refreshPeriod);
    refresh();
  }

  /**
   * Request a certificate refresh.
   */
  public void
  refresh()
  {
    double now = Common.getNowMilliseconds();
    if (expireTime_ > now)
      return;

    expireTime_ = now + refreshPeriod_;
    logger_.log(Level.INFO, "Reloading the dynamic trust anchor group");

    // Save a copy of anchorNames_ .
    HashSet<Name> oldAnchorNames = new HashSet<Name>(anchorNames_);

    if (!isDirectory_)
      loadCertificate(path_, oldAnchorNames);
    else {
      File[] allFiles = new File(path_).listFiles();
      if (allFiles != null) {
        for (int i = 0; i < allFiles.length; ++i)
          loadCertificate(allFiles[i].getAbsolutePath(), oldAnchorNames);
      }
    }

    // Remove old certificates.
    for (Name name : oldAnchorNames) {
      anchorNames_.remove(name);
      certificates_.remove(name);
    }
  }

  private void
  loadCertificate(String file, HashSet<Name> oldAnchorNames)
  {
    CertificateV2 certificate = readCertificate(file);
    if (certificate != null) {
      if (!anchorNames_.contains(certificate.getName())) {
        anchorNames_.add(certificate.getName());
        certificates_.add(certificate);
      }
      else
        oldAnchorNames.remove(certificate.getName());
    }
  }

  private final boolean isDirectory_;
  private final String path_;
  private final double refreshPeriod_;
  private double expireTime_;

  private static final Logger logger_ =
    Logger.getLogger(DynamicTrustAnchorGroup.class.getName());
  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
