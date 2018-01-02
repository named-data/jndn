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

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashSet;
import net.named_data.jndn.Name;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

/**
 * TrustAnchorGroup represents a group of trust anchors which implement the
 * CertificateContainerInterface.
 */
public class TrustAnchorGroup {
  /**
   * Create a TrustAnchorGroup to use an existing container.
   * @param certificateContainer The existing certificate container.
   * @param id The group ID.
   */
  public TrustAnchorGroup
    (CertificateContainerInterface certificateContainer, String id)
  {
    certificates_ = certificateContainer;
    id_ = id;
  }

  /**
   * Get the group id given to the constructor.
   * @return The group id.
   */
  public final String
  getId() { return id_; }

  /**
   * Get the number of certificates in the group.
   * @return The number of certificates.
   */
  public final int
  size() { return anchorNames_.size(); }

  /**
   * Request a certificate refresh. The base method does nothing.
   */
  public void
  refresh()
  {
  }

  /**
   * Read a base-64-encoded certificate from a file.
   * @param filePath The certificate file path.
   * @return The decoded certificate, or null if there is an error.
   */
  public static CertificateV2
  readCertificate(String filePath)
  {
    StringBuilder encodedData = new StringBuilder();

    try {
      BufferedReader certificateFile = new BufferedReader(new FileReader(filePath));
      // Use "try/finally instead of "try-with-resources" or "using"
      // which are not supported before Java 7.
      try {
        String line;
        while ((line = certificateFile.readLine()) != null)
          encodedData.append(line);
      } finally {
        certificateFile.close();
      }
    } catch (FileNotFoundException ex) {
      return null;
    } catch (IOException ex) {
      return null;
    }

    byte[] decodedData = Common.base64Decode(encodedData.toString());
    CertificateV2 result = new CertificateV2();
    try {
      result.wireDecode(new Blob(decodedData, false));
      return result;
    } catch (Throwable ex) {
      return null;
    }
  }

  protected final CertificateContainerInterface certificates_;
  protected final HashSet<Name> anchorNames_ = new HashSet<Name>();
  private final String id_;
}
