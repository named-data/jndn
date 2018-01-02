/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/certificate-request.hpp
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

/**
 * A CertificateRequest represents a request for a certificate, associated with
 * the number of retries left. The interest_ and nRetriesLeft_ fields are public
 * so that you can modify them.
 */
public class CertificateRequest {
  /**
   * Create a CertificateRequest with a default Interest and 0 retries left.
   */
  public CertificateRequest()
  {
    interest_ = new Interest();
    nRetriesLeft_ = 0;
  }

  /**
   * Create  a CertificateRequest for the Interest and 3 retries left.
   * @param interest The Interest which is copied.
   */
  public CertificateRequest(Interest interest)
  {
    // Copy the Interest.
    interest_ = new Interest(interest);
    nRetriesLeft_ = 3;
  }

  /** The Interest for the requested Data packet or Certificate.
   */
  public Interest interest_;
  /** The number of remaining retries after time out or NACK.
   */
  public int nRetriesLeft_;
}
