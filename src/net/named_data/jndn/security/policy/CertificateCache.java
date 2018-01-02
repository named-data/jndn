/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From PyNDN certificate_cache.py by Adeola Bannis.
 * Originally from Yingdi Yu <http://irl.cs.ucla.edu/~yingdi/>.
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

package net.named_data.jndn.security.policy;

import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.security.certificate.IdentityCertificate;
import net.named_data.jndn.util.Blob;

/**
 * A CertificateCache is used to save other users' certificate during
 * verification.
 */
public class CertificateCache {
  /**
   * Insert the certificate into the cache. Assumes the timestamp is not yet
   * removed from the name.
   * @param certificate The certificate to copy and insert.
   */
  public void
  insertCertificate(IdentityCertificate certificate)
  {
    Name certName = certificate.getName().getPrefix(-1);
    cache_.put(certName.toUri(), certificate.wireEncode());
  }

  /**
   * Remove a certificate from the cache. This does nothing if it is not present.
   * @param certificateName The name of the certificate to remove. This assumes
   * there is no timestamp in the name.
   */
  public void
  deleteCertificate(Name certificateName)
  {
    cache_.remove(certificateName.toUri());
  }

  /**
   * Fetch a certificate from the cache.
   * @param certificateName The name of the certificate to remove. Assumes there
   * is no timestamp in the name.
   * @return A new copy of the IdentityCertificate, or null if not found.
   */
  public IdentityCertificate
  getCertificate(Name certificateName)
  {
    Blob certData = (Blob)cache_.get(certificateName.toUri());
    if (certData == null)
      return null;

    IdentityCertificate cert = new IdentityCertificate();
    try {
      cert.wireDecode(certData.buf());
    } catch (EncodingException ex) {
      Logger.getLogger(CertificateCache.class.getName()).log(Level.SEVERE, null, ex);
      throw new Error(ex.getMessage());
    }

    return cert;
  }

  /**
   * Clear all certificates from the store.
   */
  public void
  reset()
  {
    cache_.clear();
  }

  // The key is the certificate name URI. The value is the wire encoding Blob.
  // Use HashMap without generics so it works with older Java compilers.
  private final HashMap cache_ = new HashMap();
}
