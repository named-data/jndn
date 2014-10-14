/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From code in NDN-CPP by Yingdi Yu <yingdi@cs.ucla.edu>
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

package net.named_data.jndn.security.certificate;

import java.util.List;
import net.named_data.jndn.Data;
import net.named_data.jndn.Name;

public abstract class Certificate extends Data {
  /**
   * The default constructor.
   */
  public Certificate()
  {
    throw new UnsupportedOperationException
      ("Certificate constructor is not implemented");
  }

  /**
   * Create a Certificate from the content in the data packet.
   * @param data The data packet with the content to decode.
   */
  public Certificate(Data data)
  {
    throw new UnsupportedOperationException
      ("Certificate constructor is not implemented");
  }

  /**
   * encode certificate info into content
   */
  public final void
  encode()
  {
    throw new UnsupportedOperationException
      ("Certificate.encode is not implemented");
  }

  /**
   * Add a subject description.
   * @param description The description to be added.
   */
  public final void
  addSubjectDescription(CertificateSubjectDescription description)
  {
    throw new UnsupportedOperationException
      ("Certificate.addSubjectDescription is not implemented");
  }

  // List of CertificateSubjectDescription.
  public final List
  getSubjectDescriptionList()
  {
    throw new UnsupportedOperationException
      ("Certificate.getSubjectDescriptionList is not implemented");
  }

  /**
   * Add a certificate extension.
   * @param extension the extension to be added
   */
  public final void
  addExtension(CertificateExtension extension)
  {
    throw new UnsupportedOperationException
      ("Certificate.addExtension is not implemented");
  }

  // List of CertificateExtension.
  public final List
  getExtensionList()
  {
    throw new UnsupportedOperationException
      ("Certificate.getExtensionList is not implemented");
  }

  public final void
  setNotBefore(double notBefore)
  {
    throw new UnsupportedOperationException
      ("Certificate.setNotBefore is not implemented");
  }

  public final double
  getNotBefore()
  {
    throw new UnsupportedOperationException
      ("Certificate.getNotBefore is not implemented");
  }

  public final void
  setNotAfter(double notAfter)
  {
    throw new UnsupportedOperationException
      ("Certificate.setNotAfter is not implemented");
  }

  public final double
  getNotAfter()
  {
    throw new UnsupportedOperationException
      ("Certificate.getNotAfter is not implemented");
  }

  public final void
  setPublicKeyInfo(PublicKey key)
  {
    throw new UnsupportedOperationException
      ("Certificate.setPublicKeyInfo is not implemented");
  }

  public final PublicKey
  getPublicKeyInfo()
  {
    throw new UnsupportedOperationException
      ("Certificate.getPublicKeyInfo is not implemented");
  }

  public abstract Name
  getPublicKeyName();

  /**
   * Check if the certificate is valid.
   * @return True if the current time is earlier than notBefore.
   */
  public final boolean
  isTooEarly()
  {
    throw new UnsupportedOperationException
      ("Certificate.isTooEarly is not implemented");
  }

  /**
   * Check if the certificate is valid.
   * @return True if the current time is later than notAfter.
   */
  public final boolean
  isTooLate()
  {
    throw new UnsupportedOperationException
      ("Certificate.isTooLate is not implemented");
  }

  public final void
  printCertificate()
  {
    throw new UnsupportedOperationException
      ("Certificate.printCertificate is not implemented");
  }
}
