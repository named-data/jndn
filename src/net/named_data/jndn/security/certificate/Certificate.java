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

import java.util.ArrayList;
import java.util.List;
import net.named_data.jndn.Data;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.der.DerDecodingException;
import net.named_data.jndn.encoding.der.DerNode;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

public abstract class Certificate extends Data {
  /**
   * The default constructor.
   */
  public Certificate()
  {
  }

  /**
   * Create a Certificate from the content in the data packet.
   * @param data The data packet with the content to decode.
   */
  public Certificate(Data data) throws DerDecodingException
  {
    super(data);
    decode();
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
    subjectDescriptionList_.add(description);
  }

  // List of CertificateSubjectDescription.
  public final List
  getSubjectDescriptionList()
  {
    return subjectDescriptionList_;
  }

  /**
   * Add a certificate extension.
   * @param extension the extension to be added
   */
  public final void
  addExtension(CertificateExtension extension)
  {
    extensionList_.add(extension);
  }

  // List of CertificateExtension.
  public final List
  getExtensionList()
  {
    return extensionList_;
  }

  public final void
  setNotBefore(double notBefore)
  {
    notBefore_ = notBefore;
  }

  public final double
  getNotBefore()
  {
    return notBefore_;
  }

  public final void
  setNotAfter(double notAfter)
  {
    notAfter_ = notAfter;
  }

  public final double
  getNotAfter()
  {
    return notAfter_;
  }

  public final void
  setPublicKeyInfo(PublicKey key)
  {
    key_ = key;
  }

  public final PublicKey
  getPublicKeyInfo()
  {
    return key_;
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
    double now = Common.getNowMilliseconds();
    return now < notBefore_;
  }

  /**
   * Check if the certificate is valid.
   * @return True if the current time is later than notAfter.
   */
  public final boolean
  isTooLate()
  {
    double now = Common.getNowMilliseconds();
    return now > notAfter_;
  }

  /**
   * Populates the fields by decoding DER data from the Content.
   */
  private void
  decode() throws DerDecodingException
  {
    throw new UnsupportedOperationException
      ("Certificate.decode is not implemented");
  }

  public final void
  printCertificate()
  {
    throw new UnsupportedOperationException
      ("Certificate.printCertificate is not implemented");
  }

  // Use a non-template ArrayList so it works with older Java compilers.
  private final ArrayList subjectDescriptionList_ = new ArrayList(); // of CertificateSubjectDescription
  private final ArrayList extensionList_ = new ArrayList();          // of CertificateExtension
  private double notBefore_ = Double.MAX_VALUE; // MillisecondsSince1970
  private double notAfter_ = -Double.MAX_VALUE;  // MillisecondsSince1970
  private PublicKey key_ = new PublicKey();
}
