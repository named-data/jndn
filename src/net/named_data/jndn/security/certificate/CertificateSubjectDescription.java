/**
 * Copyright (C) 2014-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From code in ndn-cxx by Yingdi Yu <yingdi@cs.ucla.edu>
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

import net.named_data.jndn.encoding.OID;
import net.named_data.jndn.encoding.der.DerEncodingException;
import net.named_data.jndn.encoding.der.DerNode;
import net.named_data.jndn.encoding.der.DerNode.DerOid;
import net.named_data.jndn.encoding.der.DerNode.DerPrintableString;
import net.named_data.jndn.encoding.der.DerNode.DerSequence;
import net.named_data.jndn.util.Blob;

/**
 * A CertificateSubjectDescription represents the SubjectDescription entry in a
 * Certificate.
 */
public class CertificateSubjectDescription {
  /**
   * Create a new CertificateSubjectDescription.
   * @param oid The oid of the subject description entry.
   * @param value The value of the subject description entry.
   */
  public CertificateSubjectDescription(String oid, String value)
  {
    oid_ = new OID(oid);
    value_ = value;
  }

  /**
   * Create a new CertificateSubjectDescription.
   * @param oid The oid of the subject description entry.
   * @param value The value of the subject description entry.
   */
  public CertificateSubjectDescription(OID oid, String value)
  {
    oid_ = oid;
    value_ = value;
  }

  /**
   * Encode the object into a DER syntax tree.
   * @return The encoded DER syntax tree.
   */
  public final DerNode
  toDer() throws DerEncodingException
  {
    DerSequence root = new DerSequence();

    DerOid oid = new DerOid(oid_);
    // Use Blob to convert the String to a ByteBuffer.
    DerPrintableString value = new DerPrintableString(new Blob(value_).buf());

    root.addChild(oid);
    root.addChild(value);

    return root;
  }

  public final String
  getOidString()
  {
    return "" + oid_;
  }

  public final String
  getValue()
  {
    return value_;
  }

  private final OID oid_;
  private final String value_;
}
