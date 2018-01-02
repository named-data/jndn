/**
 * Copyright (C) 2014-2018 Regents of the University of California.
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
import net.named_data.jndn.encoding.der.DerNode.DerBoolean;
import net.named_data.jndn.encoding.der.DerNode.DerOctetString;
import net.named_data.jndn.encoding.der.DerNode.DerOid;
import net.named_data.jndn.encoding.der.DerNode.DerSequence;
import net.named_data.jndn.util.Blob;

/**
 * A CertificateExtension represents the Extension entry in a certificate.
 */
public class CertificateExtension {
  /**
   * Create a new CertificateExtension.
   * @param oid The oid of subject description entry.
   * @param isCritical If true, the extension must be handled.
   * @param value The extension value.
   */
  public CertificateExtension(String oid, boolean isCritical, Blob value)
  {
    extensionId_ = new OID(oid);
    isCritical_ = isCritical;
    extensionValue_ = value;
  }

  /**
   * Create a new CertificateExtension.
   * @param oid The oid of subject description entry.
   * @param isCritical If true, the extension must be handled.
   * @param value The extension value.
   */
  public CertificateExtension(OID oid, boolean isCritical, Blob value)
  {
    extensionId_ = oid;
    isCritical_ = isCritical;
    extensionValue_ = value;
  }

  /**
   * Encode the object into DER syntax tree.
   * @return The encoded DER syntax tree.
   */
  public final DerNode
  toDer() throws DerEncodingException
  {
    DerSequence root = new DerSequence();

    DerOid extensionId = new DerOid(extensionId_);
    DerBoolean isCritical = new DerBoolean(isCritical_);
    DerOctetString extensionValue = new DerOctetString(extensionValue_.buf());

    root.addChild(extensionId);
    root.addChild(isCritical);
    root.addChild(extensionValue);

    root.getSize();

    return root;
  }

  public final Blob
  toDerBlob() throws DerEncodingException
  {
    return toDer().encode();
  }

  public final OID
  getOid() { return extensionId_; }

  public final boolean
  getIsCritical() { return isCritical_; }

  public final Blob
  getValue() { return extensionValue_; }

  protected final OID extensionId_;
  protected final boolean isCritical_;
  protected final Blob extensionValue_;
}
