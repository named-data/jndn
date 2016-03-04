/**
 * Copyright (C) 2015-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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

package net.named_data.jndn;

import net.named_data.jndn.util.Blob;

/**
 * A GenericSignature extends Signature and holds the encoding bytes of the
 * SignatureInfo so that the application can process experimental signature
 * types. When decoding a packet, if the type of SignatureInfo is not
 * recognized, the library creates a GenericSignature.
 */
public class GenericSignature extends Signature {
  /**
   * Create a new GenericSignature with default values.
   */
  public GenericSignature()
  {
  }

  /**
   * Create a new GenericSignature with a copy of the fields in the given
   * signature object.
   * @param signature The signature object to copy.
   */
  public GenericSignature(GenericSignature signature)
  {
    signature_ = signature.signature_;
    signatureInfoEncoding_ = signature.signatureInfoEncoding_;
    typeCode_ = signature.typeCode_;
  }

  /**
   * Return a new GenericSignature which is a deep copy of this
   * GenericSignature.
   * @return A new GenericSignature.
   * @throws CloneNotSupportedException
   */
  public Object clone() throws CloneNotSupportedException
  {
    return new GenericSignature(this);
  }

  /**
   * Get the bytes of the entire signature info encoding (including the type
   * code).
   * @return The encoding bytes. If not specified, the value isNull().
   */
  public final Blob
  getSignatureInfoEncoding() { return signatureInfoEncoding_; }

  /**
   * Set the bytes of the entire signature info encoding (including the type
   * code).
   * @param signatureInfoEncoding A Blob with the encoding bytes.
   * @param typeCode the type code of the signature type, or -1 if not known.
   * (When a GenericSignature is created by wire decoding, it sets the typeCode.)
   */
  public final void
  setSignatureInfoEncoding(Blob signatureInfoEncoding, int typeCode)
  {
    signatureInfoEncoding_ =
      (signatureInfoEncoding == null ? new Blob() : signatureInfoEncoding);
    typeCode_ = typeCode;
  
    ++changeCount_;
  }

  /**
   * Set the bytes of the entire signature info encoding (including the type
   * code). getTypeCode() will return -1 for not known.
   * @param signatureInfoEncoding A Blob with the encoding bytes.
   */
  public final void
  setSignatureInfoEncoding(Blob signatureInfoEncoding)
  {
    setSignatureInfoEncoding(signatureInfoEncoding, -1);
  }

  /**
   * Get the signature bytes.
   * @return The signature bytes. If not specified, the value isNull().
   */
  public final Blob
  getSignature() { return signature_; }

  /**
   * Set the signature bytes to the given value.
   * @param signature A Blob with the signature bytes.
   */
  public final void
  setSignature(Blob signature)
  {
    signature_ = (signature == null ? new Blob() : signature);
    ++changeCount_;
  }

  /**
   * Get the type code of the signature type. When wire decode calls
   * setSignatureInfoEncoding, it sets the type code. Note that the type code
   * is ignored during wire encode, which simply uses getSignatureInfoEncoding()
   * where the encoding already has the type code.
   * @return The type code, or -1 if not known.
   */
  public final int
  getTypeCode() { return typeCode_; }

  /**
   * Get the change count, which is incremented each time this object
   * (or a child object) is changed.
   * @return The change count.
   */
  public final long
  getChangeCount()
  {
    return changeCount_;
  }

  private Blob signature_ = new Blob();
  private Blob signatureInfoEncoding_ = new Blob();
  private int typeCode_ = -1;
  private long changeCount_ = 0;
}
