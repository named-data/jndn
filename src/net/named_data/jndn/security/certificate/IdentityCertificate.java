/**
 * Copyright (C) 2014-2015 Regents of the University of California.
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

import net.named_data.jndn.Data;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.der.DerDecodingException;

public class IdentityCertificate extends Certificate {
  public IdentityCertificate() {}

  /**
   * Create an IdentityCertificate from the content in the data packet.
   * @param data The data packet with the content to decode.
   */
  public IdentityCertificate(Data data) throws DerDecodingException
  {
    super(data);

    if (!isCorrectName(data.getName()))
      throw new SecurityException("Wrong Identity Certificate Name!");

    setPublicKeyName();
  }

  /**
   * The copy constructor.
   */
  public IdentityCertificate(IdentityCertificate identityCertificate)
    throws DerDecodingException
  {
    super(identityCertificate);
    publicKeyName_ = identityCertificate.publicKeyName_;
  }

  /**
   * Override the base class method to check that the name is a valid identity certificate name.
   * @param name The identity certificate name which is copied.
   * @return This Data so that you can chain calls to update values.
   */
  public Data
  setName(Name name)
  {
    if (!isCorrectName(name))
      throw new SecurityException("Wrong Identity Certificate Name!");

    super.setName(name);
    setPublicKeyName();
    return this;
  }

  public final Name
  getPublicKeyName() { return publicKeyName_; }

  public static boolean
  isIdentityCertificate(Certificate certificate)
  {
    return isCorrectName(certificate.getName());
  }

  /**
   * Get the public key name from the full certificate name.
   * @param certificateName The full certificate name.
   * @return The related public key name.
   */
  public static Name
  certificateNameToPublicKeyName(Name certificateName)
  {
    int i = certificateName.size() - 1;
    String idString = "ID-CERT";
    for (; i >= 0; i--) {
      if (certificateName.get(i).toEscapedString().equals(idString))
        break;
    }

    Name tmpName = certificateName.getSubName(0, i);
    String keyString = "KEY";
    for (i = 0; i < tmpName.size(); i++) {
      if (tmpName.get(i).toEscapedString().equals(keyString))
        break;
    }

    return tmpName.getSubName(0, i).append
      (tmpName.getSubName(i + 1, tmpName.size() - i - 1));
  }

  private static boolean
  isCorrectName(Name name)
  {
    int i = name.size() - 1;

    String idString = "ID-CERT";
    for (; i >= 0; i--) {
      if(name.get(i).toEscapedString().equals(idString))
        break;
    }

    if (i < 0)
      return false;

    int keyIdx = 0;
    String keyString = "KEY";
    for (; keyIdx < name.size(); keyIdx++) {
      if(name.get(keyIdx).toEscapedString().equals(keyString))
        break;
    }

    if (keyIdx >= name.size())
      return false;

    return true;
  }

  private void
  setPublicKeyName()
  {
    publicKeyName_ = certificateNameToPublicKeyName(getName());
  }

  private Name publicKeyName_ = new Name();
}
