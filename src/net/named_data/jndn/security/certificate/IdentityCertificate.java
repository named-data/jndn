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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

package net.named_data.jndn.security.certificate;

import net.named_data.jndn.Data;
import net.named_data.jndn.Name;

public class IdentityCertificate extends Certificate {
  // TODO: Implement IdentityCertificate.
  public IdentityCertificate() {}
  public IdentityCertificate(Data data) {}

  public Name
  getPublicKeyName() { return publicKeyName_; }

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

  private Name publicKeyName_;
}
