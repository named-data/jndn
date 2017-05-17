/**
 * Copyright (C) 2017 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/pib/key.cpp
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

package net.named_data.jndn.security.pib;

import net.named_data.jndn.Name;
import net.named_data.jndn.security.v2.CertificateV2;

/**
 * The PibKey class provides access to a key at the second level in the PIB's
 * Identity-Key-Certificate hierarchy. A PibKey object has a Name
 * (identity + "KEY" + keyId), and contains one or more CertificateV2
 * objects, one of which is set as the default certificate of this key.
 * A certificate can be directly accessed by getting a CertificateV2 object.
 */
public class PibKey {

  /**
   * Construct a key name based on the appropriate naming conventions.
   * @param identityName The name of the identity.
   * @param keyId The key ID name component.
   * @return The constructed name as a new Name.
   */
  public static Name
  constructKeyName(Name identityName, Name.Component keyId)
  {
    Name keyName = new Name(identityName);
    keyName.append(CertificateV2.KEY_COMPONENT).append(keyId);

    return keyName;
  }

  /**
   * Check if keyName follows the naming conventions for a key name.
   * @param keyName The name of the key.
   * @return True if keyName follows the naming conventions, otherwise false.
   */
  public static boolean
  isValidKeyName(Name keyName)
  {
    return (keyName.size() > CertificateV2.MIN_KEY_NAME_LENGTH &&
            keyName.get(-CertificateV2.MIN_KEY_NAME_LENGTH).equals
              (CertificateV2.KEY_COMPONENT));
  }

  /**
   * Extract the identity namespace from keyName.
   * @param keyName The name of the key.
   * @return The identity name as a new Name.
   */
  public static Name
  extractIdentityFromKeyName(Name keyName)
  {
    if (!isValidKeyName(keyName))
      throw new IllegalArgumentException
        ("Key name `" + keyName.toUri() +
         "` does not follow the naming conventions");

    // Trim everything after and including "KEY".
    return keyName.getPrefix(-CertificateV2.MIN_KEY_NAME_LENGTH);
  }

}
