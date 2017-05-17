/**
 * Copyright (C) 2017 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/pib/pib.cpp
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

/**
 * In general, a PIB (Public Information Base) stores the public portion of a
 * user's cryptography keys. The format and location of stored information is
 * indicated by the PIB locator. A PIB is designed to work with a TPM (Trusted
 * Platform Module) which stores private keys. There is a one-to-one association
 * between a PIB and a TPM, and therefore the TPM locator is recorded by the PIB
 * to enforce this association and prevent one from operating on mismatched PIB
 * and TPM.
 *
 * Information in the PIB is organized in a hierarchy of
 * Identity-Key-Certificate. At the top level, this Pib class provides access to
 * identities, and allows setting a default identity. Properties of an identity
 * (such as PibKey objects) can be accessed after obtaining a PibIdentity object.
 * (Likewise, CertificateV2 objects can be obtained from a PibKey object.)
 *
 * Note: A Pib instance is created and managed only by the KeyChain, and is
 * returned by the KeyChain getPib() method.
 */
public class Pib {
  /**
   * A Pib.Error extends Exception and represents a semantic error in PIB
   * processing.
   * Note that even though this is called "Error" to be consistent with the
   * other libraries, it extends the Java Exception class, not Error.
   */
  public static class Error extends Exception {
    public Error(String message)
    {
      super(message);
    }
  }


}
