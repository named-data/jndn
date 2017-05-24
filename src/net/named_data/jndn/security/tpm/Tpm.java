/**
 * Copyright (C) 2017 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/tpm/tpm.cpp
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

package net.named_data.jndn.security.tpm;

/**
 * The TPM (Trusted Platform Module) stores the private portion of a user's
 * cryptography keys. The format and location of stored information is indicated
 * by the TPM locator. The TPM is designed to work with a PIB (Public
 * Information Base) which stores public keys and related information such as
 * certificates.
 *
 * The TPM also provides functionalities of cryptographic transformation, such
 * as signing and decryption.
 *
 * A TPM consists of a unified front-end interface and a backend implementation.
 * The front-end caches the handles of private keys which are provided by the
 * backend implementation.
 *
 * Note: A Tpm instance is created and managed only by the KeyChain. It is
 * returned by the KeyChain getTpm() method, through which it is possible to
 * check for the existence of private keys, get public keys for the private
 * keys, sign, and decrypt the supplied buffers using managed private keys.
 */
public class Tpm {
  /**
   * A Tpm.Error extends Exception and represents a semantic error in TPM
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
