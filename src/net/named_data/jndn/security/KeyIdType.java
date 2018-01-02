/**
 * Copyright (C) 2017-2018 Regents of the University of California.
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

package net.named_data.jndn.security;

/**
 * The KeyIdType enum represents the type of a KeyId component in a key name.
 */
public enum KeyIdType {
  /**
   * USER_SPECIFIED: A user-specified key ID. It is the user's responsibility to
   * ensure the uniqueness of key names.
   */
  USER_SPECIFIED,
  /**
   * SHA256: The SHA256 hash of the public key as the key id. This KeyId type
   * guarantees the uniqueness of key names.
   */
  SHA256,
  /**
   * RANDOM: A 64-bit random number as the key id. This KeyId provides rough
   * uniqueness of key names.
   */
  RANDOM
}
