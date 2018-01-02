/**
 * Copyright (C) 2015-2018 Regents of the University of California.
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

import net.named_data.jndn.Name;
import net.named_data.jndn.util.Common;

/**
 * KeyParams is a base class for key parameters. Its subclasses are used to
 * store parameters for key generation.
 */
public class KeyParams {
  public final KeyType
  getKeyType() { return keyType_; }

  public final KeyIdType
  getKeyIdType() { return keyIdType_; }

  public final void
  setKeyId(Name.Component keyId) { keyId_ = keyId; }

  public final Name.Component
  getKeyId() { return keyId_; }

  /**
   * Create a key generation parameter.
   * @param keyType The type for the created key.
   * @param keyIdType The method for how the key id should be generated, which
   * must not be KeyIdType.USER_SPECIFIED.
   * @throws AssertionError if keyIdType is KeyIdType.USER_SPECIFIED.
   */
  protected KeyParams(KeyType keyType, KeyIdType keyIdType)
  {
    if (keyIdType == KeyIdType.USER_SPECIFIED)
      throw new AssertionError("KeyParams: KeyIdType is USER_SPECIFIED");

    keyType_ = keyType;
    keyIdType_ = keyIdType;
  }

  /**
   * Create a key generation parameter.
   * @param keyType The type for the created key.
   * @param keyId The user-specified key ID. This sets the keyIdType to
   * KeyIdType.USER_SPECIFIED. keyId must not be empty.
   * @throws AssertionError if keyId is empty.
   */
  protected KeyParams(KeyType keyType, Name.Component keyId)
  {
    if (keyId.getValue().size() == 0)
      throw new AssertionError("KeyParams: keyId is empty");

    keyType_ = keyType;
    keyIdType_ = KeyIdType.USER_SPECIFIED;
    keyId_ = keyId;
  }

  private final KeyType keyType_;
  private final KeyIdType keyIdType_;
  private Name.Component keyId_ = new Name.Component();

  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
