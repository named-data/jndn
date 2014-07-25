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

package net.named_data.jndn.security.encryption;

import java.nio.ByteBuffer;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.EncryptMode;
import net.named_data.jndn.security.KeyType;
import net.named_data.jndn.util.Blob;

public abstract class EncryptionManager {
  public abstract void
  createSymmetricKey
    (Name keyName, KeyType keyType, Name signkeyName, boolean isSymmetric);

  public void
  createSymmetricKey(Name keyName, KeyType keyType, Name signkeyName)
  {
    createSymmetricKey(keyName, keyType, signkeyName, true);
  }

  public void
  createSymmetricKey(Name keyName, KeyType keyType)
  {
    createSymmetricKey(keyName, keyType, new Name(), true);
  }

  public abstract Blob
  encrypt
    (Name keyName, ByteBuffer data, boolean useSymmetric,
     EncryptMode encryptMode);

  public Blob
  encrypt(Name keyName, ByteBuffer data, boolean useSymmetric)
  {
    return encrypt(keyName, data, useSymmetric, EncryptMode.DEFAULT);
  }

  public Blob
  encrypt(Name keyName, ByteBuffer data)
  {
    return encrypt(keyName, data, false, EncryptMode.DEFAULT);
  }

  public abstract Blob
  decrypt
    (Name keyName, ByteBuffer data, boolean useSymmetric,
     EncryptMode encryptMode);

  public Blob
  decrypt(Name keyName, ByteBuffer data, boolean useSymmetric)
  {
    return decrypt(keyName, data, useSymmetric, EncryptMode.DEFAULT);
  }

  public Blob
  decrypt(Name keyName, ByteBuffer data)
  {
    return decrypt(keyName, data, false, EncryptMode.DEFAULT);
  }
}
