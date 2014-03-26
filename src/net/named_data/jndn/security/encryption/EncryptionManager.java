/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From code in NDN-CPP by Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.security.encryption;

import java.nio.ByteBuffer;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.EncryptMode;
import net.named_data.jndn.security.KeyType;
import net.named_data.jndn.util.Blob;

public abstract class EncryptionManager {
  abstract void 
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

  abstract Blob
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

  abstract Blob
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
