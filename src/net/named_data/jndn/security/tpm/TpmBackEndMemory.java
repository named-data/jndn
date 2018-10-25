/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/tpm/back-end-mem.cpp
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

import java.nio.ByteBuffer;
import java.util.HashMap;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.KeyParams;
import net.named_data.jndn.util.Blob;

/**
 * TpmBackEndMemory extends TpmBackEnd to implement a TPM back-end using
 * in-memory storage.
 */
public class TpmBackEndMemory extends TpmBackEnd {
  public static String
  getScheme() { return "tpm-memory"; }

  /**
   * Check if the key with name keyName exists in the TPM.
   * @param keyName The name of the key.
   * @return True if the key exists.
   */
  protected boolean
  doHasKey(Name keyName) throws TpmBackEnd.Error
  {
    return keys_.containsKey(keyName);
  }

  /**
   * Get the handle of the key with name keyName.
   * @param keyName The name of the key.
   * @return The handle of the key, or null if the key does not exist.
   */
  protected TpmKeyHandle
  doGetKeyHandle(Name keyName) throws TpmBackEnd.Error
  {
    TpmPrivateKey key = keys_.get(keyName);
    if (key == null)
      return null;

    return new TpmKeyHandleMemory(key);
  }

  /**
   * Create a key for identityName according to params. The created key is
   * named as: /{identityName}/[keyId]/KEY . The key name is set in the returned
   * TpmKeyHandle.
   * @param identityName The name if the identity.
   * @param params The KeyParams for creating the key.
   * @return The handle of the created key.
   * @throws TpmBackEnd.Error if the key cannot be created.
   */
  protected TpmKeyHandle
  doCreateKey(Name identityName, KeyParams params) throws TpmBackEnd.Error
  {
    TpmPrivateKey key;
    try {
      key = TpmPrivateKey.generatePrivateKey(params);
    } catch (TpmPrivateKey.Error ex) {
      throw new TpmBackEnd.Error
        ("Error in TpmPrivateKey.generatePrivateKey: " + ex);
    }
    TpmKeyHandle keyHandle = new TpmKeyHandleMemory(key);

    setKeyName(keyHandle, identityName, params);

    keys_.put(keyHandle.getKeyName(), key);
    return keyHandle;
  }

  /**
   * Delete the key with name keyName. If the key doesn't exist, do nothing.
   * @param keyName The name of the key to delete.
   * @throws TpmBackEnd.Error if the deletion fails.
   */
  protected void
  doDeleteKey(Name keyName) throws TpmBackEnd.Error
  {
    keys_.remove(keyName);
  }

  /**
   * Get the encoded private key with name keyName in PKCS #8 format, possibly
   * password-encrypted.
   * @param keyName The name of the key in the TPM.
   * @param password The password for encrypting the private key, which should
   * have characters in the range of 1 to 127. If the password is supplied, use
   * it to return a PKCS #8 EncryptedPrivateKeyInfo. If the password is null,
   * return an unencrypted PKCS #8 PrivateKeyInfo.
   * @return The encoded private key.
   * @throws TpmBackEnd.Error if the key does not exist or if the key cannot be
   * exported, e.g., insufficient privileges.
   */
  protected Blob
  doExportKey(Name keyName, ByteBuffer password) throws TpmBackEnd.Error
  {
    if (!hasKey(keyName))
      throw new TpmBackEnd.Error("exportKey: The key does not exist");

    try {
      if (password != null)
        return keys_.get(keyName).toEncryptedPkcs8(password);
      else
        return keys_.get(keyName).toPkcs8();
    } catch (TpmPrivateKey.Error ex) {
      throw new TpmBackEnd.Error("Error in toPkcs8: " + ex);
    }
  }

  /**
   * Import an encoded private key with name keyName in PKCS #8 format, possibly
   * password-encrypted.
   * @param keyName The name of the key to use in the TPM.
   * @param pkcs8 The input byte buffer. If the password is supplied, this is a
   * PKCS #8 EncryptedPrivateKeyInfo. If the password is null, this is an
   * unencrypted PKCS #8 PrivateKeyInfo.
   * @param password The password for decrypting the private key, which should
   * have characters in the range of 1 to 127. If the password is supplied, use
   * it to decrypt the PKCS #8 EncryptedPrivateKeyInfo. If the password is null,
   * import an unencrypted PKCS #8 PrivateKeyInfo.
   * @throws TpmBackEnd.Error for an error importing the key.
   */
  protected void
  doImportKey
    (Name keyName, ByteBuffer pkcs8, ByteBuffer password) throws TpmBackEnd.Error
  {
    try {
      TpmPrivateKey key = new TpmPrivateKey();
      if (password  != null)
        key.loadEncryptedPkcs8(pkcs8, password);
      else
        key.loadPkcs8(pkcs8);
      // Copy the Name.
      keys_.put(new Name(keyName), key);
    } catch (TpmPrivateKey.Error ex) {
      throw new TpmBackEnd.Error("Cannot import private key: " + ex);
    }
  }

  private final HashMap<Name, TpmPrivateKey> keys_ =
    new HashMap<Name, TpmPrivateKey>();
}
