/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/tpm/back-end.cpp
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
import net.named_data.jndn.Name;
import net.named_data.jndn.security.KeyIdType;
import net.named_data.jndn.security.KeyParams;
import net.named_data.jndn.security.pib.PibKey;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

/**
 * TpmBackEnd is an abstract base class for a TPM backend implementation which
 * provides a TpmKeyHandle to the TPM front end. This class defines the
 * interface that an actual TPM backend implementation should provide, for
 * example TpmBackEndMemory.
 */
public abstract class TpmBackEnd {
  /**
   * A TpmBackEnd.Error extends Exception and represents a non-semantic
   * error in backend TPM processing.
   * Note that even though this is called "Error" to be consistent with the
   * other libraries, it extends the Java Exception class, not Error.
   */
  public static class Error extends Exception {
    public Error(String message)
    {
      super(message);
    }
  }

  /**
   * Check if the key with name keyName exists in the TPM.
   * @param keyName The name of the key.
   * @return True if the key exists.
   */
  public final boolean
  hasKey(Name keyName) throws TpmBackEnd.Error { return doHasKey(keyName); }

  /**
   * Get the handle of the key with name keyName.
   * Calling getKeyHandle multiple times with the same keyName will return
   * different TpmKeyHandle objects that all refer to the same key.
   * @param keyName The name of the key.
   * @return The handle of the key, or null if the key does not exist.
   */
  public final TpmKeyHandle
  getKeyHandle(Name keyName) throws TpmBackEnd.Error
  {
    return doGetKeyHandle(keyName);
  }

  /**
   * Create a key for the identityName according to params.
   * @param identityName The name if the identity.
   * @param params The KeyParams for creating the key.
   * @return The handle of the created key.
   * @throws Tpm.Error if params is invalid.
   * @throws TpmBackEnd.Error if the key cannot be created.
   */
  public final TpmKeyHandle
  createKey(Name identityName, KeyParams params)
    throws TpmBackEnd.Error, Tpm.Error
  {
    // Do key name checking.
    if (params.getKeyIdType() == KeyIdType.USER_SPECIFIED) {
      // The keyId is pre-set.
      Name keyName = PibKey.constructKeyName(identityName, params.getKeyId());
      if (hasKey(keyName))
        throw new Tpm.Error("Key `" + keyName.toUri() + "` already exists");
    }
    else if (params.getKeyIdType() == KeyIdType.SHA256) {
      // The key name will be assigned in setKeyName after the key is generated.
    }
    else if (params.getKeyIdType() == KeyIdType.RANDOM) {
      Name keyName;
      Name.Component keyId;
      ByteBuffer random = ByteBuffer.allocate(8);
      do {
        Common.getRandom().nextBytes(random.array());
        keyId = new Name.Component(new Blob(random, false));
        keyName = PibKey.constructKeyName(identityName, keyId);
      } while (hasKey(keyName));

      params.setKeyId(keyId);
    }
    else
      throw new Tpm.Error("Unsupported key id type");

    return doCreateKey(identityName, params);
  }

  /**
   * Delete the key with name keyName. If the key doesn't exist, do nothing.
   * Note: Continuing to use existing Key handles on a deleted key results in
   * undefined behavior.
   * @param keyName The name of the key to delete.
   * @throws TpmBackEnd.Error if the deletion fails.
   */
  public final void
  deleteKey(Name keyName) throws TpmBackEnd.Error { doDeleteKey(keyName); }

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
  public final Blob
  exportKey(Name keyName, ByteBuffer password) throws TpmBackEnd.Error
  {
    if (!hasKey(keyName))
      throw new Error("Key `" + keyName.toUri() + "` does not exist");

    return doExportKey(keyName, password);
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
   * @throws TpmBackEnd.Error if a key with name keyName already exists, or for
   * an error importing the key.
   */
  public final void
  importKey(Name keyName, ByteBuffer pkcs8, ByteBuffer password)
    throws TpmBackEnd.Error
  {
    if (hasKey(keyName))
      throw new Error("Key `" + keyName.toUri() + "` already exists");

    doImportKey(keyName, pkcs8, password);
  }

  /**
   * Check if the TPM is in terminal mode. The default implementation always
   * returns true.
   * @return True if in terminal mode.
   */
  public boolean
  isTerminalMode() throws TpmBackEnd.Error { return true; }

  /**
   * Set the terminal mode of the TPM. In terminal mode, the TPM will not ask
   * for a password from the GUI. The default implementation does nothing.
   * @param isTerminal True to enable terminal mode.
   */
  public void
  setTerminalMode(boolean isTerminal) throws TpmBackEnd.Error {}

  /**
   * Check if the TPM is locked. The default implementation returns false.
   * @return True if the TPM is locked, otherwise false.
   */
  public boolean
  isTpmLocked() throws TpmBackEnd.Error { return false; }

  /**
   * Unlock the TPM. If !isTerminalMode(), prompt for a password from the GUI.
   * The default implementation does nothing and returns !isTpmLocked().
   * @param password The password to unlock TPM.
   * @return True if the TPM was unlocked.
   */
  public boolean
  unlockTpm(ByteBuffer password) throws TpmBackEnd.Error { return !isTpmLocked(); }

  /**
   * Set the key name in keyHandle according to identityName and params.
   */
  protected static void
  setKeyName(TpmKeyHandle keyHandle, Name identityName, KeyParams params)
    throws TpmBackEnd.Error
  {
    Name.Component keyId;
    if (params.getKeyIdType() == KeyIdType.USER_SPECIFIED)
      keyId = params.getKeyId();
    else if (params.getKeyIdType() == KeyIdType.SHA256) {
      byte[] digest = Common.digestSha256(keyHandle.derivePublicKey().buf());
      keyId = new Name.Component(digest);
    }
    else if (params.getKeyIdType() == KeyIdType.RANDOM) {
      if (params.getKeyId().getValue().size() == 0)
        throw new Error("setKeyName: The keyId is empty for type RANDOM");
      keyId = params.getKeyId();
    }
    else
      throw new Error("setKeyName: unrecognized params.getKeyIdType()");

    keyHandle.setKeyName(PibKey.constructKeyName(identityName, keyId));
  }

  /**
   * Check if the key with name keyName exists in the TPM.
   * @param keyName The name of the key.
   * @return True if the key exists.
   */
  protected abstract boolean
  doHasKey(Name keyName) throws TpmBackEnd.Error;

  /**
   * Get the handle of the key with name keyName.
   * @param keyName The name of the key.
   * @return The handle of the key, or null if the key does not exist.
   */
  protected abstract TpmKeyHandle
  doGetKeyHandle(Name keyName) throws TpmBackEnd.Error;

  /**
   * Create a key for identityName according to params. The created key is
   * named as: /{identityName}/[keyId]/KEY . The key name is set in the returned
   * TpmKeyHandle.
   * @param identityName The name if the identity.
   * @param params The KeyParams for creating the key.
   * @return The handle of the created key.
   * @throws TpmBackEnd.Error if the key cannot be created.
   */
  protected abstract TpmKeyHandle
  doCreateKey(Name identityName, KeyParams params) throws TpmBackEnd.Error;

  /**
   * Delete the key with name keyName. If the key doesn't exist, do nothing.
   * @param keyName The name of the key to delete.
   * @throws TpmBackEnd.Error if the deletion fails.
   */
  protected abstract void
  doDeleteKey(Name keyName) throws TpmBackEnd.Error;

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
    throw new Error("TpmBackEnd doExportKey is not implemented");
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
    throw new Error("TpmBackEnd doImportKey is not implemented");
  }
}
