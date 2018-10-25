/**
 * Copyright (C) 2017-2018 Regents of the University of California.
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

import java.nio.ByteBuffer;
import java.util.HashMap;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.DigestAlgorithm;
import net.named_data.jndn.security.KeyParams;
import net.named_data.jndn.security.KeyType;
import net.named_data.jndn.util.Blob;

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

  public String
  getTpmLocator() { return scheme_ + ":" + location_; }

  /**
   * Check if the key with name keyName exists in the TPM.
   * @param keyName The name of the key.
   * @return True if the key exists.
   */
  public final boolean
  hasKey(Name keyName) throws TpmBackEnd.Error
  {
    return backEnd_.hasKey(keyName);
  }

  /**
   * Get the public portion of an asymmetric key pair with name keyName.
   * @param keyName The name of the key.
   * @return The encoded public key, or an isNull Blob if the key does not exist.
   */
  public final Blob
  getPublicKey(Name keyName) throws TpmBackEnd.Error
  {
    TpmKeyHandle key = findKey(keyName);

    if (key == null)
      return new Blob();
    else
      return key.derivePublicKey();
  }

  /**
   * Compute a digital signature from the byte buffer using the key with name
   * keyName.
   * @param data The input byte buffer.
   * @param keyName The name of the key.
   * @param digestAlgorithm The digest algorithm for the signature.
   * @return The signature Blob, or an isNull Blob if the key does not exist, or
   * for an unrecognized digestAlgorithm.
   */
  public final Blob
  sign(ByteBuffer data, Name keyName, DigestAlgorithm digestAlgorithm)
    throws TpmBackEnd.Error
  {
    TpmKeyHandle key = findKey(keyName);

    if (key == null)
      return new Blob();
    else
      return key.sign(digestAlgorithm, data);
  }

  /**
   * Return the plain text which is decrypted from cipherText using the key
   * with name keyName.
   * @param cipherText The cipher text byte buffer.
   * @param keyName The name of the key.
   * @return The decrypted data, or an isNull Blob if the key does not exist.
   */
  public final Blob
  decrypt(ByteBuffer cipherText, Name keyName) throws TpmBackEnd.Error
  {
    TpmKeyHandle key = findKey(keyName);

    if (key == null)
      return new Blob();
    else
      return key.decrypt(cipherText);
  }

  // TPM Management

  /**
   * Check if the TPM is in terminal mode.
   * @return True if in terminal mode.
   */
  public final boolean
  isTerminalMode() throws TpmBackEnd.Error
  {
    return backEnd_.isTerminalMode();
  }

  /**
   * Set the terminal mode of the TPM. In terminal mode, the TPM will not ask
   * for a password from the GUI.
   * @param isTerminal True to enable terminal mode.
   */
  public final void
  setTerminalMode(boolean isTerminal) throws TpmBackEnd.Error
  {
    backEnd_.setTerminalMode(isTerminal);
  }

  /**
   * Check if the TPM is locked.
   * @return True if the TPM is locked, otherwise false.
   */
  public final boolean
  isTpmLocked() throws TpmBackEnd.Error
  {
    return backEnd_.isTpmLocked();
  }

  /**
   * Unlock the TPM. If !isTerminalMode(), prompt for a password from the GUI.
   * @param password The password to unlock TPM.
   * @return True if the TPM was unlocked.
   */
  public final boolean
  unlockTpm(ByteBuffer password) throws TpmBackEnd.Error
  {
    return backEnd_.unlockTpm(password);
  }

  /*
   * Create a new TPM instance with the specified location. This constructor
   * should only be called by KeyChain.
   * @param scheme The scheme for the TPM.
   * @param location The location for the TPM.
   * @param backEnd The TPM back-end implementation.
   */
  public Tpm(String scheme, String location, TpmBackEnd backEnd)
  {
    scheme_ = scheme;
    location_ = location;
    backEnd_ = backEnd;
  }

  /**
   * Get the TpmBackEnd.
   * This should only be called by KeyChain.
   */
  public final TpmBackEnd
  getBackEnd_() { return backEnd_; }

  /**
   * Create a key for the identityName according to params. The created key is
   * named /{identityName}/[keyId]/KEY .
   * This should only be called by KeyChain.
   * @param identityName The name if the identity.
   * @param params The KeyParams for creating the key.
   * @return The name of the created key.
   * @throws Tpm.Error if params is invalid or the key type is unsupported.
   * @throws TpmBackEnd.Error if the key already exists or cannot be created.
   */
  public final Name
  createKey_(Name identityName, KeyParams params)
    throws Tpm.Error, TpmBackEnd.Error
  {
    if (params.getKeyType() == KeyType.RSA ||
        params.getKeyType() == KeyType.EC) {
      TpmKeyHandle keyHandle = backEnd_.createKey(identityName, params);
      Name keyName = keyHandle.getKeyName();
      keys_.put(keyName, keyHandle);
      return keyName;
    }
    else
      throw new Error("createKey: Unsupported key type");
  }

  /**
   * Delete the key with name keyName. If the key doesn't exist, do nothing.
   * Note: Continuing to use existing Key handles on a deleted key results in
   * undefined behavior.
   * This should only be called by KeyChain.
   * @throws TpmBackEnd.Error if the deletion fails.
   */
  public final void
  deleteKey_(Name keyName) throws TpmBackEnd.Error
  {
    keys_.remove(keyName);
    backEnd_.deleteKey(keyName);
  }

  /**
   * Get the encoded private key with name keyName in PKCS #8 format, possibly
   * encrypted.
   * This should only be called by KeyChain.
   * @param keyName The name of the key in the TPM.
   * @param password The password for encrypting the private key, which should
   * have characters in the range of 1 to 127. If the password is supplied, use
   * it to return a PKCS #8 EncryptedPrivateKeyInfo. If the password is null,
   * return an unencrypted PKCS #8 PrivateKeyInfo.
   * @return The private key encoded in PKCS #8 format, or an isNull Blob if
   * the key does not exist.
   * @throws TpmBackEnd.Error if the key does not exist or if the key cannot be
   * exported, e.g., insufficient privileges.
   */
  public final Blob
  exportPrivateKey_(Name keyName, ByteBuffer password) throws TpmBackEnd.Error
  {
    return backEnd_.exportKey(keyName, password);
  }

  /**
   * Import an encoded private key with name keyName in PKCS #8 format, possibly
   * password-encrypted.
   * This should only be called by KeyChain.
   * @param keyName The name of the key to use in the TPM.
   * @param pkcs8 The input byte buffer. If the password is supplied, this is a
   * PKCS #8 EncryptedPrivateKeyInfo. If the password is null, this is an
   * unencrypted PKCS #8 PrivateKeyInfo.
   * @param password The password for decrypting the private key, which should
   * have characters in the range of 1 to 127. If the password is supplied, use
   * it to decrypt the PKCS #8 EncryptedPrivateKeyInfo. If the password is null,
   * import an unencrypted PKCS #8 PrivateKeyInfo.
   * @throws TpmBackEnd.Error if the key cannot be imported.
   */
  public final void
  importPrivateKey_(Name keyName, ByteBuffer pkcs8, ByteBuffer password)
    throws TpmBackEnd.Error
  {
    backEnd_.importKey(keyName, pkcs8, password);
  }

  /**
   * Get the TpmKeyHandle with name keyName, using backEnd_.getKeyHandle if it
   * is not already cached in keys_.
   * @param keyName The name of the key, which is copied.
   * @return The key handle in the keys_ cache, or null if no key exists with
   * name keyName.
   */
  private TpmKeyHandle
  findKey(Name keyName) throws TpmBackEnd.Error
  {
    TpmKeyHandle handle = keys_.get(keyName);

    if (handle != null)
      return handle;

    handle = backEnd_.getKeyHandle(keyName);

    if (handle != null) {
      // Copy the Name.
      keys_.put(new Name(keyName), handle);
      return handle;
    }

    return null;
  }

  private final String scheme_;
  private final String location_;

  HashMap<Name, TpmKeyHandle> keys_ = new HashMap<Name, TpmKeyHandle>();

  private final TpmBackEnd backEnd_;
}
