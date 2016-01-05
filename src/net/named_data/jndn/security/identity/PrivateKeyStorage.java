/**
 * Copyright (C) 2013-2016 Regents of the University of California.
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

package net.named_data.jndn.security.identity;

import java.nio.ByteBuffer;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.DigestAlgorithm;
import net.named_data.jndn.security.KeyClass;
import net.named_data.jndn.security.KeyParams;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.certificate.PublicKey;
import net.named_data.jndn.util.Blob;

public abstract class PrivateKeyStorage {
  /**
   * Generate a pair of asymmetric keys.
   * @param keyName The name of the key pair.
   * @param params The parameters of the key.
   * @throws SecurityException
   */
  public abstract void
  generateKeyPair(Name keyName, KeyParams params) throws SecurityException;

  /**
   * Delete a pair of asymmetric keys. If the key doesn't exist, do nothing.
   * @param keyName The name of the key pair.
   */
  public abstract void
  deleteKeyPair(Name keyName) throws SecurityException;

  /**
   * Get the public key
   * @param keyName The name of public key.
   * @return The public key.
   * @throws SecurityException
   */
  public abstract PublicKey
  getPublicKey(Name keyName) throws SecurityException;

  /**
   * Fetch the private key for keyName and sign the data, returning a signature
   * Blob.
   * @param data Pointer the input byte buffer to sign.
   * @param keyName The name of the signing key.
   * @param digestAlgorithm the digest algorithm.
   * @return The signature Blob.
   * @throws SecurityException
   */
  public abstract Blob
  sign(ByteBuffer data, Name keyName, DigestAlgorithm digestAlgorithm)
      throws SecurityException;

  /**
   * Fetch the private key for keyName and sign the data using
   * DigestAlgorithm.SHA256, returning a signature Blob.
   * @param data Pointer the input byte buffer to sign.
   * @param keyName The name of the signing key.
   * @return The signature Blob.
   * @throws SecurityException
   */
  public final Blob
  sign(ByteBuffer data, Name keyName) throws SecurityException
  {
    return sign(data, keyName, DigestAlgorithm.SHA256);
  }

  /**
   * Decrypt data.
   * @param keyName The name of the decrypting key.
   * @param data The byte buffer to be decrypted, from its position to its
   * limit.
   * @param isSymmetric If true symmetric encryption is used, otherwise
   * asymmetric encryption is used.
   * @return The decrypted data.
   * @throws SecurityException
   */
  public abstract Blob
  decrypt(Name keyName, ByteBuffer data, boolean isSymmetric)
         throws SecurityException;

  /**
   * Decrypt data using asymmetric encryption.
   * @param keyName The name of the decrypting key.
   * @param data The byte buffer to be decrypted, from its position to its
   * limit.
   * @return The decrypted data.
   * @throws SecurityException
   */
  public final Blob
  decrypt(Name keyName, ByteBuffer data) throws SecurityException
  {
    return decrypt(keyName, data, false);
  }

  /**
   * Encrypt data.
   * @param keyName The name of the encrypting key.
   * @param data The byte buffer to be encrypted, from its position to its
   * limit.
   * @param isSymmetric If true symmetric encryption is used, otherwise
   * asymmetric encryption is used.
   * @return The encrypted data.
   * @throws SecurityException
   */
  public abstract Blob
  encrypt(Name keyName, ByteBuffer data, boolean isSymmetric)
          throws SecurityException;

  /**
   * Encrypt data using asymmetric encryption.
   * @param keyName The name of the encrypting key.
   * @param data The byte buffer to be encrypted, from its position to its
   * limit.
   * @return The encrypted data.
   * @throws SecurityException
   */
  public final Blob
  encrypt(Name keyName, ByteBuffer data) throws SecurityException
  {
    return encrypt(keyName, data, false);
  }

  /**
   * Generate a symmetric key.
   * @param keyName The name of the key.
   * @param params The parameters of the key.
   * @throws SecurityException
   */
  public abstract void
  generateKey(Name keyName, KeyParams params) throws SecurityException;

  /**
   * Check if a particular key exists.
   * @param keyName The name of the key.
   * @param keyClass The class of the key, e.g. KeyClass.PUBLIC,
   * KeyClass.PRIVATE, or KeyClass.SYMMETRIC.
   * @return True if the key exists, otherwise false.
   */
  public abstract boolean
  doesKeyExist(Name keyName, KeyClass keyClass) throws SecurityException;
}
