/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/tpm/key-handle.cpp
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
import net.named_data.jndn.security.DigestAlgorithm;
import net.named_data.jndn.util.Blob;

/**
 * TpmKeyHandle is an abstract base class for a TPM key handle, which provides
 * an interface to perform cryptographic operations with a key in the TPM.
 */
public abstract class TpmKeyHandle {
  /**
   * Compute a digital signature from the byte buffer using this key with
   * digestAlgorithm.
   * @param digestAlgorithm The digest algorithm.
   * @param data The input byte buffer.
   * @return The signature Blob, or an isNull Blob for an unrecognized
   * digestAlgorithm.
   */
  public final Blob
  sign(DigestAlgorithm digestAlgorithm, ByteBuffer data)
    throws TpmBackEnd.Error
  {
    return doSign(digestAlgorithm, data);
  }

  /**
   * Return the plain text which is decrypted from cipherText using this key.
   * @param cipherText The cipher text byte buffer.
   * @return The decrypted data.
   */
  public final Blob
  decrypt(ByteBuffer cipherText) throws TpmBackEnd.Error
  {
    return doDecrypt(cipherText);
  }

  /**
   * Get the encoded public key derived from this key.
   * @return The public key encoding Blob.
   */
  public final Blob
  derivePublicKey() throws TpmBackEnd.Error { return doDerivePublicKey(); }

  public final void
  setKeyName(Name keyName) { keyName_ = new Name(keyName); }

  public final Name
  getKeyName() { return keyName_; }

  protected abstract Blob
  doSign(DigestAlgorithm digestAlgorithm, ByteBuffer data)
    throws TpmBackEnd.Error;

  protected abstract Blob
  doDecrypt(ByteBuffer cipherText) throws TpmBackEnd.Error;

  protected abstract Blob
  doDerivePublicKey() throws TpmBackEnd.Error;

  private Name keyName_ = new Name();
}
