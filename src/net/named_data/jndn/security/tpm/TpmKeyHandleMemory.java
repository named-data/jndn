/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/tpm/key-handle-mem.cpp
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
import net.named_data.jndn.security.DigestAlgorithm;
import net.named_data.jndn.util.Blob;

/**
 * TpmKeyHandleMemory extends TpmKeyHandle to implement a TPM key handle that
 * keeps the private key in memory.
 */
public class TpmKeyHandleMemory extends TpmKeyHandle {
  /**
   * Create a TpmKeyHandleMemory to use the given in-memory key.
   * @param key The in-memory key.
   */
  public TpmKeyHandleMemory(TpmPrivateKey key)
  {
    if (key == null)
      throw new AssertionError("The key is null");

    key_ = key;
  }

  protected Blob
  doSign(DigestAlgorithm digestAlgorithm, ByteBuffer data)
    throws TpmBackEnd.Error
  {
    if (digestAlgorithm == DigestAlgorithm.SHA256) {
      try {
        return key_.sign(data, digestAlgorithm);
      } catch (TpmPrivateKey.Error ex) {
        throw new TpmBackEnd.Error("Error in TpmPrivateKey.sign: " + ex);
      }
    }
    else
      return new Blob();
  }

  protected Blob
  doDecrypt(ByteBuffer cipherText) throws TpmBackEnd.Error
  {
    try {
      return key_.decrypt(cipherText);
    } catch (TpmPrivateKey.Error ex) {
        throw new TpmBackEnd.Error("Error in TpmPrivateKey.decrypt: " + ex);
    }
  }

  protected Blob
  doDerivePublicKey() throws TpmBackEnd.Error
  {
    try {
      return key_.derivePublicKey();
    } catch (TpmPrivateKey.Error ex) {
        throw new TpmBackEnd.Error("Error in TpmPrivateKey.derivePublicKey: " + ex);
    }
  }

  private TpmPrivateKey key_;
}
