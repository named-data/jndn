/**
 * Copyright (C) 2015-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/algo/encrypt-params https://github.com/named-data/ndn-group-encrypt
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

package net.named_data.jndn.encrypt.algo;

import java.nio.ByteBuffer;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

/**
 * An EncryptParams holds an algorithm type and other parameters used to
 * encrypt and decrypt.
 * @note This class is an experimental feature. The API may change.
 */
public class EncryptParams {
  /**
   * Create an EncryptParams with the given parameters.
   * @param algorithmType The algorithm type, or null if not specified.
   * @param initialVectorLength The initial vector length, or 0 if the initial
   * vector is not specified.
   */
  public EncryptParams
    (EncryptAlgorithmType algorithmType, int initialVectorLength)
  {
    algorithmType_ = algorithmType;

    if (initialVectorLength > 0) {
      ByteBuffer initialVector = ByteBuffer.allocate(initialVectorLength);
      Common.getRandom().nextBytes(initialVector.array());
      initialVector_ = new Blob(initialVector, false);
    }
    else
      initialVector_ = new Blob();
  }

  /**
   * Create an EncryptParams with the given algorithmType and an unspecified
   * initial vector.
   * @param algorithmType The algorithm type, or null if not specified.
   */
  public EncryptParams(EncryptAlgorithmType algorithmType)
  {
    algorithmType_ = algorithmType;
    initialVector_ = new Blob();
  }

  /**
   * Get the algorithm type.
   * @return The algorithm type, or null if not specified.
   */
  public final EncryptAlgorithmType
  getAlgorithmType() { return algorithmType_; }

  /**
   * Get the initial vector.
   * @return The initial vector. If not specified, isNull() is true.
   */
  public final Blob
  getInitialVector() { return initialVector_; }

  /**
   * Set the algorithm type.
   * @param algorithmType The algorithm type. If not specified, set to null.
   * @return This EncryptParams so that you can chain calls to update values.
   */
  public final EncryptParams
  setAlgorithmType(EncryptAlgorithmType algorithmType)
  {
    algorithmType_ = algorithmType;
    return this;
  }

  /**
   * Set the initial vector.
   * @param initialVector The initial vector. If not specified, set to the
   * default Blob() where isNull() is true.
   * @return This EncryptParams so that you can chain calls to update values.
   */
  public final EncryptParams
  setInitialVector(Blob initialVector)
  {
    initialVector_ = (initialVector == null ? new Blob() : initialVector);
    return this;
  }

  private EncryptAlgorithmType algorithmType_;
  private Blob initialVector_;
}
