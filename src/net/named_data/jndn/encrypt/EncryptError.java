/**
 * Copyright (C) 2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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

package net.named_data.jndn.encrypt;

/**
 * EncryptError holds the ErrorCode enum and OnError callback definition for
 * errors from the encrypt library.
 */
public class EncryptError {
  public enum ErrorCode {
    Timeout(1),
    Validation(2),
    UnsupportedEncryptionScheme(32),
    InvalidEncryptedFormat(33),
    NoDecryptKey(34),
    EncryptionFailure(35),
    SecurityException(100),
    IOException(102);

    ErrorCode (int type)
    {
      type_ = type;
    }

    public final int
    getNumericType() { return type_; }

    private final int type_;
  }

  /**
   * A method calls onError.onError(errorCode, message) for an error.
   */
  public interface OnError {
    void onError(ErrorCode errorCode, String message);
  }
}
