/**
 * Copyright (C) 2014 Regents of the University of California.
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

package net.named_data.jndn.util;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * The Common class has static utility functions.
 */
public class Common {
  /**
   * Get the current time in milliseconds.
   * @return  The current time in milliseconds since 1/1/1970, including 
   * fractions of a millisecond.
   */
  public static double
  getNowMilliseconds() { return (double)System.currentTimeMillis(); }
  
  /**
   * Compute the sha-256 digest of data.
   * @param data The input byte buffer. This does not change the position.
   * @return The digest.
   */
  public static byte[]
  digestSha256(ByteBuffer data)
  {
    MessageDigest sha256;
    try {
      sha256 = MessageDigest.getInstance("SHA-256");
    }
    catch (NoSuchAlgorithmException exception) {
      // Don't expect this to happen.
      throw new Error
        ("MessageDigest: SHA-256 is not supported: " + exception.getMessage());
    }
    int savePosition = data.position();
    sha256.update(data);
    data.position(savePosition);
    return sha256.digest();
  }
}
