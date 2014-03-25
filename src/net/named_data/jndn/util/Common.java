/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
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
   * @param data The input byte buffer.
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
    sha256.update(data);
    return sha256.digest();
  }
}
