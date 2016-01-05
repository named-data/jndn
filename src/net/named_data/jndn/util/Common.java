/**
 * Copyright (C) 2014-2016 Regents of the University of California.
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

  /**
   * Return a hex string of the contents of buffer.
   * @param buffer The buffer.
   * @return A string of hex bytes.
   */
  public static String
  toHex(byte[] buffer)
  {
    StringBuffer output = new StringBuffer(buffer.length * 2);
    for (int i = 0; i < buffer.length; ++i) {
      String hex = Integer.toHexString((int)buffer[i] & 0xff);
      if (hex.length() <= 1)
        // Append the leading zero.
        output.append("0");
      output.append(hex);
    }

    return output.toString();
  }

  /**
   * Encode the input as base64 using the appropriate base64Converter_ from
   * establishBase64Converter(), for ANDROID or Java 7+.
   * @param input The bytes to encode.
   * @return The base64 string.
   * @throws UnsupportedOperationException If can't establish a base64 converter for
   * this platform.
   */
  public static String
  base64Encode(byte[] input)
  {
    establishBase64Converter();

    try {
      if (base64ConverterType_ == Base64ConverterType.ANDROID)
        // Base64.NO_WRAP  is 2.
        return (String)base64Converter_.getDeclaredMethod
          ("encodeToString", byte[].class, int.class).invoke(null, input, 2);
      else
        // Default to Base64ConverterType.JAVAX.
        return (String)base64Converter_.getDeclaredMethod
          ("printBase64Binary", byte[].class).invoke(null, input);
    } catch (Exception ex) {
      throw new UnsupportedOperationException("base64Encode: Error invoking method: " + ex);
    }
  }

  /**
   * Decode the input as base64 using the appropriate base64Converter_ from
   * establishBase64Converter(), for ANDROID or Java 7+.
   * @param encoding The base64 string.
   * @return The decoded bytes.
   * @throws UnsupportedOperationException If can't establish a base64 converter for
   * this platform.
   */
  public static byte[]
  base64Decode(String encoding) throws SecurityException
  {
    establishBase64Converter();

    try {
      if (base64ConverterType_ == Base64ConverterType.ANDROID)
        // Base64.DEFAULT is 0.
        return (byte[])base64Converter_.getDeclaredMethod
          ("decode", String.class, int.class).invoke(null, encoding, 0);
      else
        // Default to Base64ConverterType.JAVAX.
        return (byte[])base64Converter_.getDeclaredMethod
          ("parseBase64Binary", String.class).invoke(null, encoding);
    } catch (Exception ex) {
      throw new UnsupportedOperationException("base64Decode: Error invoking method: " + ex);
    }
  }

  /**
   * The practical limit of the size of a network-layer packet. If a packet is
   * larger than this, the library or application MAY drop it. This constant is
   * defined in this low-level class so that internal code can use it, but
   * applications should use the static API method
   * Face.getMaxNdnPacketSize() which is equivalent.
   */
  public static final int MAX_NDN_PACKET_SIZE = 8800;

  private enum Base64ConverterType {
    UNINITIALIZED, JAVAX, ANDROID, UNSUPPORTED
  }

  /**
   * If not already initialized, set base64Converter_ to the correct loaded
   * class and set base64ConverterType_ to the loaded type.
   * If base64ConverterType_ is UNINITIALIZED, set base64Converter_ to
   * the class for javax.xml.bind.DatatypeConverter and set
   * base64ConverterType_ to JAVAX.  Else try to set base64Converter_ to
   * the class for android.util.Base64 and set base64ConverterType_ to ANDROID.
   * If these fail, set base64ConverterType_ to UNSUPPORTED and throw an
   * UnsupportedOperationException from now on.
   */
  private static void
  establishBase64Converter()
  {
    if (base64ConverterType_ == Base64ConverterType.UNINITIALIZED) {
      try {
        base64Converter_ = Class.forName("javax.xml.bind.DatatypeConverter");
        base64ConverterType_ = Base64ConverterType.JAVAX;
        return;
      } catch (ClassNotFoundException ex) {}

      try {
        base64Converter_ = Class.forName("android.util.Base64");
        base64ConverterType_ = Base64ConverterType.ANDROID;
        return;
      } catch (ClassNotFoundException ex) {}

      base64ConverterType_ = Base64ConverterType.UNSUPPORTED;
    }

   if (base64ConverterType_ == Base64ConverterType.UNSUPPORTED)
      throw new UnsupportedOperationException
        ("Common.establishBase64Converter: Cannot load a Base64 converter");
  }

  private static Base64ConverterType base64ConverterType_ = Base64ConverterType.UNINITIALIZED;
  private static Class base64Converter_ = null;
}
