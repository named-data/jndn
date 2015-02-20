/**
 * Copyright (C) 2013-2015 Regents of the University of California.
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

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;

/**
 * A Blob holds a pointer to an immutable ByteBuffer.  We use an immutable
 * buffer so that it is OK to pass the object into methods because the new or
 * old owner can’t change the bytes.
 * Note that  the pointer to the ByteBuffer can be null.
 */
public class Blob {
  /**
   * Create a new Blob with a null pointer.
   */
  public
  Blob()
  {
    buffer_ = null;
  }

  /**
   * Create a new Blob and take another pointer to the given blob's buffer.
   * @param blob The Blob from which we take another pointer to the same buffer.
   */
  public
  Blob(Blob blob)
  {
    if (blob != null)
      buffer_ = blob.buffer_;
    else
      buffer_ = null;
  }

  /**
   * Create a new Blob from an existing ByteBuffer.  IMPORTANT: If copy is
   * false, after calling this constructor, if you keep a pointer to the buffer
   * then you must treat it as immutable and promise not to change it.
   * @param buffer The existing ByteBuffer.  It is important that the buffer
   * position and limit are correct.
   * @param copy If true, copy the contents into a new byte array.  If false,
   * just take a slice which uses the existing byte array in buffer.
   */
  public
  Blob(ByteBuffer buffer, boolean copy)
  {
    if (buffer != null) {
      if (copy) {
        buffer_ = ByteBuffer.allocate(buffer.remaining());

        // Put updates buffer.position(), so save and restore it.
        int savePosition = buffer.position();
        buffer_.put(buffer);
        buffer.position(savePosition);

        buffer_.flip();
      }
      else
        buffer_ = buffer.slice();
    }
    else
      buffer_ = null;
  }

  /**
   * Create a new Blob with a copy of the bytes in the array.
   * @param value The byte array to copy.
   */
  public
  Blob(byte[] value)
  {
    buffer_ = ByteBuffer.allocate(value.length);
    buffer_.put(value);
    buffer_.flip();
  }

  /**
   * Create a new Blob with a copy of the bytes in the array.
   * @param value The array of integer to copy where each integer is in
   * the range 0 to 255.
   */
  public
  Blob(int[] value)
  {
    buffer_ = ByteBuffer.allocate(value.length);
    for (int i = 0; i < value.length; ++i)
      buffer_.put((byte)value[i]);
    buffer_.flip();
  }

  /**
   * Create a new Blob from the UTF-8 encoding of the Unicode string.
   * @param value The Unicode string which is encoded as UTF-8.
   */
  public
  Blob(String value)
  {
    byte[] utf8;
    try {
      utf8 = value.getBytes("UTF-8");
    } catch (UnsupportedEncodingException ex) {
      // We don't expect this to happen.
      throw new Error("UTF-8 encoder not supported: " + ex.getMessage());
    }
    buffer_ = ByteBuffer.allocate(utf8.length);
    buffer_.put(utf8);
    buffer_.flip();
  }

  /**
   * Get the read-only ByteBuffer.
   * @return The read-only ByteBuffer using asReadOnlyBuffer(), or null if the
   * pointer is null.
   */
  public final ByteBuffer
  buf()
  {
    if (buffer_ != null)
      // We call asReadOnlyBuffer each time because it is still allowed to
      //   change the position and limit on a read-only buffer, and we don't
      //   want the caller to modify our buffer_.
      return buffer_.asReadOnlyBuffer();
    else
      return null;
  }

  /**
   * Get a byte array by calling ByteBuffer.array() if possible (because the
   * ByteBuffer slice covers the entire backing array). Otherwise return byte
   * array as a copy of the ByteBuffer. This is called immutableArray to remind
   * you not to change the contents of the returned array. This method is
   * necessary because the read-only ByteBuffer returned by buf() doesn't allow
   * you to call array().
   * @return A byte array which you should not modify, or null if the pointer
   * is null.
   */
  public final byte[]
  getImmutableArray()
  {
    if (buffer_ != null) {
      // We can't call array() on a read only ByteBuffer.
      if (!buffer_.isReadOnly()) {
        byte[] array =  buffer_.array();
        if (array.length == buffer_.remaining())
          // Assume the buffer_ covers the entire backing array, so just return.
          return array;
      }

      // We have to copy to a new byte array.
      ByteBuffer tempBuffer = ByteBuffer.allocate(buffer_.remaining());
      int savePosition = buffer_.position();
      tempBuffer.put(buffer_);
      buffer_.position(savePosition);
      tempBuffer.flip();
      return tempBuffer.array();
    }
    else
      return null;
  }

  /**
   * Get the size of the buffer.
   * @return The length (remaining) of the ByteBuffer, or 0 if the pointer is
   * null.
   */
  public final int
  size()
  {
    if (buffer_ != null)
      return buffer_.remaining();
    else
      return 0;
  }

  /**
   * Check if the buffer pointer is null.
   * @return True if the buffer pointer is null, otherwise false.
   */
  public final boolean
  isNull()
  {
    return buffer_ == null;
  }

  /**
   * Return a hex string of buf() from position to limit.
   * @return A string of hex bytes, or "" if the buffer is null.
   */
  public final String
  toHex()
  {
    if (buffer_ == null)
      return "";
    else
      return toHex(buffer_);
  }

  /**
   * Return a hex string of the contents of buffer from position to limit.
   * @param buffer The buffer.
   * @return A string of hex bytes.
   */
  public static String
  toHex(ByteBuffer buffer)
  {
    StringBuffer output = new StringBuffer(buffer.remaining() * 2);
    for (int i = buffer.position(); i < buffer.limit(); ++i) {
      String hex = Integer.toHexString((int)buffer.get(i) & 0xff);
      if (hex.length() <= 1)
        // Append the leading zero.
        output.append("0");
      output.append(hex);
    }

    return output.toString();
  }

  public final boolean equals(Blob other)
  {
    if (buffer_ == null)
      return other.buffer_ == null;
    else if (other.isNull())
      return false;
    else
      return buffer_.equals(other.buffer_);
  }

  public boolean equals(Object other)
  {
    if (!(other instanceof Blob))
      return false;

    return equals((Blob)other);
  }

  /**
   * Decode the byte array as UTF8 and return the Unicode string.
   * @return A unicode string, or "" if the buffer is null.
   */
  public final String
  toString()
  {
    if (buffer_ == null)
      return "";
    else {
      try {
        return new String(buffer_.array(), "UTF-8");
      } catch (UnsupportedEncodingException ex) {
        // We don't expect this to happen.
        throw new Error("UTF-8 decoder not supported: " + ex.getMessage());
      }
    }
  }

  private final ByteBuffer buffer_;
}
