/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.util;

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
   * Get a byte array by calling ByteBuffer.array().  This is called 
   * immutableArray to remind you not to change the contents of the returned 
   * array.  This method is necessary because the read-only ByteBuffer 
   * returned by buf()  doesn't allow you to call array().
   * @return A byte array which you should not modify, or null if the pointer 
   * is null.
   */
  public final byte[] 
  getImmutableArray() 
  { 
    if (buffer_ != null)
      return buffer_.array(); 
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
      String hex = Integer.toHexString((int)buffer.get(i) & 0xff).toUpperCase();
      if (hex.length() <= 1)
        // Append the leading zero.
        output.append("0");
      output.append(hex);
    }
    
    return output.toString();
  }

  public boolean equals(Object other)
  {
    if (!(other instanceof Blob))
      return false;
    
    if (buffer_ == null)
      return ((Blob)other).buffer_ == null;
    else
      return buffer_.equals(((Blob)other).buffer_);
  }
  
  private final ByteBuffer buffer_;
}
