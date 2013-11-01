/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.util;

import java.nio.ByteBuffer;

/**
 * A Blob holds a pointer to an immutable ByteBuffer.  We use an immutable buffer so that it is OK to pass
 * the object into methods because the new or old  owner can’t change the bytes.  
 * Note that  the pointer to the ByteBuffer can be null.
 */
public class Blob {
  /**
   * Create a new Blob with a null pointer.
   */
  public Blob()
  {
    buffer_ = null;
  }

  /**
   * Create a new Blob and take another pointer to the given blob's buffer.
   * @param blob The Blob from which we take another pointer to the same buffer.
   */
  public Blob(Blob blob)
  {
    buffer_ = blob.buffer_;
  }
  
  /**
   * Create a new Blob from an existing ByteBuffer.  IMPORTANT: After calling this constructor,
   * if you keep a pointer to the buffer then you must treat it as immutable and promise not to change it.
   * @param buffer The existing ByteBuffer.  This calls buffer.slice(), so it is important that the buffer
   * position and limit are correct.
   */
  public Blob(ByteBuffer buffer)
  {
    buffer_ = buffer.slice();
  }
  
  /**
   * Return the read-only ByteBuffer using asReadOnlyBuffer(), or null if the pointer is null.
   */
  public ByteBuffer buf() 
  { 
    if (buffer_ != null)
      // We call asReadOnlyBuffer each time because it is still allowed to change the position and
      //   limit on a read-only buffer, and we don't want the caller to modify our buffer_.
      return buffer_.asReadOnlyBuffer(); 
    else
      return null;
  }
  
  /**
   * Return the length (limit) of the ByteBuffer, or 0 if the pointer is null.
   */
  public int size() 
  { 
    if (buffer_ != null)
      return buffer_.limit(); 
    else
      return 0;
  }
  
  /**
   * Return true if the buffer pointer is null.
   */
  public boolean isNull()
  {
    return buffer_ == null;
  }
  
  private ByteBuffer buffer_;
}
