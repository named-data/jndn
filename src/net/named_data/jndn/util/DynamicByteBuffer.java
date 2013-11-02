/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.util;

import java.nio.ByteBuffer;

public class DynamicByteBuffer {
  public DynamicByteBuffer(int initialCapacity) 
  {
    buffer_ = ByteBuffer.allocate(initialCapacity);
  }
   
  /**
   * Ensure that buffer().capacity() is greater than or equal to capacity.  If it is, just return.
   * Note that this does not copy the mark to the new buffer.
   * @param capacity 
   */
  public void ensureCapacity(int capacity)
  {
    if (buffer_.capacity() >= capacity)
      return;
    
    // See if double is enough.
    int newCapacity = buffer_.capacity() * 2;
    if (capacity > newCapacity)
      // The needed capacity is much greater, so use it.
      newCapacity = capacity;
    
    ByteBuffer newBuffer = ByteBuffer.allocate(newCapacity);
    // Save the position so we can reset before calling put.
    int savePosition = buffer_.position();
    buffer_.position(0);
    buffer_.limit(buffer_.capacity());
    newBuffer.put(buffer_);
    
    // Preserve the position and limit.
    newBuffer.position(savePosition);
    newBuffer.limit(newBuffer.capacity());
    
    buffer_ = newBuffer;
  }
  
  public ByteBuffer buffer() { return buffer_; }
  
  private ByteBuffer buffer_;       
}
