/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.util;

import java.nio.ByteBuffer;

/**
 * A DynamicByteBuffer maintains a ByteBuffer and provides methods to ensure a minimum capacity, resizing if necessary.
 */
public class DynamicByteBuffer {
  /**
   * Create a new DynamicByteBuffer with an initial capacity.
   * @param initialCapacity The initial capacity of buffer().
   */
  public 
  DynamicByteBuffer(int initialCapacity) 
  {
    buffer_ = ByteBuffer.allocate(initialCapacity);
  }
   
  /**
   * Ensure that buffer().capacity() is greater than or equal to capacity.  If it is, just set the limit to the capacity.
   * Otherwise, allocate a new buffer and copy everything from 0 to the position to the new buffer, set the same position
   * and set the limit to the new capacity.
   * Note that this does not copy the mark to the new buffer.
   * @param capacity The minimum needed capacity.
   */
  public void 
  ensureCapacity(int capacity)
  {
    if (buffer_.capacity() >= capacity) {
      // Make sure the limit stays at the capacity while we are writing.
      buffer_.limit(buffer_.capacity());
      return;
    }
    
    // See if double is enough.
    int newCapacity = buffer_.capacity() * 2;
    if (capacity > newCapacity)
      // The needed capacity is much greater, so use it.
      newCapacity = capacity;
    
    ByteBuffer newBuffer = ByteBuffer.allocate(newCapacity);
    // Save the position so we can reset before calling put.
    int savePosition = buffer_.position();
    buffer_.position(0);
    buffer_.limit(savePosition);
    newBuffer.put(buffer_);
    
    // Preserve the position and limit.
    newBuffer.position(savePosition);
    newBuffer.limit(newBuffer.capacity());
    
    buffer_ = newBuffer;
  }

  /**
   * Use ensureCapacity to ensure there are remainingCapacity bytes after position().
   * @param remainingCapacity The desired minimum capacity after position().
   */
  public void 
  ensureRemainingCapacity(int remainingCapacity) 
  { 
    ensureCapacity(buffer_.position() + remainingCapacity); 
  }
  
  /**
   * Call ensureCapacity to ensure there is capacity for 1 more byte and call buffer().put(b);
   * @param b The byte to put.
   */
  public void 
  ensuredPut(byte b)
  {
    ensureCapacity(buffer_.position() + 1);
    buffer_.put(b);
  }

  /**
   * Return the ByteBuffer.  Note that ensureCapacity can change the returned ByteBuffer. 
   * @return The ByteBuffer.
   */
  public ByteBuffer 
  buffer() { return buffer_; }

  /**
   * Return buffer_.position().
   * @return The position.
   */
  public int 
  position() { return buffer_.position(); }

  /**
   * Call buffer_.position(newPosition).
   * @param newPosition The new position.
   */
  public void 
  position(int newPosition) { buffer_.position(newPosition); }
  
  private ByteBuffer buffer_;       
}
