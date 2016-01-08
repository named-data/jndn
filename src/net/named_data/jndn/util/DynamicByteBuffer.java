/**
 * Copyright (C) 2013-2016 Regents of the University of California.
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

/**
 * A DynamicByteBuffer maintains a ByteBuffer and provides methods to ensure a
 * minimum capacity, resizing if necessary.
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
   * Ensure that buffer().capacity() is greater than or equal to capacity.  If
   * it is, just set the limit to the capacity.
   * Otherwise, allocate a new buffer and copy everything from 0 to the position
   * to the new buffer, set the same position and set the limit to the new
   * capacity.
   * Note that this does not copy the mark to the new buffer.
   * @param capacity The minimum needed capacity.
   */
  public final void
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
    buffer_.flip();
    newBuffer.put(buffer_);

    // Preserve the position and limit.
    newBuffer.position(savePosition);
    newBuffer.limit(newBuffer.capacity());

    buffer_ = newBuffer;
  }

  /**
   * Use ensureCapacity to ensure there are remainingCapacity bytes after
   * position().
   * @param remainingCapacity The desired minimum capacity after position().
   */
  public final void
  ensureRemainingCapacity(int remainingCapacity)
  {
    ensureCapacity(buffer_.position() + remainingCapacity);
  }

  /**
   * Call ensureCapacity to ensure there is capacity for 1 more byte and call
   * buffer().put(b).
   * This increments the position by 1.
   * @param b The byte to put.
   */
  public final void
  ensuredPut(byte b)
  {
    ensureCapacity(buffer_.position() + 1);
    buffer_.put(b);
  }

  /**
   * Call ensureCapacity to ensure there is capacity for buffer.remaining() more
   * bytes and use buffer().put to copy.
   * This increments the position by buffer.remaining().
   * This does update buffer's position to its limit.
   * @param buffer The buffer to copy from.  This does not change
   * buffer.position() or buffer.limit().
   */
  public final void
  ensuredPut(ByteBuffer buffer)
  {
    ensureRemainingCapacity(buffer.remaining());
    int savePosition = buffer.position();
    buffer_.put(buffer);
    buffer.position(savePosition);
  }

  /**
   * Call ensureCapacity to ensure there is capacity for (limit - position) more
   * bytes and use buffer().put to copy.
   * This increments the position by (limit - position).
   * @param buffer The buffer to copy from.  This does not change
   * buffer.position() or buffer.limit().
   * @param position The position in buffer to copy from.
   * @param limit The limit in buffer to copy from.
   */
  public final void
  ensuredPut(ByteBuffer buffer, int position, int limit)
  {
    ensureRemainingCapacity(limit - position);
    int savePosition = buffer.position();
    int saveLimit = buffer.limit();
    try {
      buffer.position(position);
      buffer.limit(limit);
      buffer_.put(buffer);
    }
    finally {
      // put updates buffer's position and limit, so restore.
      buffer.position(savePosition);
      buffer.limit(saveLimit);
    }
  }

  /**
   * Ensure that buffer().capacity() is greater than or equal to capacity.  If
   * it is, just set the limit to the capacity.
   * Otherwise, allocate a new buffer and copy everything from the position to
   * the limit to the back of the new buffer, set the limit to the new capacity
   * and set the position to keep the same number of remaining bytes.
   * Note that this does not copy the mark to the new buffer.
   * @param capacity The minimum needed capacity.
   */
  public final void
  ensureCapacityFromBack(int capacity)
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
    // Save the remaining so we can restore the position later.
    int saveRemaining = buffer_.remaining();
    newBuffer.position(newBuffer.capacity() - saveRemaining);
    newBuffer.put(buffer_);

    // The limit is still at capacity().  Set the position.
    newBuffer.position(newBuffer.capacity() - saveRemaining);

    buffer_ = newBuffer;
  }

  /**
   * Change the position so that there are remaining bytes in the buffer. If
   * position would be negative, use ensureCapacityFromBack to expand the
   * buffer.
   * @param remaining The desired remaining bytes which causes the position
   * to be changed.
   * @return The new position.
   */
  public final int
  setRemainingFromBack(int remaining)
  {
    ensureCapacityFromBack(remaining);
    buffer_.position(buffer_.limit() - remaining);
    return buffer_.position();
  }

 /**
   * Call setRemainingFromBack to ensure there are remaining bytes for 1 more
   * byte and put b at the new position.
   * @param b The byte to put.
   */
  public final void
  ensuredPutFromBack(byte b)
  {
    buffer_.put(setRemainingFromBack(buffer_.remaining() + 1), b);
  }

  /**
   * Return the ByteBuffer.  Note that ensureCapacity can change the returned
   * ByteBuffer.
   * @return The ByteBuffer.
   */
  public final ByteBuffer
  buffer() { return buffer_; }

  /**
   * Return a new ByteBuffer which is the flipped version of buffer().  The
   * returned buffer's position is 0 and its
   * limit is position().
   * @return A new ByteBuffer
   */
  public final ByteBuffer
  flippedBuffer()
  {
    ByteBuffer result = buffer_.duplicate();
    result.flip();
    return result;
  }

  /**
   * Return buffer_.position().
   * @return The position.
   */
  public final int
  position() { return buffer_.position(); }

  /**
   * Call buffer_.position(newPosition).
   * @param newPosition The new position.
   */
  public final void
  position(int newPosition) { buffer_.position(newPosition); }

  /**
   * Return buffer_.limit().
   * @return The limit.
   */
  public final int
  limit() { return buffer_.limit(); }

  /**
   * Return buffer_.remaining().
   * @return The number of remaining bytes.
   */
  public final int
  remaining() { return buffer_.remaining(); }

  private ByteBuffer buffer_;
}
