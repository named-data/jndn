/**
 * Copyright (C) 2014-2018 Regents of the University of California.
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

package net.named_data.jndn.encoding.tlv;

import java.nio.ByteBuffer;
import net.named_data.jndn.util.DynamicByteBuffer;

/**
 * A TlvEncoder holds an output buffer and has methods to output NDN-TLV.
 */
public class TlvEncoder {
  /**
   * Create a new TlvEncoder to use a DynamicByteBuffer with the initialCapacity.
   * When done, you should call getOutput().
   * @param initialCapacity The initial capacity of buffer().
   */
  public
  TlvEncoder(int initialCapacity)
  {
    output_ = new DynamicByteBuffer(initialCapacity);
    // We will start encoding from the back.
    output_.position(output_.limit());
  }

  /**
   * Create a new TlvEncoder with a default DynamicByteBuffer.
   * When done, you should call getOutput().
   */
  public
  TlvEncoder()
  {
    output_ = new DynamicByteBuffer(16);
    // We will start encoding from the back.
    output_.position(output_.limit());
  }

  /**
   * Get the number of bytes that have been written to the output.  You can
   * save this number, write sub TLVs, then subtract the new length from this
   * to get the total length of the sub TLVs.
   * @return The number of bytes that have been written to the output.
   */
  public final int
  getLength()
  {
    return output_.remaining();
  }

  /**
   * Encode varNumber as a VAR-NUMBER in NDN-TLV and write it to the output just
   * before getLength() from the back.  Advance getLength().
   * @param varNumber The non-negative number to encode. This is a Java 32-bit
   * int, so this does not support encoding a 64-bit VAR-NUMBER.
   */
  public final void
  writeVarNumber(int varNumber)
  {
    if (varNumber < 253) {
      int position = output_.setRemainingFromBack(output_.remaining() + 1);
      output_.buffer().put(position, (byte)(varNumber & 0xff));
    }
    else if (varNumber <= 0xffff) {
      int position = output_.setRemainingFromBack(output_.remaining() + 3);
      output_.buffer().put(position, (byte)253);
      output_.buffer().put(position + 1, (byte)((varNumber >> 8) & 0xff));
      output_.buffer().put(position + 2, (byte)(varNumber & 0xff));
    }
    else {
      // A Java int is 32 bits so ignore a 64-bit VAR-NUMBER.
      int position = output_.setRemainingFromBack(output_.remaining() + 5);
      output_.buffer().put(position, (byte)254);
      output_.buffer().put(position + 1, (byte)((varNumber >> 24) & 0xff));
      output_.buffer().put(position + 2, (byte)((varNumber >> 16) & 0xff));
      output_.buffer().put(position + 3, (byte)((varNumber >> 8) & 0xff));
      output_.buffer().put(position + 4, (byte)(varNumber & 0xff));
    }
  }

  /**
   * Encode the type and length as VAR-NUMBER and write to the output just
   * before getLength() from the back.  Advance getLength().
   * @param type The type of the TLV. This is a Java 32-bit int, so this does
   * not support encoding a 64-bit type code.
   * @param length The non-negative length of the TLV. This is a Java 32-bit
   * int, so this does not support encoding a 64-bit length.
   */
  public final void
  writeTypeAndLength(int type, int length)
  {
    // Write backwards.
    writeVarNumber(length);
    writeVarNumber(type);
  }

  /**
   * Encode value as a non-negative integer and write it to the output just
   * before getLength() from  the back. Advance getLength(). This does not write
   * a type or length for the value.
   * @param value The non-negative integer to encode. This is a Java 64-bit
   * long, so encoding of 64-bit values is supported (actually 63-bit because
   * a Java long is signed).
   * @throws Error if the value is negative.
   */
  public final void
  writeNonNegativeInteger(long value)
  {
    if (value < 0)
      throw new Error("TLV integer value may not be negative");

    // Write backwards.
    if (value <= 0xffL) {
      int position = output_.setRemainingFromBack(output_.remaining() + 1);
      output_.buffer().put(position, (byte)(value & 0xff));
    }
    else if (value <= 0xffffL) {
      int position = output_.setRemainingFromBack(output_.remaining() + 2);
      output_.buffer().put(position,     (byte)((value >> 8) & 0xff));
      output_.buffer().put(position + 1, (byte)(value & 0xff));
    }
    else if (value <= 0xffffffffL) {
      int position = output_.setRemainingFromBack(output_.remaining() + 4);
      output_.buffer().put(position,     (byte)((value >> 24) & 0xff));
      output_.buffer().put(position + 1, (byte)((value >> 16) & 0xff));
      output_.buffer().put(position + 2, (byte)((value >> 8) & 0xff));
      output_.buffer().put(position + 3, (byte)(value & 0xff));
    }
    else {
      int position = output_.setRemainingFromBack(output_.remaining() + 8);
      output_.buffer().put(position,     (byte)((value >> 56) & 0xff));
      output_.buffer().put(position + 1, (byte)((value >> 48) & 0xff));
      output_.buffer().put(position + 2, (byte)((value >> 40) & 0xff));
      output_.buffer().put(position + 3, (byte)((value >> 32) & 0xff));
      output_.buffer().put(position + 4, (byte)((value >> 24) & 0xff));
      output_.buffer().put(position + 5, (byte)((value >> 16) & 0xff));
      output_.buffer().put(position + 6, (byte)((value >> 8) & 0xff));
      output_.buffer().put(position + 7, (byte)(value & 0xff));
    }
  }

  /**
   * Write the type, then the length of the encoded value then encode value as a
   * non-negative integer and write it to the output just before getLength()
   * from  the back. Advance getLength().
   * @param type The type of the TLV. This is a Java 32-bit int, so this does
   * not support encoding a 64-bit type code.
   * @param value The non-negative integer to encode. This is a Java 64-bit
   * long, so encoding of 64-bit values is supported (actually 63-bit because
   * a Java long is signed).
   * @throws Error if the value is negative.
   */
  public final void
  writeNonNegativeIntegerTlv(int type, long value)
  {
    // Write backwards.
    int saveNBytes = output_.remaining();
    writeNonNegativeInteger(value);
    writeTypeAndLength(type, output_.remaining() - saveNBytes);
  }

  /**
   * If value is negative or null then do nothing, otherwise call
   * writeNonNegativeIntegerTlv.
   * @param type The type of the TLV. This is a Java 32-bit int, so this does
   * not support encoding a 64-bit type code.
   * @param value If negative do nothing, otherwise the integer to encode. This
   * is a Java 64-bit long, so encoding of 64-bit values is supported (actually
   * 63-bit because a Java long is signed).
   */
  public final void
  writeOptionalNonNegativeIntegerTlv(int type, long value)
  {
    if (value >= 0)
      writeNonNegativeIntegerTlv(type, value);
  }

  /**
   * If value is negative or null then do nothing, otherwise call
   * writeNonNegativeIntegerTlv.
   * @param type The type of the TLV. This is a Java 32-bit int, so this does
   * not support encoding a 64-bit type code.
   * @param value If negative do nothing, otherwise use (long)Math.round(value).
   */
  public final void
  writeOptionalNonNegativeIntegerTlvFromDouble(int type, double value)
  {
    if (value >= 0.0)
      writeNonNegativeIntegerTlv(type, (long)Math.round(value));
  }

  /**
   * Write the buffer from its position() to limit() to the output just
   * before getLength() from the back. Advance getLength() of the output. This
   * does NOT change buffer.position(). Note that this does not encode a type
   * and length; for that see writeBlobTlv.
   * @param buffer The byte buffer with the bytes to write. If buffer is null,
   * then do nothing.
   */
  public final void
  writeBuffer(ByteBuffer buffer)
  {
    if (buffer == null)
      return;

    // Write backwards.
    int position = output_.setRemainingFromBack
      (output_.remaining() + buffer.remaining());
    int saveBufferValuePosition = buffer.position();
    output_.buffer().put(buffer);
    // Restore positions after put.
    output_.position(position);
    buffer.position(saveBufferValuePosition);
  }

  /**
   * Write the type, then the length of the buffer then the buffer value from
   * its position() to limit() to the output just before getLength() from the
   * back. Advance getLength() of the output. This does NOT change
   * value.position().
   * @param type The type of the TLV. This is a Java 32-bit int, so this does
   * not support encoding a 64-bit type code.
   * @param value The byte buffer with the bytes of the blob.  If value is null,
   * then just write the type and length 0.
   */
  public final void
  writeBlobTlv(int type, ByteBuffer value)
  {
    if (value == null) {
      writeTypeAndLength(type, 0);
      return;
    }

    // Write backwards.
    writeBuffer(value);
    writeTypeAndLength(type, value.remaining());
  }

  /**
   * If the byte buffer value is null or value.remaining() is zero then do
   * nothing, otherwise call writeBlobTlv.
   * @param type The type of the TLV. This is a Java 32-bit int, so this does
   * not support encoding a 64-bit type code.
   * @param value If null or value.remaining() is zero do nothing, otherwise
   * the buffer with the bytes of the blob.
   */
  public final void
  writeOptionalBlobTlv(int type, ByteBuffer value)
  {
    if (value != null && value.remaining() > 0)
      writeBlobTlv(type, value);
  }

  /**
   * Return a slice of the output buffer up to the current length of the output
   * encoding.
   * @return A ByteBuffer which shares the same underlying buffer with the
   * output buffer.
   */
  public final ByteBuffer
  getOutput()
  {
    // The output buffer position is already at the beginning of the encoding.
    return output_.buffer().slice();
  }

  private final DynamicByteBuffer output_;
}
