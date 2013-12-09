/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.encoding;

import java.nio.ByteBuffer;
import net.named_data.jndn.util.DynamicByteBuffer;
import net.named_data.jndn.util.Blob;

/**
 * A BinaryXmlEncoder holds an output buffer and has methods to output Binary XML.
 */
public class BinaryXmlEncoder {
  /**
   * Create a new BinaryXmlEncoder to use the DynamicByteBuffer output buffer.  The methods in the class update
   * output.position().  When done, call getOutput().
   * @param output The DynamicByteBuffer output buffer.
   */
  public 
  BinaryXmlEncoder(DynamicByteBuffer output)
  {
    output_ = output;
    initialPosition_ = output_.position();
  }

  /**
   * Create a new BinaryXmlEncoder with a default DynamicByteBuffer for the output buffer.  When done, call getOutput().
   */
  public 
  BinaryXmlEncoder()
  {
    output_ = new DynamicByteBuffer(16);
    initialPosition_ = output_.position();
  }

  /**
   * Get the current offset where the next data will be written in the output buffer.
   * @return The offset in the output buffer.
   */
  public final int
  getOffset()
  {
    return output_.position();
  }
  
  /**
   * Return a slice of the output buffer from the initial position up to the current position.
   * @return A ByteBuffer which shares the same underlying buffer with the output buffer.
   */
  public final ByteBuffer
  getOutput()
  {
    ByteBuffer tempBuffer = output_.buffer().duplicate();
    tempBuffer.position(initialPosition_);
    tempBuffer.limit(output_.position());
    return tempBuffer.slice();
  }
  
  public static final int ENCODING_LIMIT_1_BYTE = ((1 << BinaryXml.TT_VALUE_BITS) - 1);
  public static final int ENCODING_LIMIT_2_BYTES = ((1 << (BinaryXml.TT_VALUE_BITS + BinaryXml.REGULAR_VALUE_BITS)) - 1);
  public static final int ENCODING_LIMIT_3_BYTES = ((1 << (BinaryXml.TT_VALUE_BITS + 2 * BinaryXml.REGULAR_VALUE_BITS)) - 1);

  /**
   * Write an element start header using DTAG with the tag to the output buffer.
   * @param tag The DTAG tag.
   */
  public final void 
  writeElementStartDTag(int tag)
  {
    encodeTypeAndValue(BinaryXml.DTAG, tag);
  }
  
  /**
   * Write an element close to the output buffer.
   */
  public final void 
  writeElementClose()
  {
    output_.ensuredPut((byte)BinaryXml.CLOSE);
  }
  
  /**
   * Write a BLOB header, then the bytes of the blob value to the output buffer.
   * @param value A Blob with the buffer for the value.
   */
  public final void 
  writeBlob(Blob value)
  {
    encodeTypeAndValue(BinaryXml.BLOB, value.size());
    writeBuffer(value.buf());
  }
  
  /**
   * Write an element start header using DTAG with the tag to the output buffer, then the blob, then an element close.
   * (If you want to just write the blob, use writeBlob.)
   * @param tag The DTAG tag.
   * @param value A Blob with the buffer for the value.
   */
  public final void 
  writeBlobDTagElement(int tag, Blob value)
  {
    writeElementStartDTag(tag);
    writeBlob(value);
    writeElementClose();
  }
  
  /**
   * If value.buf() is null or value.size() is 0 then do nothing, otherwise call writeBlobDTagElement.
   * @param tag The DTAG tag.
   * @param value A Blob with the buffer for the value.
   */
  public final void
  writeOptionalBlobDTagElement(int tag, Blob value)
  {
    if (value.buf() != null && value.size() > 0)
      writeBlobDTagElement(tag, value);
  }
  
  /**
   * Write a UDATA header, then the bytes of the UDATA value to the output buffer.
   * @param value A Blob with the buffer for the value.
   */
  public final void
  writeUData(Blob value)
  {
    encodeTypeAndValue(BinaryXml.UDATA, value.size());
    writeBuffer(value.buf());
  }

  /**
   * Write an element start header using DTAG with the tag to the output buffer, then the UDATA value, then an element close.
   * (If you want to just write the UDATA value, use writeUData.)
   * @param tag The DTAG tag.
   * @param value A Blob with the buffer for the value.
   */
  public final void
  writeUDataDTagElement(int tag, Blob value)
  {
    writeElementStartDTag(tag);
    writeUData(value);
    writeElementClose();
  }

  /**
   * If value.buf() is null or value.size() is 0 then do nothing, otherwise call writeUDataDTagElement.
   * @param tag The DTAG tag.
   * @param value A Blob with the buffer for the value.
   */
  public final void
  writeOptionalUDataDTagElement(int tag, Blob value)
  {
    if (value.buf() != null && value.size() > 0)
      writeUDataDTagElement(tag, value);
  }
  
  /**
   * Write a UDATA header, then the value as an unsigned decimal integer.
   * @param value The unsigned integer.
   */
  public final void
  writeUnsignedDecimalInt(int value)
  {
    // First write the decimal int (to find out how many bytes it is), then shift it forward to make room for the header.
    int startPosition = output_.position();
    encodeReversedUnsignedDecimalInt(value);
    reverseBufferAndInsertHeader(startPosition, BinaryXml.UDATA);
  }

  /**
   * Write an element start header using DTAG with the tag to the output buffer, then the value as an unsigned decimal integer, 
   * then an element close.
   * (If you want to just write the integer, use writeUnsignedDecimalInt.)
   * @param tag The DTAG tag.
   * @param value The unsigned integer.
   */
  public final void
  writeUnsignedDecimalIntDTagElement(int tag, int value)
  {
    writeElementStartDTag(tag);
    writeUnsignedDecimalInt(value);
    writeElementClose();
  }
  
  /**
   * If value is negative then do nothing, otherwise call writeUnsignedDecimalIntDTagElement.
   * @param tag The DTAG tag.
   * @param value The unsigned integer.
   */
  public final void
  writeOptionalUnsignedDecimalIntDTagElement(int tag, int value)
  {
    if (value >= 0)
      writeUnsignedDecimalIntDTagElement(tag, value);
  }

  public final void
  writeAbsDoubleBigEndianBlob(double value)
  {
    // First encode the big endian backwards, then reverseBufferAndInsertHeader will reverse it.
    int startPosition = output_.position();

    // A Java long is 64 bits and can hold the bits of a 64 bit double.
    long int64 = (long)Math.round(Math.abs(value));
    while (int64 != 0) {
      output_.ensuredPut((byte)(int64 & 0xff));
      int64 >>= 8;
    }

    reverseBufferAndInsertHeader(startPosition, BinaryXml.BLOB);
  }
  
  /**
   * Write an element start header using DTAG with the tag to the output buffer, then the absolute value of milliseconds
   * as a big endian BLOB converted to 4096 ticks per second, then an element close.
   * (If you want to just write the integer, use writeUnsignedDecimalInt.)
   * @param tag The DTAG tag.
   * @param milliseconds The the number of milliseconds.
   */
  public final void
  writeTimeMillisecondsDTagElement(int tag, double milliseconds)
  {
    writeElementStartDTag(tag);
    writeAbsDoubleBigEndianBlob((milliseconds / 1000.0) * 4096.0);
    writeElementClose();
  }
  
  /**
   * If milliseconds is negative then do nothing, otherwise call writeTimeMillisecondsDTagElement.
   * @param tag The DTAG tag.
   * @param milliseconds The the number of milliseconds.
   */
  public final void
  writeOptionalTimeMillisecondsDTagElement(int tag, double milliseconds)
  {
    if (milliseconds >= 0)
      writeTimeMillisecondsDTagElement(tag, milliseconds);
  }
  
  /**
   * Encode a header with the type and value and write it to the output buffer.
   * @param type The the header type.
   * @param value The header value.
   */
  private void 
  encodeTypeAndValue(int type, int value)
  {
    if (type > BinaryXml.UDATA)
      // This should not happen since this is a private method and we use types from BinaryXml.
      throw new Error("Header type is out of range");

    // Encode backwards. Calculate how many bytes we need.
    int nEncodingBytes = getNHeaderEncodingBytes(value);
    output_.ensureRemainingCapacity(nEncodingBytes);

    // Bottom 4 bits of the value go in the last byte with the tag.
    output_.buffer().put
      (output_.position() + nEncodingBytes - 1, 
       (byte)((BinaryXml.TT_MASK & type | ((BinaryXml.TT_VALUE_MASK & value) << BinaryXml.TT_BITS)) |
              BinaryXml.TT_FINAL)); // set top bit for last byte
    value >>= BinaryXml.TT_VALUE_BITS;

    // The rest of the value goes into the preceding bytes, 7 bits per byte. (Zero top bit is the "more" flag.)
    int i = output_.position() + nEncodingBytes - 2;
    while (value != 0 && i >= output_.position()) {
      output_.buffer().put(i, (byte)(value & BinaryXml.REGULAR_VALUE_MASK));
      value >>= BinaryXml.REGULAR_VALUE_BITS;
      --i;
    }
    if (value != 0)
      // This should not happen if getNHeaderEncodingBytes is correct.
      throw new Error("EncodeTypeAndValue miscalculated N encoding bytes");

    output_.position(output_.position() + nEncodingBytes);
  }

  /**
   * Call output_.ensureRemainingCapacity to ensure that there is enough room in the output, and copy buffer
   *   from its position() to limit() to the output buffer.  This does NOT change buffer.position().
   * This does not write a header.
   * @param buffer The ByteBuffer to write.
   */
  private void 
  writeBuffer(ByteBuffer buffer)
  {
    output_.ensuredPut(buffer, buffer.position(), buffer.limit());
  }
  
  /**
   * Return the number of bytes to encode a header of value x.
   */
  private static int 
  getNHeaderEncodingBytes(int x) 
  {
    // Do a quick check for pre-compiled results.
    if (x <= ENCODING_LIMIT_1_BYTE) 
      return 1;
    if (x <= ENCODING_LIMIT_2_BYTES) 
      return 2;
    if (x <= ENCODING_LIMIT_3_BYTES) 
      return 3;
  
    int nBytes = 1;
  
    // Last byte gives you TT_VALUE_BITS.
    // Remainder each gives you REGULAR_VALUE_BITS.
    x >>= BinaryXml.TT_VALUE_BITS;
    while (x != 0) {
      ++nBytes;
      x >>= BinaryXml.REGULAR_VALUE_BITS;
    }
  
    return nBytes;
  }

  /**
   * Reverse length bytes in the buffer starting at startPosition.
   */
  private static void 
  reverse(ByteBuffer buffer, int startPosition, int length) 
  {
    if (length == 0)
      return;
  
    int left = startPosition;
    int right = startPosition + length - 1;
    while (left < right) {
      // Swap.
      byte temp = buffer.get(left);
      buffer.put(left, buffer.get(right));
      buffer.put(right, temp);
    
      ++left;
      --right;
    }
  }

  /**
   * Write x as an unsigned decimal integer to the output with the digits in reverse order, using output_ensureCapacity.
   * This does not write a header.
   * We encode in reverse order because this is the natural way to encode the digits, and the caller can reverse as needed.
   * @param x The unsigned integer to write.
   */
  private void 
  encodeReversedUnsignedDecimalInt(int x) 
  {
    if (x < 0)
      // Don't expect this to happen.
      x = 0;
    
    while (true) {
      output_.ensuredPut((byte)(x % 10 + '0'));
      x /= 10;
    
      if (x == 0)
        break;
    }
  }
  
  /**
   * Reverse the buffer in output_buffer() from startPosition to the current position, then shift it right by the amount 
   * needed to prefix a header with type, then encode the header at startPosition.
   * We reverse and shift in the same function to avoid unnecessary copying if we first reverse then shift.
   * @param startPosition The position in output_buffer() of the start of the buffer to shift right.
   * @param type The header type.
   */
  private void
  reverseBufferAndInsertHeader(int startPosition, int type)
  {
    int nBufferBytes = output_.position() - startPosition;
    int nHeaderBytes = getNHeaderEncodingBytes(nBufferBytes);
    output_.ensureRemainingCapacity(nHeaderBytes);

    // To reverse and shift at the same time, we first shift nHeaderBytes to the destination while reversing,
    //   then reverse the remaining bytes in place.
    int from = startPosition;
    int fromEnd = from + nHeaderBytes;
    int to = startPosition + nBufferBytes + nHeaderBytes - 1;
    while (from < fromEnd) {
      output_.buffer().put(to, output_.buffer().get(from));
      --to;
      ++from;
    }
    // Reverse the remaining bytes in place (if any).
    if (nBufferBytes > nHeaderBytes)
      reverse(output_.buffer(), startPosition + nHeaderBytes, nBufferBytes - nHeaderBytes);

    // Override the offset to force encodeTypeAndValue to encode at startOffset, then fix the offset.
    output_.position(startPosition);
    encodeTypeAndValue(type, nBufferBytes);
    output_.position(startPosition + nHeaderBytes + nBufferBytes);
  }
  
  private final DynamicByteBuffer output_;
  private final int initialPosition_;
}
