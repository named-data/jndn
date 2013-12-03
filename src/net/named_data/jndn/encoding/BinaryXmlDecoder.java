/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.encoding;

import java.nio.ByteBuffer;

/**
 * A BinaryXmlDecoder has methods to decode an input according to Binary XML.
 */
public class BinaryXmlDecoder {
  /**
   * Create a new BinaryXmlDecoder to decode the input.
   * @param input The input ByteBuffer whose position and limit are set to the desired bytes to decode.  
   * This calls input.duplicate(), but does not copy the underlying buffer whose contents must remain valid during 
   * the life of this object.
   */
  public 
  BinaryXmlDecoder(ByteBuffer input)
  {
    input_ = input.duplicate();        
  }
  
  public class TypeAndValue {
    public 
    TypeAndValue(int type, int value)
    {
      type_ = type;
      value_ = value;
    }
    
    int 
    getType() { return type_; }
    
    int 
    getValue() { return value_; }
    
    private int type_;
    private int value_;
  }
  
  /**
   * Decode the header's type and value from the input starting at its position. Update the input's position.
   * @return a TypeAndValue with the header's type and value
   * @throws EncodingException For invalid encoding including if the first head octet is zero.
   */
  public TypeAndValue
  decodeTypeAndValue() throws EncodingException
  {
    int value = 0;
    boolean gotFirstOctet = false;

    while (true) {
      int octet = (int)input_.get();

      if (!gotFirstOctet) {
        if (octet == 0)
          throw new EncodingException("The first header octet may not be zero");

        gotFirstOctet = true;
      }

      if ((octet & BinaryXml.TT_FINAL) != 0) {
        // Finished.
        value = (value << BinaryXml.TT_VALUE_BITS) | ((octet >> BinaryXml.TT_BITS) & BinaryXml.TT_VALUE_MASK);
        return new TypeAndValue(octet & BinaryXml.TT_MASK, value);
      }

      value = (value << BinaryXml.REGULAR_VALUE_BITS) | (octet & BinaryXml.REGULAR_VALUE_MASK);    
    }
  }
  
  /**
   * Decode the header from the input starting at its position, expecting the type to be DTAG and the value to be expectedTag.
   * Update the input's position.
   * @param expectedTag The expected value for DTAG.
   * @throws EncodingException For invalid encoding including if did not get the expected DTAG.
   */
  public final void
  readElementStartDTag(int expectedTag) throws EncodingException
  {
    TypeAndValue typeAndValue = decodeTypeAndValue();
    if (typeAndValue.getType() != BinaryXml.DTAG)
      throw new EncodingException("Header type is not a DTAG");

    if (typeAndValue.getValue() != expectedTag)
      throw new EncodingException("Did not get the expected DTAG " + expectedTag + ", got " + typeAndValue.getValue());
  }

  /**
   * Read one byte from the input starting at its position, expecting it to be the element close.
   * Update the input's position.
   * @throws EncodingException For invalid encoding including if did not get the expected element close.
   */
  public final void
  readElementClose() throws EncodingException
  {
    if (input_.get() != BinaryXml.CLOSE)
      throw new EncodingException("Did not get the expected element close");
  }
  
  /**
   * Decode the header from the input starting at its position, and if it is a DTAG where the value is the expectedTag,
   * then set return true.  Do not update the input's position.
   * @param expectedTag The expected value for DTAG.
   * @return True if the tag is the expected tag, otherwise false.
   * @throws EncodingException For invalid encoding including if did not get the expected DTAG.
   */
  public final boolean
  peekDTag(int expectedTag) throws EncodingException
  {
    // First check if it is an element close (which cannot be the expected tag).  
    if (input_.get(input_.position()) == BinaryXml.CLOSE)
      return false;

    int savePosition = input_.position();
    TypeAndValue typeAndValue = decodeTypeAndValue();
    // Restore the position.
    input_.position(savePosition);

    return typeAndValue.getType() == BinaryXml.DTAG && typeAndValue.getValue() == expectedTag;
  }
  
  /**
   * Decode the header from the input starting its position, expecting the type to be DTAG and the value to be expectedTag.
   * Then read one item of any type (presumably BLOB, UDATA, TAG or ATTR) and return a 
   * ByteBuffer. However, if allowNull is true, then the item may be absent.
   * Finally, read the element close.  Update the input's position.
   * @param expectedTag The expected value for DTAG.
   * @param allowNull True if the binary item may be missing.
   * @return a ByteBuffer which is a slice on the data inside the input buffer. However, 
   * if allowNull is true and the binary data item is absent, then return null.
   * @throws EncodingException For invalid encoding including if did not get the expected DTAG.
   */
  public final ByteBuffer
  readBinaryDTagElement(int expectedTag, boolean allowNull) throws EncodingException
  {
    readElementStartDTag(expectedTag);
    if (allowNull) {
      if (input_.get(input_.position()) == BinaryXml.CLOSE) {
        // The binary item is missing, and this is allowed, so read the element close and return a null value.
        input_.get();
        return null;
      }
    }

    TypeAndValue typeAndValue = decodeTypeAndValue();
    // Ignore the type.
    // Temporarily set the limit so we can call slice.
    int saveLimit = input_.limit();
    input_.limit(input_.position() + typeAndValue.getValue());
    ByteBuffer result = input_.slice();
    input_.limit(saveLimit);
    input_.position(input_.position() + typeAndValue.getValue());

    readElementClose();

    return result;
  }

  /**
   * Peek at the next element and if it is the expectedTag, call readBinaryDTagElement.
   * Otherwise, return null.
   * @param expectedTag The expected value for DTAG.
   * @param allowNull True if the binary item may be missing.
   * @return a ByteBuffer which is a slice on the data inside the input buffer. However, 
   * if the next element is not the expectedTag, or allowNull is true and the binary data 
   * item is absent, then return null.
   * @throws EncodingException For invalid encoding.
   */
  public final ByteBuffer
  readOptionalBinaryDTagElement(int expectedTag, boolean allowNull) throws EncodingException
  {
    if (peekDTag(expectedTag))
      return readBinaryDTagElement(expectedTag, allowNull);
    else
      return null;
  }

  /**
   * Decode the header from the input starting at its position, expecting the type to be 
   * DTAG and the value to be expectedTag.  Then read one item expecting it to be type 
   * UDATA, and return a ByteBuffer.  Finally, read the element close.  
   * Update the input's position.
   * @param expectedTag The expected value for DTAG.
   * @return a ByteBuffer which is a slice on the data inside the input buffer.
   * @throws EncodingException For invalid encoding including if did not get the expected DTAG.
   */
  public final ByteBuffer
  readUDataDTagElement(int expectedTag) throws EncodingException
  {
    readElementStartDTag(expectedTag);

    TypeAndValue typeAndValue = decodeTypeAndValue();
    if (typeAndValue.getType() != BinaryXml.UDATA)
      throw new EncodingException("The item is not UDATA");

    // Temporarily set the limit so we can call slice.
    int saveLimit = input_.limit();
    input_.limit(input_.position() + typeAndValue.getValue());
    ByteBuffer result = input_.slice();
    input_.limit(saveLimit);
    input_.position(input_.position() + typeAndValue.getValue());

    readElementClose();

    return result;
  }
  
  /**
   * Peek at the next element and if it is the expectedTag, call readUDataDTagElement.
   * Otherwise, return null.
   * @param expectedTag The expected value for DTAG.
   * @return a ByteBuffer which is a slice on the data inside the input buffer. However, 
   * if the next element is not the expectedTag, return null.
   * @throws EncodingException For invalid encoding.
   */
  public final ByteBuffer
  readOptionalUDataDTagElement(int expectedTag) throws EncodingException
  {
    if (peekDTag(expectedTag))
      return readUDataDTagElement(expectedTag);
    else
      return null;
  }

  /**
   * Decode the header from the input starting at its position, expecting the type to be 
   * DTAG and the value to be expectedTag.  Then read one item expecting it to be type 
   * UDATA, parse it as an unsigned decimal integer and return the integer.
   * Finally, read the element close. Update the input's position.
   * @param expectedTag The expected value for DTAG.
   * @return The parsed integer.
   * @throws EncodingException For invalid encoding including if did not get the expected 
   * DTAG or can't parse the decimal integer.
   */
  public final int
  readUnsignedIntegerDTagElement(int expectedTag) throws EncodingException
  {
    return parseUnsignedDecimalInt(readUDataDTagElement(expectedTag));
  }

  /**
   * Peek at the next element, and if it has the expectedTag then call readUnsignedIntegerDTagElement.
   * Otherwise, return -1.
   * @param expectedTag The expected value for DTAG.
   * @return The parsed integer, or -1 if the next element doesn't have expectedTag.
   * @throws EncodingException For invalid encoding including if can't parse the 
   * decimal integer.
   */
  public final int
  readOptionalUnsignedIntegerDTagElement(int expectedTag) throws EncodingException
  {
    if (peekDTag(expectedTag))
      return readUnsignedIntegerDTagElement(expectedTag);
    else
      return -1;
  }

  /**
   * Decode the header from the input starting at its position, expecting the type to be 
   * DTAG and the value to be expectedTag.  Then read one item, parse it as an unsigned 
   * big endian integer in 4096 ticks per second, and convert it to milliseconds.
   * Finally, read the element close.  Update the input's position.
   * @param expectedTag The expected value for DTAG.
   * @return The number of milliseconds.
   * @throws EncodingException For invalid encoding including if did not get the expected DTAG.
   */
  public final double
  readTimeMillisecondsDTagElement(int expectedTag) throws EncodingException
  {
    return 1000.0 * unsignedBigEndianToDouble
      (readBinaryDTagElement(expectedTag, false)) / 4096.0;
  }
  
  /**
   * Peek at the next element, and if it has the expectedTag then call 
   * readTimeMillisecondsDTagElement. Otherwise, return -1.0 .
   * @param expectedTag The expected value for DTAG.
   * @return The number of milliseconds, or -1.0 if the next element doesn't have expectedTag.
   * @throws EncodingException For invalid encoding.
   */
  public final double
  readOptionalTimeMillisecondsDTagElement(int expectedTag) throws EncodingException
  {
    if (peekDTag(expectedTag))
      return readTimeMillisecondsDTagElement(expectedTag);
    else
      return -1.0;
  }
  
  /**
   * Interpret the bytes as an unsigned big endian integer and convert to a double. 
   * Don't check for overflow.  We use a double because it is large enough to represent 
   * NDN time (4096 ticks per second since 1970).
   * @param bytes The ByteBuffer with the value.  This reads from position() to limit().
   * @return The double value.
   */
  public final double
  unsignedBigEndianToDouble(ByteBuffer bytes) 
  {
    double result = 0.0;
    for (int i = bytes.position(); i < bytes.limit(); ++i) {
      result *= 256.0;
      result += (double)((int)bytes.get(i) & 0xff);
    }

    return result;
  }

  /**
   * Get the current position of the input, used for the next read.
   * @return The position.
   */
  public final int
  getOffset() { return input_.position(); }
  
  /**
   * Set the position of the input, used for the next read.
   * @param position The new position.
   */
  public final void
  seek(int position) 
  {
    input_.position(position);
  }
  
  /**
   * Parse the value as a decimal unsigned integer.  This does not check for whitespace 
   * or + sign.  If the value length is 0, this returns 0.
   * @param value The ByteBuffer with the value.  This reads from position() to limit().
   * @return The parsed integer.
   * @throws EncodingException For invalid encoding including if an element of the
   * value is not a decimal digit.
   */
  private int
  parseUnsignedDecimalInt(ByteBuffer value) throws EncodingException
  {
    int result = 0;

    for (int i = value.position(); i < value.limit(); ++i) {
      int digit = (char)value.get(i);
      if (!(digit >= '0' && digit <= '9'))
        throw new EncodingException("Element of the value is not a decimal digit:" + digit);

      result *= 10;
      result += (digit - '0');
    }

    return result;
  }
  
  private final ByteBuffer input_;
}
