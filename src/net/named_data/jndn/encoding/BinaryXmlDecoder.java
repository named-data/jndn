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
  public BinaryXmlDecoder(ByteBuffer input)
  {
    input_ = input.duplicate();        
  }
  
  public class TypeAndValue {
    public TypeAndValue(int type, int value)
    {
      type_ = type;
      value_ = value;
    }
    
    int getType() { return type_; }
    
    int getValue() { return value_; }
    
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
   * Then read one item of any type (presumably BLOB, UDATA, TAG or ATTR) and return a ByteBuffer.
   * However, if allowNull is true, then the item may be absent.
   * Finally, read the element close.  Update the input's position.
   * @param expectedTag The expected value for DTAG.
   * @param allowNull True if the binary item may be missing.
   * @return a ByteBuffer which is a slice on the data inside the input buffer. However, if allowNull is true and the
   * binary data item is absent, then return null.
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

  // ----------------------
  
  /*
  static ndn_Error parseUnsignedDecimalInt(uint8_t *value, size_t valueLength, unsigned int *resultOut)
  {
    unsigned int result = 0;

    size_t i;
    for (i = 0; i < valueLength; ++i) {
      uint8_t digit = value[i];
      if (!(digit >= '0' && digit <= '9'))
        return NDN_ERROR_element_of_value_is_not_a_decimal_digit;

      result *= 10;
      result += (unsigned int)(digit - '0');
    }

    *resultOut = result;
    return NDN_ERROR_success;
  }
  */
  
  public static void main(String[] args) 
  {
    System.out.println("hello");
  }
  
  private final ByteBuffer input_;
}
