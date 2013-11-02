/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.encoding;

import net.named_data.jndn.util.DynamicByteBuffer;

public class BinaryXmlEncoder {
  public BinaryXmlEncoder()
  {
    output_ = new DynamicByteBuffer(100);
    offset_ = 0;
  }
  
  public static final int ENCODING_LIMIT_1_BYTE = ((1 << BinaryXml.TT_VALUE_BITS) - 1);
  public static final int ENCODING_LIMIT_2_BYTES = ((1 << (BinaryXml.TT_VALUE_BITS + BinaryXml.REGULAR_VALUE_BITS)) - 1);
  public static final int ENCODING_LIMIT_3_BYTES = ((1 << (BinaryXml.TT_VALUE_BITS + 2 * BinaryXml.REGULAR_VALUE_BITS)) - 1);

  /*
  private void writeArray(ByteBuffer array)
  {
    if ((error = ndn_DynamicUInt8Array_ensureLength(self->output, self->offset + arrayLength)))
      return error;
  
    ndn_memcpy(self->output->array + self->offset, array, arrayLength);
    self->offset += arrayLength;
  }
  */
  
  /**
   * Return the number of bytes to encode a header of value x.
   */
  private static int getNHeaderEncodingBytes(int x) 
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

  /*
  private static void reverse(uint8_t *array, size_t length) 
  {
    if (length == 0)
      return;
  
    uint8_t *left = array;
    uint8_t *right = array + length - 1;
    while (left < right) {
      // Swap.
      uint8_t temp = *left;
      *left = *right;
      *right = temp;
    
      ++left;
      --right;
    }
  }
  */
  
  private DynamicByteBuffer output_;
  private int offset_;
}
