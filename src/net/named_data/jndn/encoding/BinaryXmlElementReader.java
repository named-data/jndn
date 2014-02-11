/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.encoding;

import java.nio.ByteBuffer;
import net.named_data.jndn.util.DynamicByteBuffer;

/**
 * A BinaryXmlElementReader lets you call onReceivedData multiple times which uses a
 * BinaryXmlStructureDecoder to detect the end of a binary XML element and calls
 * elementListener.onReceivedElement(element) with the element. 
 * This handles the case where a single call to onReceivedData may contain multiple elements.
 */
public class BinaryXmlElementReader {
  /**
   * Create a new BinaryXmlElementReader with the elementListener.
   * @param elementListener The ElementListener used by onReceivedData.
   */
  public
  BinaryXmlElementReader(ElementListener elementListener)
  {
    elementListener_ = elementListener;
  }

  /**
   * Continue to read binary XML data until the end of an element, then call elementListener.onReceivedElement(element ).
   * The buffer passed to onReceivedElement is only valid during this call.  If you need the data later, you must copy.
   * @param data The input data containing bytes of the element to read.  This reads from position() to limit(), 
   * but does not change the position.
   * @throws EncodingException For invalid encoding.
   */
  public void 
  onReceivedData(ByteBuffer data) throws EncodingException
  {
    // We may repeatedly set data to a slice as we read elements.
    data = data.slice();
    
    // Process multiple objects in the data.
    while(true) {
      // Scan the input to check if a whole binary XML object has been read.
      structureDecoder_.seek(0);

      if (structureDecoder_.findElementEnd(data)) {
        // Got the remainder of an element.  Report to the caller.
        if (usePartialData_) {
          // We have partial data from a previous call, so append this data and point to partialData.
          partialData_.ensuredPut(data, 0, structureDecoder_.getOffset());

          elementListener_.onReceivedElement(partialData_.flippedBuffer());
          // Assume we don't need to use partialData anymore until needed.
          usePartialData_ = false;
        }
        else {
          // We are not using partialData, so just point to the input data buffer.
          ByteBuffer dataDuplicate = data.duplicate();
          dataDuplicate.limit(structureDecoder_.getOffset());
          elementListener_.onReceivedElement(dataDuplicate);
        }

        // Need to read a new object.
        data.position(structureDecoder_.getOffset());
        data = data.slice();
        structureDecoder_ = new BinaryXmlStructureDecoder();
        if (data.remaining() <= 0)
          // No more data in the packet.
          return;

        // else loop back to decode.
      }
      else {
        // Save remaining data for a later call.
        if (!usePartialData_) {
          usePartialData_ = true;
          partialData_.position(0);
        }

        partialData_.ensuredPut(data);
        return;
      }
    }      
  }
  
  private ElementListener elementListener_;
  private BinaryXmlStructureDecoder structureDecoder_ = new BinaryXmlStructureDecoder();
  private boolean usePartialData_;
  private DynamicByteBuffer partialData_ = new DynamicByteBuffer(1000);
}
