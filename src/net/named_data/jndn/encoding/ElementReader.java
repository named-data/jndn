/**
 * Copyright (C) 2013-2018 Regents of the University of California.
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

package net.named_data.jndn.encoding;

import java.nio.ByteBuffer;
import net.named_data.jndn.util.DynamicByteBuffer;
import net.named_data.jndn.encoding.tlv.TlvStructureDecoder;
import net.named_data.jndn.util.Common;

/**
 * A ElementReader lets you call onReceivedData multiple times which
 * uses a TlvStructureDecoder to detect the end of an NDN-TLV element and calls
 * elementListener.onReceivedElement(element) with the element. This handles the
 * case where a single call to onReceivedData may contain multiple elements.
 */
public class ElementReader {
  /**
   * Create a new ElementReader with the elementListener.
   * @param elementListener The ElementListener used by onReceivedData.
   */
  public
  ElementReader(ElementListener elementListener)
  {
    elementListener_ = elementListener;
  }

  /**
   * Continue to read data until the end of an element, then call
   * elementListener.onReceivedElement(element ). The buffer passed to
   * onReceivedElement is only valid during this call.  If you need the data
   * later, you must copy.
   * @param data The input data containing bytes of the element to read.
   * This reads from position() to limit(), but does not change the position.
   * @throws EncodingException For invalid encoding.
   */
  public void
  onReceivedData(ByteBuffer data) throws EncodingException
  {
    // We may repeatedly set data to a slice as we read elements.
    data = data.slice();

    // Process multiple objects in the data.
    while(true) {
      boolean gotElementEnd;
      int offset;

      try {
        if (!usePartialData_) {
          // This is the beginning of an element.
          if (data.remaining() <= 0)
            // Wait for more data.
            return;
        }

        // Scan the input to check if a whole TLV object has been read.
        tlvStructureDecoder_.seek(0);
        gotElementEnd = tlvStructureDecoder_.findElementEnd(data);
        offset = tlvStructureDecoder_.getOffset();
      } catch (EncodingException ex) {
        // Reset to read a new element on the next call.
        usePartialData_ = false;
        tlvStructureDecoder_ = new TlvStructureDecoder();

        throw ex;
      }

      if (gotElementEnd) {
        // Got the remainder of an element.  Report to the caller.
        ByteBuffer element;
        if (usePartialData_) {
          // We have partial data from a previous call, so append this data and point to partialData.
          partialData_.ensuredPut(data, 0, offset);

          element = partialData_.flippedBuffer();
          // Assume we don't need to use partialData anymore until needed.
          usePartialData_ = false;
        }
        else {
          // We are not using partialData, so just point to the input data buffer.
          element = data.duplicate();
          element.limit(offset);
        }

        // Reset to read a new object. Do this before calling onReceivedElement
        // in case it throws an exception.
        data.position(offset);
        data = data.slice();
        tlvStructureDecoder_ = new TlvStructureDecoder();

        elementListener_.onReceivedElement(element);
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

        if (partialData_.buffer().position() + data.remaining() >
            Common.MAX_NDN_PACKET_SIZE) {
          // Reset to read a new element on the next call.
          usePartialData_ = false;
          tlvStructureDecoder_ = new TlvStructureDecoder();

          throw new EncodingException
            ("The incoming packet exceeds the maximum limit Face.getMaxNdnPacketSize()");
        }

        partialData_.ensuredPut(data);
        return;
      }
    }
  }

  private final ElementListener elementListener_;
  private TlvStructureDecoder tlvStructureDecoder_ = new TlvStructureDecoder();
  private boolean usePartialData_;
  private final DynamicByteBuffer partialData_ = new DynamicByteBuffer(1000);
}
