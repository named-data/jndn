/**
 * Copyright (C) 2013-2015 Regents of the University of California.
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

public class BinaryXmlStructureDecoder {
  /**
   * Continue scanning input starting from offset_.  If found the end of the element
   *   which started at offset 0, then return true, else false.
   * If this returns true, then the element end is at getOffset().
   * If this returns false, you should read more into input and call again.
   * You have to pass in input each time because the array could be reallocated.
   * @param input The input buffer to read.  This does not update its position().
   * @return True if found the element end, false to read more input.
   * @throws EncodingException For invalid encoding.
   */
  public boolean
  findElementEnd(ByteBuffer input) throws EncodingException
  {
    if (gotElementEnd_)
      // Someone is calling when we already got the end.
      return true;

    BinaryXmlDecoder decoder = new BinaryXmlDecoder(input);

    while (true) {
      if (offset_ >= input.limit())
        // All the cases assume we have some input.
        return false;

      if (state_ == READ_HEADER_OR_CLOSE) {
        // First check for XML_CLOSE.
        if (headerLength_ == 0 && input.get(offset_) == BinaryXml.CLOSE) {
          ++offset_;
          // Close the level.
          --level_;
          if (level_ == 0) {
            // Finished.
            gotElementEnd_ = true;
            return true;
          }
          if (level_ < 0)
            throw new Error("BinaryXMLStructureDecoder: Unexpected close tag at offset " + (offset_ - 1));

          // Get ready for the next header.
          startHeader();
          continue;
        }

        int startingHeaderLength = headerLength_;
        while (true) {
          if (offset_ >= input.limit()) {
            // We can't get all of the header bytes from this input. Save in headerBuffer.
            useHeaderBuffer_ = true;
            int nNewBytes = headerLength_ - startingHeaderLength;
            headerBuffer_.ensuredPut(input, offset_ - nNewBytes, offset_);

            return false;
          }
          int headerByte = input.get(offset_++);
          ++headerLength_;
          if ((headerByte & BinaryXml.TT_FINAL) != 0)
            // Break and read the header.
            break;
        }

        BinaryXmlDecoder.TypeAndValue typeAndVal;
        if (useHeaderBuffer_) {
          // Copy the remaining bytes into headerBuffer.
          int nNewBytes = headerLength_ - startingHeaderLength;
          headerBuffer_.ensuredPut(input, offset_ - nNewBytes, offset_);

          typeAndVal = new BinaryXmlDecoder(headerBuffer_.flippedBuffer()).decodeTypeAndValue();
        }
        else {
          // We didn't have to use the headerBuffer.
          decoder.seek(offset_ - headerLength_);
          typeAndVal = decoder.decodeTypeAndValue();
        }

        // Set the next state based on the type.
        int type = typeAndVal.getType();
        if (type == BinaryXml.DATTR)
          // We already consumed the item. READ_HEADER_OR_CLOSE again.
          // Binary XML has rules about what must follow an attribute, but we are just scanning.
          startHeader();
        else if (type == BinaryXml.DTAG || type == BinaryXml.EXT) {
          // Start a new level and READ_HEADER_OR_CLOSE again.
          ++level_;
          startHeader();
        }
        else if (type == BinaryXml.TAG || type == BinaryXml.ATTR) {
          if (type == BinaryXml.TAG)
            // Start a new level and read the tag.
            ++level_;
          // Minimum tag or attribute length is 1.
          nBytesToRead_ = typeAndVal.getValue() + 1;
          state_ = READ_BYTES;
          // Binary XML has rules about what must follow an attribute, but we are just scanning.
        }
        else if (type == BinaryXml.BLOB || type == BinaryXml.UDATA) {
          nBytesToRead_ = typeAndVal.getValue();
          state_ = READ_BYTES;
        }
        else
          throw new EncodingException("BinaryXMLStructureDecoder: Unrecognized header type " + type);
      }
      else if (state_ == READ_BYTES) {
        int nRemainingBytes = input.limit() - offset_;
        if (nRemainingBytes < nBytesToRead_) {
          // Need more.
          offset_ += nRemainingBytes;
          nBytesToRead_ -= nRemainingBytes;
          return false;
        }
        // Got the bytes.  Read a new header or close.
        offset_ += nBytesToRead_;
        startHeader();
      }
      else
        // We don't expect this to happen.
        throw new EncodingException("BinaryXMLStructureDecoder: Unrecognized state " + state_);
    }
  }

  /**
   * Set the offset into the input, used for the next read.
   * @param offset The new offset.
   */
  public void
  seek(int offset)
  {
    offset_ = offset;
  }

  /**
   * When findElementEnd returns true, call this to get the element end.
   * @return The position just past the element end.
   */
  public int
  getOffset() { return offset_; }

  /**
   * Set the state to READ_HEADER_OR_CLOSE and set up to start reading the header.
   */
  private void
  startHeader()
  {
    headerLength_ = 0;
    headerBuffer_.position(0);
    useHeaderBuffer_ = false;
    state_ = READ_HEADER_OR_CLOSE;
  }

  private static final int READ_HEADER_OR_CLOSE = 0;
  private static final int READ_BYTES = 1;

  private boolean gotElementEnd_;
  private int offset_;
  private int level_;
  private int state_ = READ_HEADER_OR_CLOSE;
  private int headerLength_;
  private boolean useHeaderBuffer_;
  // 10 bytes is enough to hold an encoded header with a type and a 64 bit value.
  private final DynamicByteBuffer headerBuffer_ = new DynamicByteBuffer(10);
  private int nBytesToRead_;
}
