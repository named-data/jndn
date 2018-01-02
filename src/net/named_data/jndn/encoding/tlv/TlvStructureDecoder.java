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
import net.named_data.jndn.encoding.EncodingException;

public class TlvStructureDecoder {
  /**
   * Continue scanning input starting from offset_ to find the element end.
   * If the end of the element which started at offset 0 is found, this returns
   * true and getOffset() is the length of the element.  Otherwise, this returns
   * false which means you should read more into input and call again.
   * @param input  The input buffer.  This reads starting from index 0 (not
   * index.position()) to input.limit(). This does not update its position().
   * You have to pass in input each time because the buffer could be
   * reallocated.
   * @return true if found the element end, false if not.
   */
  public final boolean
  findElementEnd(ByteBuffer input) throws EncodingException
  {
    if (gotElementEnd_)
      // Someone is calling when we already got the end.
      return true;

    TlvDecoder decoder = new TlvDecoder(input);

    while (true) {
      if (offset_ >= input.limit())
        // All the cases assume we have some input. Return and wait for more.
        return false;

      if (state_ == TlvStructureDecoder.READ_TYPE) {
        int firstOctet = (int)input.get(offset_) & 0xff;
        offset_ += 1;
        if (firstOctet < 253)
          // The value is simple, so we can skip straight to reading the length.
          state_ = TlvStructureDecoder.READ_LENGTH;
        else {
          // Set up to skip the type bytes.
          if (firstOctet == 253)
            nBytesToRead_ = 2;
          else if (firstOctet == 254)
            nBytesToRead_ = 4;
          else
            // value == 255.
            nBytesToRead_ = 8;

          state_ = TlvStructureDecoder.READ_TYPE_BYTES;
        }
      }
      else if (state_ == TlvStructureDecoder.READ_TYPE_BYTES) {
        int nRemainingBytes = input.limit() - offset_;
        if (nRemainingBytes < nBytesToRead_) {
          // Need more.
          offset_ += nRemainingBytes;
          nBytesToRead_ -= nRemainingBytes;
          return false;
        }

        // Got the type bytes. Move on to read the length.
        offset_ += nBytesToRead_;
        state_ = TlvStructureDecoder.READ_LENGTH;
      }
      else if (state_ == TlvStructureDecoder.READ_LENGTH) {
        int firstOctet = (int)input.get(offset_) & 0xff;
        offset_ += 1;
        if (firstOctet < 253) {
          // The value is simple, so we can skip straight to reading
          //  the value bytes.
          nBytesToRead_ = firstOctet;
          if (nBytesToRead_ == 0) {
            // No value bytes to read. We're finished.
            gotElementEnd_ = true;
            return true;
          }

          state_ = TlvStructureDecoder.READ_VALUE_BYTES;
        }
        else {
          // We need to read the bytes in the extended encoding of
          //  the length.
          if (firstOctet == 253)
            nBytesToRead_ = 2;
          else if (firstOctet == 254)
            nBytesToRead_ = 4;
          else
            // value == 255.
            nBytesToRead_ = 8;

          // We need to use firstOctet in the next state.
          firstOctet_ = firstOctet;
          state_ = TlvStructureDecoder.READ_LENGTH_BYTES;
        }
      }
      else if (state_ == TlvStructureDecoder.READ_LENGTH_BYTES) {
        int nRemainingBytes = input.limit() - offset_;
        if (!useHeaderBuffer_ && nRemainingBytes >= nBytesToRead_) {
          // We don't have to use the headerBuffer. Set nBytesToRead.
          decoder.seek(offset_);

          nBytesToRead_ = decoder.readExtendedVarNumber(firstOctet_);
          // Update offset_ to the decoder's offset after reading.
          offset_ = decoder.getOffset();
        }
        else {
          useHeaderBuffer_ = true;

          int nNeededBytes = nBytesToRead_ - headerBuffer_.position();
          if (nNeededBytes > nRemainingBytes) {
            // We can't get all of the header bytes from this input.
            // Save in headerBuffer.
            if (headerBuffer_.position() + nRemainingBytes >
                headerBuffer_.limit())
              // We don't expect this to happen.
              throw new Error
                ("Cannot store more header bytes than the size of headerBuffer");
            ByteBuffer remainingInput = input.duplicate();
            remainingInput.position(offset_);
            headerBuffer_.put(remainingInput);
            offset_ += nRemainingBytes;

            return false;
          }

          // Copy the remaining bytes into headerBuffer, read the
          //   length and set nBytesToRead.
          if (headerBuffer_.position() + nNeededBytes > headerBuffer_.limit())
            // We don't expect this to happen.
            throw new Error
              ("Cannot store more header bytes than the size of headerBuffer");
          ByteBuffer remainingLengthBytes = input.duplicate();
          remainingLengthBytes.position(offset_);
          remainingLengthBytes.limit(offset_ + nNeededBytes);
          headerBuffer_.put(remainingLengthBytes);
          offset_ += nNeededBytes;

          // Use a local decoder just for the headerBuffer.
          headerBuffer_.flip();
          TlvDecoder bufferDecoder = new TlvDecoder(headerBuffer_);
          // Replace nBytesToRead with the length of the value.
          nBytesToRead_ = bufferDecoder.readExtendedVarNumber(firstOctet_);
        }

        if (nBytesToRead_ == 0) {
          // No value bytes to read. We're finished.
          gotElementEnd_ = true;
          return true;
        }

        // Get ready to read the value bytes.
        state_ = TlvStructureDecoder.READ_VALUE_BYTES;
      }
      else if (state_ == TlvStructureDecoder.READ_VALUE_BYTES) {
        int nRemainingBytes = input.limit() - offset_;
        if (nRemainingBytes < nBytesToRead_) {
          // Need more.
          offset_ += nRemainingBytes;
          nBytesToRead_ -= nRemainingBytes;
          return false;
        }

        // Got the bytes. We're finished.
        offset_ += nBytesToRead_;
        gotElementEnd_ = true;
        return true;
      }
      else
        // We don't expect this to happen.
        throw new Error("findElementEnd: unrecognized state");
    }
  }

  /**
   * Get the current offset into the input buffer.
   * @return The offset.
   */
  public final int
  getOffset() { return offset_; }

  /**
   * Set the offset into the input, used for the next read.
   * @param offset The new offset.
   */
  public final void
  seek(int offset) { offset_ = offset; }

  private static int READ_TYPE =         0;
  private static int READ_TYPE_BYTES =   1;
  private static int READ_LENGTH =       2;
  private static int READ_LENGTH_BYTES = 3;
  private static int READ_VALUE_BYTES =  4;

  private boolean gotElementEnd_ = false;
  private int offset_ = 0;
  private int state_ = READ_TYPE;
  private boolean useHeaderBuffer_ = false;
  // 8 bytes is enough to hold the extended bytes in the length encoding
  // where it is an 8-byte number.
  private ByteBuffer headerBuffer_ = ByteBuffer.allocate(8);
  private int nBytesToRead_ = 0;
  private int firstOctet_;
}
