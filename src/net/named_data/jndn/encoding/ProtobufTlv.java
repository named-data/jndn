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

package net.named_data.jndn.encoding;

import com.google.protobuf.ByteString;
import com.google.protobuf.Descriptors.Descriptor;
import com.google.protobuf.Descriptors.EnumValueDescriptor;
import com.google.protobuf.Descriptors.FieldDescriptor;
import com.google.protobuf.Descriptors.FieldDescriptor.Type;
import com.google.protobuf.Message;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.util.List;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.tlv.TlvDecoder;
import net.named_data.jndn.encoding.tlv.TlvEncoder;
import net.named_data.jndn.util.Blob;

/**
 * ProtobufTlv has static methods to encode and decode an Protobuf Message
 * object as NDN-TLV. The Protobuf tag value is used as the TLV type code. A
 * Protobuf message is encoded/decoded as a nested TLV encoding. Protobuf types
 * uint32, uint64 and enum are encoded/decoded as TLV nonNegativeInteger. (It is
 * an error if an enum value is negative.) Protobuf types bytes and string are
 * encoded/decoded as TLV bytes. The Protobuf type bool is encoded/decoded as a
 * TLV boolean (a zero length value for True, omitted for False). Other Protobuf
 * types are an error.
 *
 * Protobuf has no "outer" message type, so you need to put your TLV message
 * inside an outer "typeless" message.
 */
public class ProtobufTlv {
  /**
   * Encode the Protobuf message object as NDN-TLV.
   * @param message The Protobuf message object. This calls
   * message.IsInitialized() to ensure that all required fields are present and
   * throws an exception if not.
   * @return The encoded buffer in a Blob object.
   */
  public static Blob
  encode(Message message)
  {
    if (!message.isInitialized())
      throw new Error
        ("Message fields are not initialized: " + message.getInitializationErrorString());

    TlvEncoder encoder = new TlvEncoder(256);

    encodeMessageValue(message, encoder);
    return new Blob(encoder.getOutput(), false);
  }

  /**
   * Decode the input as NDN-TLV and update the fields of the Protobuf message
   * object.
   * @param message The Protobuf Message builder object. This does not first
   * clear the object.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @throws EncodingException For invalid encoding.
   */
  public static void
  decode(Message.Builder message, ByteBuffer input) throws EncodingException
  {
    TlvDecoder decoder = new TlvDecoder(input);
    decodeMessageValue(message, decoder, input.remaining());
  }

  public static void
  decode(Message.Builder message, Blob input) throws EncodingException
  {
    decode(message, input.buf());
  }

  /**
   * Return a Name made from the component array in a Protobuf message object,
   * assuming that it was defined with "repeated bytes". For example:
   * message Name {
   *   repeated bytes component = 8;
   * }
   * (See the TestEncodeDecodeFibEntry example.)
   * @param nameMessage The Protobuf message object containing the "repeated
   * bytes" component array.
   * @return A new name.
   */
  public static Name
  toName(Message nameMessage)
  {
    Name name = new Name();
    Descriptor descriptor = nameMessage.getDescriptorForType();
    FieldDescriptor field = (FieldDescriptor)descriptor.getFields().get(0);

    for (int i = 0; i < nameMessage.getRepeatedFieldCount(field); ++i)
      name.append(new Blob
        (((ByteString)nameMessage.getRepeatedField(field, i)).asReadOnlyByteBuffer(),
         true));

    return name;
  }

  private static void
  encodeMessageValue(Message message, TlvEncoder encoder)
  {
    // Note: We can't use ListFields because it sorts by field number.
    Descriptor descriptor = message.getDescriptorForType();
    // Go in reverse so that we encode backwards.
    List fields = descriptor.getFields();
    for (int i = fields.size() - 1; i >= 0; --i) {
      FieldDescriptor field = (FieldDescriptor)fields.get(i);

      int tlvType = field.getNumber();

      int valueCount = 0;
      if (field.isRepeated())
        valueCount = message.getRepeatedFieldCount(field);
      else {
        if (message.hasField(field))
          valueCount = 1;
      }

      // Reverse so that we encode backwards.
      for (int iValue = valueCount - 1; iValue >= 0; --iValue) {
        Object value;
        if (field.isRepeated())
          value = message.getRepeatedField(field, iValue);
        else
          value = message.getField(field);

        if (field.getType() == Type.MESSAGE) {
          int saveLength = encoder.getLength();

          // Encode backwards.
          encodeMessageValue((Message)value, encoder);
          encoder.writeTypeAndLength(tlvType, encoder.getLength() - saveLength);
        }
        else if (field.getType() == Type.UINT32)
          encoder.writeNonNegativeIntegerTlv(tlvType, (Integer)value);
        else if (field.getType() == Type.UINT64)
          encoder.writeNonNegativeIntegerTlv(tlvType, (Long)value);
        else if (field.getType() == Type.ENUM) {
          int intValue = ((EnumValueDescriptor)value).getNumber();
          if (intValue < 0)
            throw new Error("ProtobufTlv.encode: ENUM value may not be negative");
          encoder.writeNonNegativeIntegerTlv(tlvType, intValue);
        }
        else if (field.getType() == Type.BYTES)
          encoder.writeBlobTlv(tlvType, ((ByteString)value).asReadOnlyByteBuffer());
        else if (field.getType() == Type.STRING)
          // Use Blob to UTF-8 encode and get a ByteBuffer.
          encoder.writeBlobTlv(tlvType, new Blob((String)value).buf());
        else if (field.getType() == Type.BOOL) {
          if ((boolean)(Boolean)value)
            encoder.writeTypeAndLength(tlvType, 0);
        }
        else
          throw new Error("ProtobufTlv.encode: Unknown field type");
      }
    }
  }

  private static void
  decodeMessageValue(Message.Builder message, TlvDecoder decoder, int endOffset)
    throws EncodingException
  {
    Descriptor descriptor = message.getDescriptorForType();

    for (FieldDescriptor field : descriptor.getFields()) {
      int tlvType = field.getNumber();

      if (field.isOptional() && !decoder.peekType(tlvType, endOffset))
          continue;

      if (field.isRepeated()) {
        while (decoder.peekType(tlvType, endOffset)) {
          if (field.getType() == Type.MESSAGE) {
            Message.Builder innerMessage = message.newBuilderForField(field);

            int innerEndOffset = decoder.readNestedTlvsStart(tlvType);
            decodeMessageValue(innerMessage, decoder, innerEndOffset);
            decoder.finishNestedTlvs(innerEndOffset);

            message.addRepeatedField(field, innerMessage.build());
          }
          else
            message.addRepeatedField
              (field, decodeFieldValue(field, tlvType, decoder, endOffset));
        }
      }
      else {
        if (field.getType() == Type.MESSAGE) {
          Message.Builder innerMessage = message.newBuilderForField(field);

          int innerEndOffset = decoder.readNestedTlvsStart(tlvType);
          decodeMessageValue(innerMessage, decoder, innerEndOffset);
          decoder.finishNestedTlvs(innerEndOffset);

          message.setField(field, innerMessage.build());
        }
        else
          message.setField
            (field, decodeFieldValue(field, tlvType, decoder, endOffset));
      }
    }
  }

  /**
   * This is a helper for decodeMessageValue. Decode a single field and return
   * the value. Assume the field type is not Type.MESSAGE.
   */
  private static Object
  decodeFieldValue
    (FieldDescriptor field, int tlvType, TlvDecoder decoder, int endOffset)
      throws EncodingException
  {
    if (field.getType() == Type.UINT32)
      return (int)decoder.readNonNegativeIntegerTlv(tlvType);
    else if (field.getType() == Type.UINT64)
      return decoder.readNonNegativeIntegerTlv(tlvType);
    else if (field.getType() == Type.ENUM)
      return field.getEnumType().findValueByNumber
        ((int)decoder.readNonNegativeIntegerTlv(tlvType));
    else if (field.getType() == Type.BYTES)
      return ByteString.copyFrom(decoder.readBlobTlv(tlvType));
    else if (field.getType() == Type.STRING) {
      try {
        ByteBuffer byteBuffer = decoder.readBlobTlv(tlvType);
        // Use Blob to get the byte array.
        return new String(new Blob(byteBuffer, false).getImmutableArray(), "UTF-8");
      } catch (UnsupportedEncodingException ex) {
        // We don't expect this to happen.
        throw new Error("UTF-8 decoder not supported: " + ex.getMessage());
      }
    }
    else if (field.getType() == Type.BOOL)
      return decoder.readBooleanTlv(tlvType, endOffset);
    else
      throw new Error("ProtobufTlv.decode: Unknown field type");
  }
}
