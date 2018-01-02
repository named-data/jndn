/**
 * Copyright (C) 2013-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From PyNDN der_node.py by Adeola Bannis <thecodemaiden@gmail.com>.
 * @author: Originally from code in ndn-cxx by Yingdi Yu <yingdi@cs.ucla.edu>
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

package net.named_data.jndn.encoding.der;

import java.nio.ByteBuffer;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;
import net.named_data.jndn.encoding.OID;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;
import net.named_data.jndn.util.DynamicByteBuffer;

/**
 * DerNode implements the DER node types used in encoding/decoding DER-formatted
 * data.
 */
public class DerNode {
  /**
   * Create a generic DER node with the given nodeType. This is a private
   * constructor used by one of the public DerNode subclasses defined below.
   * @param nodeType The DER node type, a value from DerNodeType.
   */
  private DerNode(int nodeType)
  {
    nodeType_ = nodeType;
  }

  public int
  getSize()
  {
    // payload_ is not flipped yet.
    return header_.remaining() + payload_.position();
  }

  /**
   * Encode the given size and update the header.
   * @param size The payload size to encode.
   */
  protected final void
  encodeHeader(int size)
  {
    DynamicByteBuffer buffer = new DynamicByteBuffer(10);
    buffer.ensuredPut((byte)nodeType_);
    if (size < 0)
      // We don't expect this to happen since this is a protected method and
      // always called with the non-negative size() of some buffer.
      throw new Error("encodeHeader: DER object has negative length");
    else if (size <= 127)
      buffer.ensuredPut((byte)(size & 0xff));
    else {
      DynamicByteBuffer tempBuf = new DynamicByteBuffer(10);
      // We encode backwards from the back.
      tempBuf.position(tempBuf.limit());

      int val = size;
      int n = 0;
      while (val != 0) {
        tempBuf.ensuredPutFromBack((byte)(val & 0xff));
        val >>= 8;
        n += 1;
      }
      tempBuf.ensuredPutFromBack((byte)(((1<<7) | n) & 0xff));

      buffer.ensuredPut(tempBuf.buffer());
    }

    header_ = buffer.flippedBuffer();
  }

  /**
   * Extract the header from an input buffer and return the size.
   * @param inputBuf The input buffer to read from. This reads from
   * startIdx (regardless of the buffer's position) and does not change the
   * position.
   * @param startIdx The offset into the buffer.
   * @return The parsed size in the header.
   */
  protected final int
  decodeHeader(ByteBuffer inputBuf, int startIdx) throws DerDecodingException
  {
    int idx = startIdx;

    int nodeType = ((int)inputBuf.get(idx)) & 0xff;
    idx += 1;

    nodeType_ = nodeType;

    int sizeLen = ((int)inputBuf.get(idx)) & 0xff;
    idx += 1;

    DynamicByteBuffer header = new DynamicByteBuffer(10);
    header.ensuredPut((byte)nodeType);
    header.ensuredPut((byte)sizeLen);

    int size = sizeLen;
    boolean isLongFormat = (sizeLen & (1 << 7)) != 0;
    if (isLongFormat) {
      int lenCount = sizeLen & ((1<<7) - 1);
      size = 0;
      while (lenCount > 0) {
        if (inputBuf.limit() <= idx)
          throw new DerDecodingException
            ("DerNode.parse: The input length is too small");
        byte b = inputBuf.get(idx);
        idx += 1;
        header.ensuredPut(b);
        size = 256 * size + (((int)b) & 0xff);
        lenCount -= 1;
      }
    }

    header_ = header.flippedBuffer();
    return size;
  }

  /**
   * Get the raw data encoding for this node.
   * @return The raw data encoding.
   */
  public Blob
  encode()
  {
    DynamicByteBuffer buffer = new DynamicByteBuffer(getSize());

    buffer.ensuredPut(header_);
    buffer.ensuredPut(payload_.flippedBuffer());

    return new Blob(buffer.flippedBuffer(), false);
  }

  /**
   * Decode and store the data from an input buffer.
   * @param inputBuf The input buffer to read from. This reads from
   * startIdx (regardless of the buffer's position) and does not change the
   * position.
   * @param startIdx The offset into the buffer.
   */
  protected void
  decode(ByteBuffer inputBuf, int startIdx) throws DerDecodingException
  {
    int idx = startIdx;
    int payloadSize = decodeHeader(inputBuf, idx);
    int skipBytes = header_.remaining();
    if (payloadSize > 0) {
      idx += skipBytes;
      payload_.ensuredPut(inputBuf, idx, idx + payloadSize);
    }
  }

  /**
   * Parse the data from the input buffer recursively and return the root as an
   * object of a subclass of DerNode.
   * @param inputBuf The input buffer to read from. This reads from
   * startIdx (regardless of the buffer's position) and does not change the
   * position.
   * @param startIdx The offset into the buffer.
   * @return An object of a subclass of DerNode.
   */
  public static DerNode
  parse(ByteBuffer inputBuf, int startIdx) throws DerDecodingException
  {
    if (inputBuf.limit() <= startIdx)
      throw new DerDecodingException
        ("DerNode.parse: The input length is too small");
    int nodeType = ((int)inputBuf.get(startIdx)) & 0xff;
    // Don't increment idx. We're just peeking.

    DerNode newNode;
    if (nodeType == DerNodeType.Boolean)
      newNode = new DerBoolean();
    else if (nodeType == DerNodeType.Integer)
      newNode = new DerInteger();
    else if (nodeType == DerNodeType.BitString)
      newNode = new DerBitString();
    else if (nodeType == DerNodeType.OctetString)
      newNode = new DerOctetString();
    else if (nodeType == DerNodeType.Null)
      newNode = new DerNull();
    else if (nodeType == DerNodeType.ObjectIdentifier)
      newNode = new DerOid();
    else if (nodeType == DerNodeType.Sequence)
      newNode = new DerSequence();
    else if (nodeType == DerNodeType.PrintableString)
      newNode = new DerPrintableString();
    else if (nodeType == DerNodeType.GeneralizedTime)
      newNode = new DerGeneralizedTime();
    else if ((nodeType & 0xe0) == DerNodeType.ExplicitlyTagged)
      newNode = new DerExplicitlyTagged(nodeType & 0x1f);
    else
      throw new DerDecodingException("Unimplemented DER type " + nodeType);

    newNode.decode(inputBuf, startIdx);
    return newNode;
  }

  /**
   * Parse the data from the input buffer recursively and return the root as an
   * object of a subclass of DerNode.
   * @param inputBuf The input buffer to read from. This reads from
   * position and does not change the position.
   * @return An object of a subclass of DerNode.
   */
  public static DerNode
  parse(ByteBuffer inputBuf) throws DerDecodingException
  {
    return parse(inputBuf, inputBuf.position());
  }

  /**
   * Convert the encoded data to a standard representation. Overridden by some
   * subclasses (e.g. DerBoolean).
   * @return The encoded data as a Blob.
   */
  public Object
  toVal() throws DerDecodingException
  {
    return encode();
  }

  /**
   * Get a copy of the payload bytes.
   * @return A copy of the payload.
   */
  public final Blob
  getPayload()
  {
    return new Blob(payload_.flippedBuffer(), true);
  }

  /**
   * If this object is a DerSequence, get the children of this node. Otherwise,
   * throw an exception. (DerSequence overrides to implement this method.)
   * @return The children as a List of DerNode.
   * @throws DerDecodingException if this object is not a DerSequence.
   */
  public List
  getChildren() throws DerDecodingException
  {
    throw new DerDecodingException("getChildren: This DerNode is not DerSequence");
  }

  /**
   * Check that index is in bounds for the children list, cast
   * children.get(index) to DerSequence and return it.
   * @param children The list of DerNode, usually returned by another
   * call to getChildren.
   * @param index The index of the children.
   * @return children.get(index) cast to DerSequence.
   * @throws DerDecodingException if index is out of bounds or if
   * children.get(index) is not a DerSequence.
   */
  public static DerSequence
  getSequence(List children, int index) throws DerDecodingException
  {
    if (index < 0 || index >= children.size())
      throw new DerDecodingException("getSequence: Child index is out of bounds");

    if (!(children.get(index) instanceof DerSequence))
      throw new DerDecodingException
        ("getSequence: Child DerNode is not DerSequence");

    return (DerSequence)children.get(index);
  }

  /**
   * A DerStructure extends DerNode to hold other DerNodes.
   */
  public static class DerStructure extends DerNode {
    /**
     * Create a DerStructure with the given nodeType. This is a private
     * constructor. To create an object, use DerSequence.
     * @param nodeType The DER node type, a value from DerNodeType.
     */
    private DerStructure(int nodeType)
    {
      super(nodeType);
    }

    /**
     * Get the total length of the encoding, including children.
     * @return The total (header + payload) length.
     */
    public int
    getSize()
    {
      if (childChanged_) {
        updateSize();
        childChanged_ = false;
      }

      encodeHeader(size_);
      return size_ + header_.remaining();
    }

    /**
     * Get the children of this node.
     * @return The children as a List of DerNode.
     */
    public final List
    getChildren()
    {
      return nodeList_;
    }

    private void
    updateSize()
    {
      int newSize = 0;

      for (int i = 0; i < nodeList_.size(); ++i) {
        DerNode n = nodeList_.get(i);
        newSize += n.getSize();
      }

      size_ = newSize;
      childChanged_ = false;
    }

    /**
     * Add a child to this node.
     * @param node The child node to add.
     * @param notifyParent Set to true to cause any containing nodes to update
     * their size.
     */
    public final void
    addChild(DerNode node, boolean notifyParent)
    {
      node.parent_ = this;
      nodeList_.add(node);

      if (notifyParent) {
        if (parent_ != null)
          parent_.setChildChanged();
      }

      childChanged_ = true;
    }

    public final void
    addChild(DerNode node)
    {
      addChild(node, false);
    }

    /**
     * Mark the child list as dirty, so that we update size when necessary.
     */
    private void
    setChildChanged()
    {
      if (parent_ != null)
        parent_.setChildChanged();
      childChanged_ = true;
    }

    /**
     * Override the base encode to return raw data encoding for this node and
     * its children
     * @return The raw data encoding.
     */
    public Blob
    encode()
    {
      DynamicByteBuffer temp = new DynamicByteBuffer(10);
      updateSize();
      encodeHeader(size_);
      temp.ensuredPut(header_);

      for (int i = 0; i < nodeList_.size(); ++i) {
        DerNode n = nodeList_.get(i);
        Blob encodedChild = n.encode();
        temp.ensuredPut(encodedChild.buf());
      }

      return new Blob(temp.flippedBuffer(), false);
    }

    /**
     * Override the base decode to decode and store the data from an input
     * buffer. Recursively populates child nodes.
     * @param inputBuf The input buffer to read from. This reads from
     * startIdx (regardless of the buffer's position) and does not change the
     * position.
     * @param startIdx The offset into the buffer.
     */
    protected void
    decode(ByteBuffer inputBuf, int startIdx) throws DerDecodingException
    {
      int idx = startIdx;
      size_ = decodeHeader(inputBuf, idx);
      idx += header_.remaining();

      int accSize = 0;
      while (accSize < size_) {
        DerNode node = parse(inputBuf, idx);
        int size = node.getSize();
        idx += size;
        accSize += size;
        addChild(node, false);
      }
    }

    private boolean childChanged_ = false;
    private final ArrayList<DerNode> nodeList_ = new ArrayList<DerNode>();
    private int size_ = 0;
  }

  ////////
  // Now for all the node types...
  ////////

  /**
   * A DerByteString extends DerNode to handle byte strings.
   */
  public static class DerByteString extends DerNode {
    /**
     * Create a DerByteString with the given inputData and nodeType. This is a
     * private constructor used by one of the public subclasses such as
     * DerOctetString or DerPrintableString.
     * @param inputData An input buffer containing the string to encode.  This
     * copies from the buffer's position to limit, but does not change position.
     * @param nodeType The specific DER node type, a value from DerNodeType.
     */
    private DerByteString(ByteBuffer inputData, int nodeType)
    {
      super(nodeType);

      if (inputData != null) {
        payload_.ensuredPut(inputData);
        encodeHeader(inputData.remaining());
      }
    }

    /**
     * Override to return just the byte string.
     * @return The byte string as a copy of the payload ByteBuffer.
     */
    public Object
    toVal() throws DerDecodingException
    {
      return getPayload();
    }
  }

  /**
   * DerBoolean extends DerNode to encode a boolean value.
   */
  public static class DerBoolean extends DerNode {
    /**
     * Create a new DerBoolean for the value.
     * @param value The value to encode.
     */
    public DerBoolean(boolean value)
    {
      super(DerNodeType.Boolean);

      byte val = value ? (byte)0xff : (byte)0x00;
      payload_.ensuredPut(val);
      encodeHeader(1);
    }

    private DerBoolean()
    {
      super(DerNodeType.Boolean);
    }

    public Object
    toVal() throws DerDecodingException
    {
      byte val = payload_.buffer().get(0);
      return val != 0x00;
    }
  }

  /**
   * DerInteger extends DerNode to encode an integer value.
   */
  public static class DerInteger extends DerNode {
    /**
     * Create a new DerInteger for the value.
     * @param integer The value to encode.
     */
    public DerInteger(int integer) throws DerEncodingException
    {
      super(DerNodeType.Integer);

      if (integer < 0)
        throw new DerEncodingException
          ("DerInteger: Negative integers are not currently supported");

      // Convert the integer to bytes the easy/slow way.
      DynamicByteBuffer temp = new DynamicByteBuffer(10);
      // We encode backwards from the back.
      temp.position(temp.limit());
      while (true) {
        temp.ensuredPutFromBack((byte)(integer & 0xff));
        integer >>= 8;

        if (integer <= 0)
          // We check for 0 at the end so we encode one byte if it is 0.
          break;
      }

      if ((((int)temp.buffer().get(temp.position())) & 0xff) >= 0x80)
        // Make it a non-negative integer.
        temp.ensuredPutFromBack((byte)0);

      payload_.ensuredPut(temp.buffer().slice());
      encodeHeader(payload_.position());
    }

    /**
     * Create a new DerInteger from the bytes in the buffer. If bytes represent
     * a positive integer, you must ensure that the first byte is less than 0x80.
     * @param buffer The buffer containing the bytes of the integer.  This
     * copies from the buffer's position to limit, but does not change position.
     * @throws DerEncodingException if the first byte is not less than 0x80.
     */
    public DerInteger(ByteBuffer buffer) throws DerEncodingException
    {
      super(DerNodeType.Integer);

      if (buffer.remaining() > 0 &&
          (((int)buffer.get(buffer.position())) & 0xff) >= 0x80)
        throw new DerEncodingException
          ("DerInteger: Negative integers are not currently supported");

      if (buffer.remaining() == 0)
        payload_.ensuredPut((byte)0);
      else
        payload_.ensuredPut(buffer);

      encodeHeader(payload_.position());
    }

    public DerInteger()
    {
      super(DerNodeType.Integer);
    }

    public Object
    toVal() throws DerDecodingException
    {
      if (payload_.buffer().position() > 0 &&
          (((int)payload_.buffer().get(0)) & 0xff) >= 0x80)
        throw new DerDecodingException
          ("DerInteger: Negative integers are not currently supported");

      int result = 0;
      // payload_ is not flipped yet.
      for (int i = 0; i < payload_.buffer().position(); ++i) {
        result <<= 8;
        // Use & 0xff in case byte was in the range -128 to -1.
        result += ((int)payload_.buffer().get(i)) & 0xff;
      }

      return result;
    }
  }

  /**
   * A DerBitString extends DerNode to handle a bit string.
   */
  public static class DerBitString extends DerNode {
    /**
     * Create a DerBitString with the given padding and inputBuf.
     * @param inputBuf An input buffer containing the bit octets to encode.  This
     * copies from the buffer's position to limit, but does not change position.
     * @param paddingLen The number of bits of padding at the end of the bit
     * string.  Should be less than 8.
     */
    public DerBitString(ByteBuffer inputBuf, int paddingLen)
    {
      super(DerNodeType.BitString);

      if (inputBuf != null) {
        payload_.ensuredPut((byte)(paddingLen & 0xff));
        payload_.ensuredPut(inputBuf);
        encodeHeader(payload_.position());
      }
    }

    private DerBitString()
    {
      super(DerNodeType.BitString);
    }
  }

  /**
   * DerOctetString extends DerByteString to encode a string of bytes.
   */
  public static class DerOctetString extends DerByteString {
    /**
     * Create a new DerOctetString for the inputData.
     * @param inputData An input buffer containing the string to encode.  This
     * copies from the buffer's position to limit, but does not change position.
     */
    public DerOctetString(ByteBuffer inputData)
    {
      super(inputData, DerNodeType.OctetString);
    }

    private DerOctetString()
    {
      super(null, DerNodeType.OctetString);
    }
  }

  /**
   * A DerNull extends DerNode to encode a null value.
   */
  public static class DerNull extends DerNode {
    /**
     * Create a DerNull.
     */
    public DerNull()
    {
      super(DerNodeType.Null);
      encodeHeader(0);
    }
  }

  /**
   * A DerOid extends DerNode to represent an object identifier
   */
  public static class DerOid extends DerNode {
    /**
     * Create a DerOid with the given object identifier. The object identifier
     * string must begin with 0,1, or 2 and must contain at least 2 digits.
     * @param oidStr The OID string to encode.
     */
    public DerOid(String oidStr) throws DerEncodingException
    {
      super(DerNodeType.ObjectIdentifier);

      String[] splitString = oidStr.split("\\.");
      int[] parts = new int[splitString.length];
      for (int i = 0; i < parts.length; ++i)
        parts[i] = Integer.parseInt(splitString[i]);

      prepareEncoding(parts);
    }

    /**
     * Create a DerOid with the given object identifier. The object identifier
     * must begin with 0,1, or 2 and must contain at least 2 digits.
     * @param oid The OID to encode.
     */
    public DerOid(OID oid) throws DerEncodingException
    {
      super(DerNodeType.ObjectIdentifier);

      prepareEncoding(oid.getIntegerList());
    }

    private DerOid()
    {
      super(DerNodeType.ObjectIdentifier);
    }

    /**
     * Encode a sequence of integers into an OID object and set the payload.
     * @param value The array of integers.
     */
    private void
    prepareEncoding(int[] value) throws DerEncodingException
    {
      int firstNumber = 0;
      if (value.length == 0)
          throw new DerEncodingException("No integer in OID");
      else {
        if (value[0] >= 0 && value[0] <= 2)
          firstNumber = value[0] * 40;
        else
          throw new DerEncodingException("First integer in OID is out of range");
      }

      if (value.length >= 2) {
        if (value[1] >= 0 && value[1] <= 39)
          firstNumber += value[1];
        else
          throw new DerEncodingException("Second integer in OID is out of range");
      }

      DynamicByteBuffer encodedBuffer = new DynamicByteBuffer(10);
      encodedBuffer.ensuredPut(encode128(firstNumber));

      if (value.length > 2) {
        for (int i = 2; i < value.length; ++i)
          encodedBuffer.ensuredPut(encode128(value[i]));
      }

      encodeHeader(encodedBuffer.position());
      payload_.ensuredPut(encodedBuffer.flippedBuffer());
    }

    /**
     * Compute the encoding for one part of an OID, where values greater than 128 must be encoded as multiple bytes.
     * @param value A component of an OID.
     * @return The encoded buffer.
     */
    private static ByteBuffer
    encode128(int value)
    {
      int mask = (1 << 7) - 1;
      DynamicByteBuffer outBytes = new DynamicByteBuffer(10);
      // We encode backwards from the back.
      outBytes.position(outBytes.limit());

      if (value < 128)
        outBytes.ensuredPutFromBack((byte)(value & mask));
      else {
        outBytes.ensuredPutFromBack((byte)(value & mask));
        value >>= 7;
        while (value != 0) {
          outBytes.ensuredPutFromBack((byte)((value & mask) | (1 << 7)));
          value >>= 7;
        }
      }

      return outBytes.buffer().slice();
    }

    /**
     * Convert an encoded component of the encoded OID to the original integer.
     * @param offset The offset into this node's payload.
     * @param skip Set skip[0] to the number of payload bytes to skip.
     * @return The original integer.
     */
    private int
    decode128(int offset, int[] skip)
    {
      int flagMask = 0x80;
      int result = 0;
      int oldOffset = offset;

      while ((payload_.buffer().get(offset) & flagMask) != 0) {
        result = 128 * result + ((int)payload_.buffer().get(offset) & 0xff) - 128;
        offset += 1;
      }

      result = result * 128 + ((int)payload_.buffer().get(offset) & 0xff);

      skip[0] = offset - oldOffset + 1;
      return result;
    }

    /**
     * Override to return the string representation of the OID.
     * @return The string representation of the OID.
     */
    public Object
    toVal() throws DerDecodingException
    {
      int offset = 0;
      ArrayList components = new ArrayList(); // of Integer.

      while (offset < payload_.position()) {
        int[] skip = new int[1];
        int nextVal = decode128(offset, skip);
        offset += skip[0];
        components.add(nextVal);
      }

      // for some odd reason, the first digits are represented in one byte
      int firstByte = (Integer)components.get(0);
      int firstDigit = firstByte / 40;
      int secondDigit = firstByte % 40;

      String result = firstDigit + "." + secondDigit;
      for (int i = 1; i < components.size(); ++i)
        result += "." + (Integer)components.get(i);

      return result;
    }
  }

  /**
   * A DerSequence extends DerStructure to contains an ordered sequence of other
   * nodes.
   */
  public static class DerSequence extends DerStructure {
    /**
     * Create a DerSequence.
     */
    public DerSequence()
    {
      super(DerNodeType.Sequence);
    }
  }

  /**
   * A DerPrintableString extends DerByteString to handle a a printable string. No
   * escaping or other modification is done to the string
   */
  public static class DerPrintableString extends DerByteString {
    /**
     * Create a DerPrintableString with the given inputData.
     * @param inputData An input buffer containing the string to encode.  This
     * copies from the buffer's position to limit, but does not change position.
     */
    public DerPrintableString(ByteBuffer inputData)
    {
      super(inputData, DerNodeType.PrintableString);
    }

    private DerPrintableString()
    {
      super(null, DerNodeType.PrintableString);
    }
  }

  /**
   * A DerGeneralizedTime extends DerNode to represent a date and time, with
   * millisecond accuracy.
   */
  public static class DerGeneralizedTime extends DerNode {
    /**
     * Create a DerGeneralizedTime with the given milliseconds since 1970.
     * @param msSince1970 The timestamp as milliseconds since Jan 1, 1970.
     */
    public DerGeneralizedTime(double msSince1970)
    {
      super(DerNodeType.GeneralizedTime);

      String derTime = toDerTimeString(msSince1970);
      // Use Blob to convert to a ByteBuffer.
      payload_.ensuredPut(new Blob(derTime).buf());
      encodeHeader(payload_.position());
    }

    private DerGeneralizedTime()
    {
      super(DerNodeType.GeneralizedTime);
    }

    /**
     * Convert a UNIX timestamp to the internal string representation.
     * @param msSince1970 Timestamp as milliseconds since Jan 1, 1970.
     * @return The string representation.
     */
    private static String
    toDerTimeString(double msSince1970)
    {
      Date utcTime = Common.millisecondsSince1970ToDate
        ((long)Math.round(msSince1970));
      return dateFormat_.format(utcTime);
    }

    /**
     * Compute the date format for storing in the static variable dateFormat_.
     */
    private static SimpleDateFormat
    getDateFormat()
    {
      SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
      dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
      return dateFormat;
    }

    /**
     * Override to return the milliseconds since 1970.
     * @return The timestamp value as milliseconds since 1970 as a Double value.
     */
    public Object
    toVal() throws DerDecodingException
    {
      // Use Blob to convert to a string.
      String timeStr = "" + new Blob(payload_.flippedBuffer(), false);
      try {
        Date date = dateFormat_.parse(timeStr);
        return (double)Common.dateToMillisecondsSince1970(date);
      } catch (ParseException ex) {
        throw new DerDecodingException
          ("DerGeneralizedTime: Error decoding the date string: " + ex);
      }
    }

    private static final SimpleDateFormat dateFormat_ = getDateFormat();
  }

  /**
   * A DerExplicitlyTagged extends DerNode to represent an explicitly-tagged
   * type which wraps another DerNode.
   */
  public static class DerExplicitlyTagged extends DerNode {
    /**
     * Create a DerExplicitlyTagged with the given tag number.
     * @param tagNumber The explicit tag number from 0x00 to 0x1f.
     */
    public DerExplicitlyTagged(int tagNumber)
    {
      super(DerNodeType.ExplicitlyTagged);
      tagNumber_ = tagNumber;
    }

    /**
     * Override the base encode to return raw data encoding for the explicit tag
     * and encoded inner node.
     * @return The raw data encoding.
     */
    public Blob
    encode()
    {
      throw new UnsupportedOperationException
        ("DerExplicitlyTagged.encode is not implemented");
    }

    /**
     * Override the base decode to decode and store the inner DerNode.
     * @param inputBuf The input buffer to read from. This reads from
     * startIdx (regardless of the buffer's position) and does not change the
     * position.
     * @param startIdx The offset into the buffer.
     */
    protected void
    decode(ByteBuffer inputBuf, int startIdx) throws DerDecodingException
    {
      super.decode(inputBuf, startIdx);
      innerNode_ = parse(getPayload().buf());
    }

    /**
     * Get the tag number.
     * @return The tag number.
     */
    public final int
    getTagNumber() { return tagNumber_; }

    /**
     * Get the inner node that is wrapped by the explicit tag.
     * @return The inner node, or null if node specified.
     */
    public final DerNode
    getInnerNode() { return innerNode_; }

    private final int tagNumber_;
    private DerNode innerNode_ = null;
  }

  protected DerStructure parent_ = null;
  // A value from DerNodeType.
  private int nodeType_;
  protected ByteBuffer header_ = ByteBuffer.allocate(0);
  // NOTE: We never "flip" the internal buffer.  Its data is from 0 to position().
  protected DynamicByteBuffer payload_ = new DynamicByteBuffer(0);
}
