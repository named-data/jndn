/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.encoding;

import java.nio.ByteBuffer;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Data;
import net.named_data.jndn.ForwardingEntry;

public class WireFormat {
  /**
   * Encode interest and return the encoding.  Your derived class should 
   * override.
   * @param interest The Interest object to encode.
   * @return A Blob containing the encoding.
   * @throws UnsupportedOperationException for unimplemented if the derived 
   * class does not override.
   */
  public Blob 
  encodeInterest(Interest interest)
  {
    throw new UnsupportedOperationException
      ("encodeInterest is not implemented");
  }
  
  /**
   * Decode input as an interest and set the fields of the interest object.  
   * Your derived class should override.
   * @param interest The Interest object whose fields are updated.
   * @param input The input buffer to decode.  This reads from position() to 
   * limit(), but does not change the position.
   * @throws UnsupportedOperationException for unimplemented if the derived 
   * class does not override.
   * @throws EncodingException For invalid encoding.
   */
  public void 
  decodeInterest(Interest interest, ByteBuffer input) throws EncodingException
  {
    throw new UnsupportedOperationException
      ("decodeInterest is not implemented");
  }

  /**
   * Encode data and return the encoding.  Your derived class should override.
   * @param data The Data object to encode.
   * @param signedPortionBeginOffset Return the offset in the encoding of the 
   * beginning of the signed portion by setting signedPortionBeginOffset[0].
   * If you are not encoding in order to sign, you can call encodeData(data) to 
   * ignore this returned value.
   * @param signedPortionEndOffset Return the offset in the encoding of the end 
   * of the signed portion by setting signedPortionEndOffset[0].
   * If you are not encoding in order to sign, you can call encodeData(data) to 
   * ignore this returned value.
   * @return A Blob containing the encoding.
   * @throws UnsupportedOperationException for unimplemented if the derived 
   * class does not override.
   */
  public Blob 
  encodeData
    (Data data, int[] signedPortionBeginOffset, int[] signedPortionEndOffset)
  {
    throw new UnsupportedOperationException("encodeData is not implemented");
  }

  /**
   * Encode data and return the encoding.
   * @param data The Data object to encode.
   * @return A Blob containing the encoding.
   * @throws UnsupportedOperationException for unimplemented if the derived 
   * class does not override.
   */
  public final Blob 
  encodeData(Data data)
  {
    return encodeData(data, new int[1], new int[1]);
  }

  /**
   * Decode input as a data packet and set the fields in the data object.  Your 
   * derived class should override.
   * @param data The Data object whose fields are updated.
   * @param input The input buffer to decode.  This reads from position() to 
   * limit(), but does not change the position.
   * @param signedPortionBeginOffset Return the offset in the input buffer of 
   * the beginning of the signed portion by setting signedPortionBeginOffset[0].  
   * If you are not decoding in order to verify, you can call 
   * decodeData(data, input) to ignore this returned value.
   * @param signedPortionEndOffset Return the offset in the input buffer of the 
   * end of the signed portion by
   * setting signedPortionEndOffset[0]. If you are not decoding in order to 
   * verify, you can call decodeData(data, input) to ignore this returned value.
   * @throws UnsupportedOperationException for unimplemented if the derived 
   * class does not override.
   * @throws EncodingException For invalid encoding.
   */
  public void 
  decodeData
    (Data data, ByteBuffer input, int[] signedPortionBeginOffset, 
     int[] signedPortionEndOffset) throws EncodingException
  {
    throw new UnsupportedOperationException("decodeData is not implemented");
  }

  /**
   * Decode input as a data packet and set the fields in the data object.  Your 
   * derived class should override.
   * @param data The Data object whose fields are updated.
   * @param input The input buffer to decode.  This reads from position() to 
   * limit(), but does not change the position.
   * @throws UnsupportedOperationException for unimplemented if the derived 
   * class does not override.
   * @throws EncodingException For invalid encoding.
   */
  public final void 
  decodeData(Data data, ByteBuffer input) throws EncodingException
  {
    decodeData(data, input, new int[1], new int[1]);
  }
  
  /**
   * Encode forwardingEntry and return the encoding. Your derived class should 
   * override.
   * @param forwardingEntry The ForwardingEntry object to encode.
   * @return A Blob containing the encoding.
   * @throws UnsupportedOperationException for unimplemented if the derived 
   * class does not override.
   */
  public Blob 
  encodeForwardingEntry(ForwardingEntry forwardingEntry)
  {
    throw new UnsupportedOperationException
      ("encodeForwardingEntry is not implemented");
  }
  
  /**
   * Decode input as a forwarding entry and set the fields of the 
   * forwardingEntry object. Your derived class should override.
   * @param forwardingEntry The ForwardingEntry object whose fields are updated.
   * @param input ByteBuffer input.
   * @throws UnsupportedOperationException for unimplemented if the derived 
   * class does not override.
   * @throws EncodingException For invalid encoding.
   */
  public void 
  decodeForwardingEntry
    (ForwardingEntry forwardingEntry, ByteBuffer input) throws EncodingException
  {
    throw new UnsupportedOperationException
      ("decodeForwardingEntry is not implemented");
  }
    
  /**
   * Set the static default WireFormat used by default encoding and decoding 
   * methods.
   * @param wireFormat An object of a subclass of WireFormat.  This does not 
   * make a copy.
   */
  public static void 
  setDefaultWireFormat(WireFormat wireFormat) 
  {
    defaultWireFormat_ = wireFormat;
  }
  
  /**
   * Return the default WireFormat used by default encoding and decoding methods 
   * which was set with setDefaultWireFormat.
   * @return The WireFormat object.
   */
  public static WireFormat
  getDefaultWireFormat()
  {
    return defaultWireFormat_;
  }

  private static WireFormat defaultWireFormat_ = TlvWireFormat.get();
}
