/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.encoding;

import java.nio.ByteBuffer;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.Interest;

public class WireFormat {
  /**
   * Encode interest and return the encoding.  Your derived class should override.
   * @param interest The Interest object to encode.
   * @return A Blob containing the encoding.
   * @throws UnsupportedOperationException for unimplemented if the derived class does not override.
   */
  public Blob 
  encodeInterest(Interest interest)
  {
    throw new UnsupportedOperationException("encodeInterest is not implemented");
  }
  
  /**
   * Decode input as an interest and set the fields of the interest object.  Your derived class should override.
   * @param interest The Interest object whose fields are updated.
   * @param input The input buffer to decode.  This reads from position() to limit(), but does not change the position.
   * @throws UnsupportedOperationException for unimplemented if the derived class does not override.
   * @throws EncodingException For invalid encoding.
   */
  public void 
  decodeInterest(Interest interest, ByteBuffer input) throws EncodingException
  {
    throw new UnsupportedOperationException("decodeInterest is not implemented");
  }

  // TODO Data
  // TODO ForwardingEntry
  
  /**
   * Set the static default WireFormat used by default encoding and decoding methods.
   * @param wireFormat An object of a subclass of WireFormat.  This does not make a copy.
   */
  public static void 
  setDefaultWireFormat(WireFormat wireFormat) 
  {
    defaultWireFormat_ = wireFormat;
  }
  
  /**
   * Return the default WireFormat used by default encoding and decoding methods which was set with setDefaultWireFormat.
   * @return The WireFormat object.
   */
  public static WireFormat
  getDefaultWireFormat()
  {
    return defaultWireFormat_;
  }

  private static WireFormat defaultWireFormat_ = new BinaryXmlWireFormat();
}
