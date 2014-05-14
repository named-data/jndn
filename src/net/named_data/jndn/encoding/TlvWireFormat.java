/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.encoding;

/**
 * A TlvWireFormat extends WireFormat to override its methods to 
 * implement encoding and decoding using the preferred implementation of 
 * NDN-TLV.
 */
public class TlvWireFormat extends Tlv0_1WireFormat {
  /**
   * Get a singleton instance of a TlvWireFormat.  Assuming that the default 
   * wire format was set with 
   * WireFormat.setDefaultWireFormat(TlvWireFormat.get()), you can check if this 
   * is the default wire encoding with
   * if (WireFormat.getDefaultWireFormat() == TlvWireFormat.get()).
   * @return The singleton instance.
   */
  public static TlvWireFormat
  get()
  {
    return instance_;
  }

  private static TlvWireFormat instance_ = new TlvWireFormat();
}
