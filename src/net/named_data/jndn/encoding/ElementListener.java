/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.encoding;

import java.nio.ByteBuffer;

/**
 * A class implements ElementListener if it has onReceivedElement which is used 
 * by BinaryXmlElementReader.onReceivedData.  
 */
public interface ElementListener 
{
  /**
   * This is called when an entire binary XML element is received.
   * @param element The binary XML element.  This buffer is only valid during 
   * this call.  If you need the data
   * later, you must copy.
   */
  void onReceivedElement(ByteBuffer element);
}
