/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn;

/**
 * A class implements OnData if it has onData, used to pass a callback to 
 * Face.expressInterest.
 */
public interface OnData {
  /**
   * When a matching data packet is received, onData is called.
   * @param interest The interest given to Face.expressInterest.
   * @param data The received Data object.
   */
  void onData(Interest interest, Data data);
}
