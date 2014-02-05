/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn;

import net.named_data.jndn.transport.Transport;

/**
 * A class implements OnInterest if it has onInterest, used to pass a callback 
 * to Face.registerPrefix.
 */
public interface OnInterest {
  /**
   * When an interest is received which matches the name prefix, onInterest is 
   * called.
   * @param prefix The prefix given to registerPrefix.
   * @param interest The received interest.
   * @param transport The Transport with the connection which received the 
   * interest. 
   * You must encode a signed Data packet and send it using transport.send().
   * @param registeredPrefixId The registered prefix ID which can be used with 
   * Face.removeRegisteredPrefix.
   */
  void onInterest
    (Name prefix, Interest interest, Transport transport, 
     int registeredPrefixId);
}
