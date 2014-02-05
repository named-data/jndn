/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn;

/**
 * A class implements OnTimeout if it has onTimeout, used to pass a callback to 
 * Face.expressInterest.
 */
public interface OnTimeout {
  /**
   * If the interest times out according to the interest lifetime, onTimeout is 
   * called.
   * @param interest The interest given to expressInterest.
   */
  void onTimeout(Interest interest);
}
