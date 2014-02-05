/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn;

/**
 * A class implements OnRegisterFailed if it has onRegisterFailed, used to pass 
 * a callback to Face.registerPrefix.
 */
public interface OnRegisterFailed {
  /**
   * If failed to retrieve the connected hub's ID or failed to register the 
   * prefix, onRegisterFailed is called.
   * @param prefix The prefix given to registerPrefix.
   */
  void onRegisterFailed(Name prefix);
}
