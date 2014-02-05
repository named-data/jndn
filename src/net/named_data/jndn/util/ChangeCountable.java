/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.util;

/**
 * A class implements ChangeCountable if it has a method getChangeCount.  This 
 * is used by the class ChangeCounter.
 */
public interface ChangeCountable {
  /**
   * Get the change count for the object which increases monotonically when the 
   * fields of the object are changed.
   * @return The change count. 
   */
  long getChangeCount();
}
