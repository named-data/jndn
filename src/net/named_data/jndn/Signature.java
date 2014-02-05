/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn;
import net.named_data.jndn.util.ChangeCountable;

/**
 * A Signature is an abstract base class providing methods to work with the 
 * signature information in a Data packet.
 * You must create an object of a subclass, for example Sha256WithRsaSignature.
 */
public abstract class Signature implements ChangeCountable {
  /**
   * Return a new Signature which is a deep copy of this signature.
   * This is abstract, the subclass must implement it.
   * @return A new Sha256WithRsaSignature.
   * @throws CloneNotSupportedException 
   */
  @Override
  public abstract Object clone() throws CloneNotSupportedException;
  
  /**
   * Get the change count, which is incremented each time this object 
   * (or a child object) is changed.
   * @return The change count.
   */
  @Override
  public abstract long getChangeCount();
}
