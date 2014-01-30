/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.util;

/**
 * A ChangeCounter keeps a pointer to a target ChangeCountable whose change count is tracked by a local
 * change count.  You can set to a new target which updates the local change count, and you can call checkChanged
 * to check if the target (or one of the target's targets has been changed.
 * @param <T> The type of the target which also implements ChangeCountable.
 */
public class ChangeCounter<T extends ChangeCountable> {
  /**
   * Create a new ChangeCounter to track the given target.  This sets the local change counter to target.getChangeCount().
   * @param target The target to track.
   */
  public ChangeCounter(T target)
  {
    target_ = target;
    changeCount_ = target_.getChangeCount();
  }
  
  /**
   * Get the target object.  If the target is changed, then checkChanged will detect it.
   * @return The target object.
   */
  public final T get() { return target_; }

  /**
   * Set the target to the given target.  This sets the local change counter to target.getChangeCount().
   * @param target The target to track.
   */
  public final void set(T target) 
  {
    target_ = target;
    changeCount_ = target_.getChangeCount();
  }
  
  /**
   * Check if the target's change count is different than the local change count, then update the local change count
   * and return true.  Otherwise return false, meaning that the target has not changed.  This is useful since the
   * target (or one of the target's targets) may be changed and you need to find out.
   * @return True if the change count has been updated, false if not.
   */
  public final boolean checkChanged()
  {
    long targetChangeCount = target_.getChangeCount();
    if (changeCount_ != targetChangeCount) {
      changeCount_ = targetChangeCount;
      return true;
    }
    else
      return false;
  }
          
  private T target_;
  private long changeCount_;
}
