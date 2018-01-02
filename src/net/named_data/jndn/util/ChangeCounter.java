/**
 * Copyright (C) 2014-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU Lesser General Public License is in the file COPYING.
 */

package net.named_data.jndn.util;

/**
 * A ChangeCounter keeps a pointer to a target ChangeCountable whose change
 * count is tracked by a local change count.  You can set to a new target which
 * updates the local change count, and you can call checkChanged
 * to check if the target (or one of the target's targets) has been changed.
 */
public class ChangeCounter {
  /**
   * Create a new ChangeCounter to track the given target. If target is not null,
   * this sets the local change counter to target.getChangeCount().
   * @param target The target to track. This may be null.
   */
  public ChangeCounter(ChangeCountable target)
  {
    target_ = target;
    changeCount_ = (target_ == null ? 0 : target_.getChangeCount());
  }

  /**
   * Get the target object.  If the target is changed, then checkChanged will
   * detect it.
   * @return The target object.
   */
  public final ChangeCountable get() { return target_; }

  /**
   * Set the target to the given target.  If target is not null, this sets the
   * local change counter to target.getChangeCount().
   * @param target The target to track. This may be null.
   */
  public final void set(ChangeCountable target)
  {
    target_ = target;
    changeCount_ = (target_ == null ? 0 : target_.getChangeCount());
  }

  /**
   * If the target's change count is different than the local change count, then
   * update the local change count and return true.  Otherwise return false,
   * meaning that the target has not changed. Also, if the target is null,
   * simply return false.This is useful since the target (or one of the target's
   * targets) may be changed and you need to find out.
   * @return True if the change count has been updated, false if not.
   */
  public final boolean checkChanged()
  {
    if (target_ == null)
      return false;

    long targetChangeCount = target_.getChangeCount();
    if (changeCount_ != targetChangeCount) {
      changeCount_ = targetChangeCount;
      return true;
    }
    else
      return false;
  }

  private ChangeCountable target_;
  private long changeCount_;
}
