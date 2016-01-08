/**
 * Copyright (C) 2014-2016 Regents of the University of California.
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

package net.named_data.jndn;

/**
 * A ForwardingFlags object holds the flags which specify how the forwarding
 * daemon should forward an interest for a registered prefix.  We use a separate
 * ForwardingFlags object to retain future compatibility if the daemon
 * forwarding bits are changed, amended or deprecated.
 */
public class ForwardingFlags {
  /**
   * Create a new ForwardingFlags with "childInherit" set and all other flags
   * cleared.
   */
  public ForwardingFlags() {}

  /**
   * Create a new ForwardingFlags as a copy of the given value.
   * @param forwardingFlags The ForwardingFlags to copy.
   */
  public ForwardingFlags(ForwardingFlags forwardingFlags)
  {
    childInherit_ = forwardingFlags.childInherit_;
    capture_ = forwardingFlags.capture_;
  }

  /**
   * Get the value of the "childInherit" flag.
   * @return true if the flag is set, false if it is cleared.
   */
  public final boolean
  getChildInherit() { return childInherit_; }

  /**
   * Get the value of the "capture" flag.
   * @return true if the flag is set, false if it is cleared.
   */
  public final boolean
  getCapture() { return capture_; }

  /**
   * Set the value of the "childInherit" flag
   * @param childInherit true to set the flag, false to clear it.
   */
  public final void
  setChildInherit(boolean childInherit) { childInherit_ = childInherit; }

  /**
   * Set the value of the "capture" flag
   * @param capture true to set the flag, false to clear it.
   */
  public final void
  setCapture(boolean capture) { capture_ = capture; }

  /**
   * Get an integer with the bits set according to the NFD forwarding flags as
   * used in the ControlParameters of the command interest.
   * @return An integer with the bits set.
   */
  public final int
  getNfdForwardingFlags()
  {
    int result = 0;

    if (childInherit_)
      result |= NfdForwardingFlags_CHILD_INHERIT;
    if (capture_)
      result |= NfdForwardingFlags_CAPTURE;

    return result;
  }

  /**
   * Set the flags according to the NFD forwarding flags as used in the
   * ControlParameters of the command interest.
   * @param nfdForwardingFlags An integer with the bits set.
   */
  public final void
  setNfdForwardingFlags(int nfdForwardingFlags)
  {
    childInherit_ = (nfdForwardingFlags & NfdForwardingFlags_CHILD_INHERIT) != 0;
    capture_ = (nfdForwardingFlags & NfdForwardingFlags_CAPTURE) != 0;
  }

  private static final int NfdForwardingFlags_CHILD_INHERIT  = 1;
  private static final int NfdForwardingFlags_CAPTURE  =       2;

  private boolean childInherit_ = true;
  private boolean capture_ = false;
}
