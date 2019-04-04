/**
 * Copyright (C) 2019 Regents of the University of California.
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
 * A RegistrationOptions holds the options used when registering with the
 * forwarder to specify how to forward an interest and other options. We use a
 * separate RegistrationOptions object to retain future compatibility if the
 * format of the registration command is changed.
 * (This class was renamed from ForwardingFlags, which is deprecated.)
 */
public class RegistrationOptions {
  /**
   * Create a new RegistrationOptions with "childInherit" set and all other flags
   * cleared.
   */
  public RegistrationOptions() {}

  /**
   * Create a new RegistrationOptions as a copy of the given value.
   * @param registrationOptions The RegistrationOptions to copy.
   */
  public RegistrationOptions(RegistrationOptions registrationOptions)
  {
    childInherit_ = registrationOptions.childInherit_;
    capture_ = registrationOptions.capture_;
    origin_ = registrationOptions.origin_;
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
   * Get the origin value.
   * @return The origin value, or -1 if not specified.
   */
  public final int
  getOrigin() { return origin_; }

  /**
   * Set the value of the "childInherit" flag
   * @param childInherit true to set the flag, false to clear it.
   * @return This RegistrationOptions so that you can chain calls to update values.
   */
  public final RegistrationOptions
  setChildInherit(boolean childInherit)
  {
    childInherit_ = childInherit;
    return this;
  }

  /**
   * Set the value of the "capture" flag
   * @param capture true to set the flag, false to clear it.
   * @return This RegistrationOptions so that you can chain calls to update values.
   */
  public final RegistrationOptions
  setCapture(boolean capture)
  {
    capture_ = capture;
    return this;
  }

  /**
   * Set the origin value.
   * @param origin The new origin value, or -1 for not specified.
   * @return This RegistrationOptions so that you can chain calls to update values.
   */
  public final RegistrationOptions
  setOrigin(int origin)
  {
    origin_ = origin;
    return this;
  }

  /**
   * Get an integer with the bits set according to the NFD forwarding flags as
   * used in the ControlParameters of the command interest.
   * This ignores the origin value.
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
   * @return This RegistrationOptions so that you can chain calls to update values.
   */
  public final RegistrationOptions
  setNfdForwardingFlags(int nfdForwardingFlags)
  {
    childInherit_ = (nfdForwardingFlags & NfdForwardingFlags_CHILD_INHERIT) != 0;
    capture_ = (nfdForwardingFlags & NfdForwardingFlags_CAPTURE) != 0;
    return this;
  }

  private static final int NfdForwardingFlags_CHILD_INHERIT  = 1;
  private static final int NfdForwardingFlags_CAPTURE  =       2;

  private boolean childInherit_ = true;
  private boolean capture_ = false;
  private int origin_ = -1; /**< -1 for none. */
}
