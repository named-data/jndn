/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
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
   * Create a new ForwardingFlags with "active" and "childInherit" set and all 
   * other flags cleared.
   */
  public ForwardingFlags() {}

  /**
   * Create a new ForwardingFlags as a copy of the given value.
   * @param forwardingFlags The ForwardingFlags to copy.
   */
  public ForwardingFlags(ForwardingFlags forwardingFlags) 
  {
    active_ = forwardingFlags.active_;
    childInherit_ = forwardingFlags.childInherit_;
    advertise_ = forwardingFlags.advertise_;
    last_ = forwardingFlags.last_;
    capture_ = forwardingFlags.capture_;
    local_ = forwardingFlags.local_;
    tap_ = forwardingFlags.tap_;
    captureOk_ = forwardingFlags.captureOk_;
  }
  
  /**
   * Get the value of the "active" flag.
   * @return true if the flag is set, false if it is cleared.
   */
  public final boolean 
  getActive() { return active_; }
  
  /**
   * Get the value of the "childInherit" flag.
   * @return true if the flag is set, false if it is cleared.
   */
  public final boolean 
  getChildInherit() { return childInherit_; }
  
  /**
   * Get the value of the "advertise" flag.
   * @return true if the flag is set, false if it is cleared.
   */
  public final boolean 
  getAdvertise() { return advertise_; }
  
  /**
   * Get the value of the "last" flag.
   * @return true if the flag is set, false if it is cleared.
   */
  public final boolean 
  getLast() { return last_; }
  
  /**
   * Get the value of the "capture" flag.
   * @return true if the flag is set, false if it is cleared.
   */
  public final boolean 
  getCapture() { return capture_; }
  
  /**
   * Get the value of the "local" flag.
   * @return true if the flag is set, false if it is cleared.
   */
  public final boolean 
  getLocal() { return local_; }
  
  /**
   * Get the value of the "tap" flag.
   * @return true if the flag is set, false if it is cleared.
   */
  public final boolean 
  getTap() { return tap_; }
  
  /**
   * Get the value of the "captureOk" flag.
   * @return true if the flag is set, false if it is cleared.
   */
  public final boolean 
  getCaptureOk() { return captureOk_; }

  /**
   * Set the value of the "active" flag
   * @param active true to set the flag, false to clear it.
   */  
  public final void 
  setActive(boolean active) { active_ = active; }
  
  /**
   * Set the value of the "childInherit" flag
   * @param childInherit true to set the flag, false to clear it.
   */  
  public final void 
  setChildInherit(boolean childInherit) { childInherit_ = childInherit; }
  
  /**
   * Set the value of the "advertise" flag
   * @param advertise true to set the flag, false to clear it.
   */  
  public final void 
  setAdvertise(boolean advertise) { advertise_ = advertise; }
  
  /**
   * Set the value of the "last" flag
   * @param last true to set the flag, false to clear it.
   */  
  public final void 
  setLast(boolean last) { last_ = last; }
  
  /**
   * Set the value of the "capture" flag
   * @param capture true to set the flag, false to clear it.
   */  
  public final void 
  setCapture(boolean capture) { capture_ = capture; }
  
  /**
   * Set the value of the "local" flag
   * @param local true to set the flag, false to clear it.
   */  
  public final void 
  setLocal(boolean local) { local_ = local; }
  
  /**
   * Set the value of the "tap" flag
   * @param tap true to set the flag, false to clear it.
   */  
  public final void 
  setTap(boolean tap) { tap_ = tap; }
  
  /**
   * Set the value of the "captureOk" flag
   * @param captureOk true to set the flag, false to clear it.
   */  
  public final void 
  setCaptureOk(boolean captureOk) { captureOk_ = captureOk; }

  /**
   * Get an integer with the bits set according to the flags as used by the 
   * ForwardingEntry message.
   * @return An integer with the bits set.
   */
  public final int 
  getForwardingEntryFlags()
  {
    int result = 0;

    if (active_)
      result |= ACTIVE;
    if (childInherit_)
      result |= CHILD_INHERIT;
    if (advertise_)
      result |= ADVERTISE;
    if (last_)
      result |= LAST;
    if (capture_)
      result |= CAPTURE;
    if (local_)
      result |= LOCAL;
    if (tap_)
      result |= TAP;
    if (captureOk_)
      result |= CAPTURE_OK;

    return result;
  }
  
  /**
   * Set the flags according to the bits in forwardingEntryFlags as used by the 
   * ForwardingEntry message.
   * @param forwardingEntryFlags An integer with the bits set.
   */
  public final void
  setForwardingEntryFlags(int forwardingEntryFlags)
  {
    active_ = (forwardingEntryFlags & ACTIVE) != 0;
    childInherit_ = (forwardingEntryFlags & CHILD_INHERIT) != 0;
    advertise_ = (forwardingEntryFlags & ADVERTISE) != 0;
    last_ = (forwardingEntryFlags & LAST) != 0;
    capture_ = (forwardingEntryFlags & CAPTURE) != 0;
    local_ = (forwardingEntryFlags & LOCAL) != 0;
    tap_ = (forwardingEntryFlags & TAP) != 0;
    captureOk_ = (forwardingEntryFlags & CAPTURE_OK) != 0;
  }
  
  private static final int ACTIVE         = 1;
  private static final int CHILD_INHERIT  = 2;
  private static final int ADVERTISE      = 4;
  private static final int LAST           = 8;
  private static final int CAPTURE       = 16;
  private static final int LOCAL         = 32;
  private static final int TAP           = 64;
  private static final int CAPTURE_OK   = 128;
  
  private boolean active_ = true;
  private boolean childInherit_ = true;
  private boolean advertise_ = false;
  private boolean last_ = false;
  private boolean capture_ = false;
  private boolean local_ = false;
  private boolean tap_ = false;
  private boolean captureOk_ = false;
}
