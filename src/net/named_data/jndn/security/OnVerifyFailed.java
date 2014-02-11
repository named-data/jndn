/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From code in NDN-CPP by Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.security;

import net.named_data.jndn.Data;

/**
 * A class implements OnVerifyFailed if it has onVerifyFailed which is called by verifyData to report a failed verification.
 */
public interface OnVerifyFailed {
  /**
   * When verifyData fails, onVerifyFailed is called.
   * @param data The data object being verified.
   */
  void onVerifyFailed(Data data);
}
