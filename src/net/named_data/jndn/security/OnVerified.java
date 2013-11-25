/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From code in NDN-CPP by Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.security;

import net.named_data.jndn.Data;

/**
 * A class implements OnVerified if it has onVerified which is called by verifyData to report a successful verification.
 */
public interface OnVerified {
  /**
   * When verifyData succeeds, onVerified is called.
   * @param data The data object being verified.
   */
  void onVerified(Data data);
}
