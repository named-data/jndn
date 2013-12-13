/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From code in NDN-CPP by Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.security;

/**
 * SecurityException extends Exception for errors related to NDN security.
 */
public class SecurityException extends Exception {
  public SecurityException(String message) 
  {
    super(message);
  }
}
