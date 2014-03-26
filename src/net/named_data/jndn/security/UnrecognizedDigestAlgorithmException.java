/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From code in NDN-CPP by Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.security;

public class UnrecognizedDigestAlgorithmException extends SecurityException {
  public UnrecognizedDigestAlgorithmException(String message) 
  {
    super(message);
  }
}
