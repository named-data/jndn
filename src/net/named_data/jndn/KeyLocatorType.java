/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn;

/**
 * A KeyLocatorType specifies the key locator type in a KeyLocator object.
 */
public enum KeyLocatorType {
  NONE(0), 
  KEYNAME(1),
  KEY_LOCATOR_DIGEST(2),
  KEY(3), 
  CERTIFICATE(4);
  
  KeyLocatorType (int type)
  {
    type_ = type;
  }

  public int getNumericType() { return type_; }

  private int type_;
}
