/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn;

/**
 * A ContentType specifies the content type in a MetaInfo object.
 */
public enum ContentType {
  BLOB(0),
  // ContentType DATA is deprecated. Use BLOB.
  DATA(0),
  LINK(1),
  KEY (2),
  // ContentType ENCR, GONE and NACK are not supported in NDN-TLV encoding and 
  //   are deprecated.
  ENCR(3),
  GONE(4),
  NACK(5);
  
  ContentType (int type)
  {
    type_ = type;
  }

  public int getNumericType() { return type_; }

  private int type_;
}
