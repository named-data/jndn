/**
 * Copyright (C) 2014 Regents of the University of California.
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
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
