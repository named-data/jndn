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
 * A ContentType specifies the content type in a MetaInfo object. If the
 * content type in the packet is not a recognized enum value, then we use
 * ContentType.OTHER_CODE and you can call MetaInfo.getOtherTypeCode(). We do
 * this to keep the recognized content type values independent of packet
 * encoding formats.
 */
public enum ContentType {
  BLOB(0),
  LINK(1),
  KEY (2),
  NACK(3),
  OTHER_CODE(0x7fff);

  ContentType (int type)
  {
    type_ = type;
  }

  public final int
  getNumericType() { return type_; }

  private final int type_;
}
