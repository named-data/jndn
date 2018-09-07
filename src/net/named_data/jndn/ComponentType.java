/**
 * Copyright (C) 2018 Regents of the University of California.
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
 * A ComponentType specifies the recognized types of a name component. If
 * the component type in the packet is not a recognized enum value, then we
 * use ComponentType.OTHER_CODE and you can call
 * Name.Component.getOtherTypeCode(). We do this to keep the recognized
 * component type values independent of packet encoding details.
 */
public enum ComponentType {
  IMPLICIT_SHA256_DIGEST(1),
  PARAMETERS_SHA256_DIGEST(2),
  GENERIC(8),
  OTHER_CODE(0x7fff);

  ComponentType(int type)
  {
    type_ = type;
  }

  public final int
  getNumericType() { return type_; }

  private final int type_;
}
