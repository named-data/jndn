/**
 * Copyright (C) 2013-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From code in ndn-cxx by Yingdi Yu <yingdi@cs.ucla.edu>
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

package net.named_data.jndn.encoding;

import net.named_data.jndn.util.Common;

public class OID {
  public OID(String oid)
  {
    String[] splitString = oid.split("\\.");
    oid_ = new int[splitString.length];
    for (int i = 0; i < oid_.length; ++i)
      oid_[i] = Integer.parseInt(splitString[i]);
  }

  public OID(int[] oid)
  {
    setIntegerList(oid);
  }

  public final int[]
  getIntegerList() { return oid_; }

  public final void
  setIntegerList(int[] oid)
  {
    oid_ = new int[oid.length];
    for (int i = 0; i < oid_.length; ++i)
      oid_[i] = oid[i];
  }

  public String
  toString()
  {
    String result = "";
    for (int i = 0; i < oid_.length; ++i) {
      if (i != 0)
        result += ".";
      result += oid_[i];
    }

    return result;
  }

  public final boolean
  equals(OID other)
  {
    if (other == null || oid_.length != other.oid_.length)
      return false;

    for (int i = 0; i < oid_.length; ++i) {
      if (oid_[i] != other.oid_[i])
        return false;
    }
    return true;
  }

  public boolean
  equals(Object other)
  {
    if (!(other instanceof OID))
      return false;

    return equals((OID)other);
  }

  private int[] oid_ = new int[0];
  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
