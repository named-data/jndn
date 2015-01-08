/**
 * Copyright (C) 2013-2015 Regents of the University of California.
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

import java.util.Arrays;

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
    oid_ = Arrays.copyOf(oid, oid.length);
  }

  public final int[]
  getIntegerList() { return oid_; }

  public final void
  setIntegerList(int[] oid)
  {
    oid_ = Arrays.copyOf(oid, oid.length);
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
    return Arrays.equals(oid_, other.oid_);
  }

  public boolean
  equals(Object other)
  {
    if (!(other instanceof OID))
      return false;

    return equals((OID)other);
  }

  // Use a non-template ArrayList so it works with older Java compilers.
  int[] oid_ = new int[0];
}
