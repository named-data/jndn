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

package net.named_data.jndn.lp;

/**
 * CongestionMark represents the congestion mark header field in an NDNLPv2
 * packet.
 * http://redmine.named-data.net/projects/nfd/wiki/NDNLPv2
 */
public class CongestionMark {
  /**
   * Get the congestion mark value.
   * @return The congestion mark value.
   */
  public long
  getCongestionMark() { return congestionMark_; }

  /**
   * Set the congestion mark value.
   * @param congestionMark The congestion mark ID value.
   */
  public void
  setCongestionMark(long congestionMark)
  {
    congestionMark_ = congestionMark;
  }

  /**
   * Get the first header field in lpPacket which is a CongestionMark. This is
   * an internal method which the application normally would not use.
   * @param lpPacket The LpPacket with the header fields to search.
   * @return The first CongestionMark header field, or null if not found.
   */
  static public CongestionMark
  getFirstHeader(LpPacket lpPacket)
  {
    for (int i = 0; i < lpPacket.countHeaderFields(); ++i) {
      Object field = lpPacket.getHeaderField(i);
      if (field instanceof CongestionMark)
        return (CongestionMark)field;
    }

    return null;
  }

  private long congestionMark_ = 0;
}
