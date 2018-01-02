/**
 * Copyright (C) 2016-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx fields.hpp https://github.com/named-data/ndn-cxx/blob/master/src/lp/fields.hpp
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
 * IncomingFaceId represents the incoming face ID header field in an NDNLPv2 packet.
 * http://redmine.named-data.net/projects/nfd/wiki/NDNLPv2
 */
public class IncomingFaceId {
  /**
   * Get the incoming face ID value.
   * @return The face ID value.
   */
  public long
  getFaceId() { return faceId_; }

  /**
   * Set the face ID value.
   * @param faceId The incoming face ID value.
   */
  public void
  setFaceId(long faceId)
  {
    faceId_ = faceId;
  }

  /**
   * Get the first header field in lpPacket which is an IncomingFaceId. This is
   * an internal method which the application normally would not use.
   * @param lpPacket The LpPacket with the header fields to search.
   * @return The first IncomingFaceId header field, or null if not found.
   */
  static public IncomingFaceId
  getFirstHeader(LpPacket lpPacket)
  {
    for (int i = 0; i < lpPacket.countHeaderFields(); ++i) {
      Object field = lpPacket.getHeaderField(i);
      if (field instanceof IncomingFaceId)
        return (IncomingFaceId)field;
    }

    return null;
  }

  private long faceId_ = -1;
}
