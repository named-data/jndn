/**
 * Copyright (C) 2013-2018 Regents of the University of California.
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
 * A class implements OnData if it has onData, used to pass a callback to
 * Face.expressInterest.
 */
public interface OnData {
  /**
   * When a matching data packet is received, onData is called.
   * @param interest The interest given to Face.expressInterest. NOTE: You must
   * not change the interest object - if you need to change it then make a copy.
   * @param data The received Data object.
   */
  void onData(Interest interest, Data data);
}
