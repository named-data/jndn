/**
 * Copyright (C) 2013-2016 Regents of the University of California.
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

import net.named_data.jndn.transport.Transport;

/**
 * A class implements OnInterest if it has onInterest, used to pass a callback
 * to Face.registerPrefix.
 */
public interface OnInterest {
  /**
   * When an interest is received which matches the name prefix, onInterest is
   * called.
   * @param prefix The prefix given to registerPrefix. NOTE: You must not change
   * the prefix object - if you need to change it then make a copy.
   * @param interest The received interest.
   * @param transport The Transport with the connection which received the
   * interest.
   * You must encode a signed Data packet and send it using transport.send().
   * @param interestFilterId The interest filter ID which can be used with
   * Face.unsetInterestFilter.
   */
  void onInterest
    (Name prefix, Interest interest, Transport transport,
     long interestFilterId);
}
