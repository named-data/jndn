/**
 * Copyright (C) 2015-2018 Regents of the University of California.
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
 * A class implements OnInterestCallback if it has onInterest, used to pass a
 * callback to Face.registerPrefix or Face.setInterestFilter.
 */
public interface OnInterestCallback {
  /**
   * When an interest is received which matches the interest filter, onInterest
   * is called.
   * @param prefix The Name prefix given to registerPrefix or setInterestFilter
   * (or directly to the InterestFilter constructor). NOTE: You must not change
   * the prefix object - if you need to change it then make a copy.
   * @param interest The received interest.
   * @param face You should call face.putData to supply a Data packet which
   * satisfies the Interest.
   * @param interestFilterId The interest filter ID which can be used with
   * Face.unsetInterestFilter.
   * @param filter The InterestFilter given to registerPrefix or
   * setInterestFilter, or the InterestFilter created from the Name prefix. The
   * first argument, prefix, is provided for convenience and is the same as
   * filter.getPrefix(). NOTE: You must not change the filter object - if you
   * need to change it then make a copy.
   */
  void onInterest
    (Name prefix, Interest interest, Face face, long interestFilterId,
     InterestFilter filter);
}
