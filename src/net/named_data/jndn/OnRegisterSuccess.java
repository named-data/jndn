/**
 * Copyright (C) 2015-2016 Regents of the University of California.
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
 * A class implements OnRegisterSuccess if it has onRegisterSuccess, called by
 * Face.registerPrefix when registration succeeds.
 */
public interface OnRegisterSuccess {
  /**
   * Face.registerPrefix calls onRegisterSuccess when it receives a success
   * message from the forwarder.
   * @param prefix The prefix given to registerPrefix. NOTE: You must not change
   * the prefix object - if you need to change it then make a copy.
   * @param registeredPrefixId The registered prefix ID which was also returned
   * by registerPrefix.
   */
  void onRegisterSuccess(Name prefix, long registeredPrefixId);
}
