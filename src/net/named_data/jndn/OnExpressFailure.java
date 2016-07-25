/**
 * Copyright (C) 2016 Regents of the University of California.
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
 * A class implements OnExpressFailure if it has the method onExpressFailure,
 * used to pass a callback to Face.expressInterest so it can report a failure
 * like timeout.
 */
public interface OnExpressFailure {
  /**
   * If expressInterest encounters a failure, onExpressFailure is called.
   * @param interest The interest given to expressInterest.
   * @param reason The reason code for the failure.
   * @param details An object containing details based on the reason code. This
   * is based on the Exception class so that, as a minimum, the application can
   * call details.getMessage().
   */
  void onExpressFailure
    (Interest interest, ExpressFailureReason reason, Exception details);
}
