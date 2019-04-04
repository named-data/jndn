/**
 * Copyright (C) 2014-2019 Regents of the University of California.
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
 * @deprecated Use RegistrationOptions.
 */
public class ForwardingFlags extends RegistrationOptions {
  /**
   * Create a new ForwardingFlags with "childInherit" set and all other flags
   * cleared.
   */
  public ForwardingFlags()
  {
  }

  /**
   * Create a new ForwardingFlags as a copy of the given value.
   * @param forwardingFlags The ForwardingFlags to copy.
   */
  public ForwardingFlags(RegistrationOptions forwardingFlags)
  {
    super(forwardingFlags);
  }
}
