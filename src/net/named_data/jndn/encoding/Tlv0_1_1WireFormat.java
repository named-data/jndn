/**
 * Copyright (C) 2014-2016 Regents of the University of California.
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

package net.named_data.jndn.encoding;

/**
 * A Tlv0_1_1WireFormat extends Tlv0_2WireFormat so that it is an alias in case
 * any applications use Tlv0_1_1WireFormat directly.  These two wire formats are
 * the same except that Tlv0_2WireFormat adds support for the name component
 * type ImplicitSha256Digest.
 */
public class Tlv0_1_1WireFormat extends Tlv0_2WireFormat {
  /**
   * Get a singleton instance of a Tlv0_1_1WireFormat.
   * @return The singleton instance.
   */
  public static Tlv0_1_1WireFormat
  get()
  {
    return instance_;
  }

  private static Tlv0_1_1WireFormat instance_ = new Tlv0_1_1WireFormat();
}
