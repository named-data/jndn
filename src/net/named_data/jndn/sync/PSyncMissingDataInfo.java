/**
 * Copyright (C) 2019 Regents of the University of California.
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

package net.named_data.jndn.sync;

import net.named_data.jndn.Name;

public class PSyncMissingDataInfo {
  public PSyncMissingDataInfo
    (Name prefix, int lowSequenceNo, int highSequenceNo)
  {
    // Copy the Name.
    prefix_ = new Name(prefix);
    lowSequenceNo_ = lowSequenceNo;
    highSequenceNo_ = highSequenceNo;
  }

  public Name prefix_;
  public int lowSequenceNo_;
  public int highSequenceNo_;
}
