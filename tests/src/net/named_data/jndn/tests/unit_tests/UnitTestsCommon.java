/**
 * Copyright (C) 2015-2017 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: Andrew Brown <andrew.brown@intel.com>
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

package net.named_data.jndn.tests.unit_tests;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import net.named_data.jndn.util.Common;

/**
 * UnitTestsCommon has static methods to help in unit tests.
 */
public class UnitTestsCommon {
  /**
   * Convert a UNIX timestamp to ISO time representation with the "T" in the middle.
   * @param msSince1970 Timestamp as milliseconds since Jan 1, 1970 UTC.
   * @return The string representation.
   */
  public static String
  toIsoString(double msSince1970)
  {
    return dateFormat.format(Common.millisecondsSince1970ToDate
      ((long)Math.round(msSince1970)));
  }

  /**
   * Convert an ISO time representation with the "T" in the middle to a UNIX
   * timestamp.
   * @param timeString The ISO time representation.
   * @return The timestamp as milliseconds since Jan 1, 1970 UTC.
   */
  public static double
  fromIsoString(String timeString) throws ParseException
  {
    return (double)Common.dateToMillisecondsSince1970
      (dateFormat.parse(timeString));
  }

  private static SimpleDateFormat
  getDateFormat()
  {
    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd'T'HHmmss");
    dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    return dateFormat;
  }

  static SimpleDateFormat dateFormat = getDateFormat();
  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
