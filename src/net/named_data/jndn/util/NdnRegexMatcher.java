/**
 * Copyright (C) 2015-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From PyNDN ndn_regex.py by Adeola Bannis.
 * Originally from Yingdi Yu <http://irl.cs.ucla.edu/~yingdi/>.
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

package net.named_data.jndn.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.named_data.jndn.Name;

/**
 * An NdnRegexMatcher has static methods to convert an NDN regex
 * (http://redmine.named-data.net/projects/ndn-cxx/wiki/Regex) to a Regex that
 * can match against URIs.
 */
public class NdnRegexMatcher {
  /**
   * Determine if the provided NDN regex matches the given Name.
   * @param pattern The NDN regex.
   * @param name The Name to match against the regex.
   * @return The Matcher object from Pattern.matcher after the first find, or
   * null if the pattern does not match.
   */
  public static Matcher
  match(String pattern, Name name)
  {
    String nameUri = name.toUri();

    pattern = sanitizeSets(pattern);

    pattern = pattern.replaceAll("<>", "(?:<.+?>)");
    pattern = pattern.replaceAll(">", "");
    pattern = pattern.replaceAll("<(?!!)", "/");

    Matcher match = Pattern.compile(pattern).matcher(nameUri);
    if (match.find())
      return match;
    else
      return null;
  }

  private static String
  sanitizeSets(String pattern)
  {
    String newPattern = pattern;

    // Positive sets can be changed to (comp1|comp2).
    // Negative sets must be changed to negative lookahead assertions.

    Pattern regex1 = Pattern.compile("\\[(\\^?)(.*?)\\]");
    Matcher match = regex1.matcher(pattern);
    while (match.find()) {
      // Insert | between components.
      int start = match.start(2);
      int end = match.end(2);
      if (start - end == 0)
        continue;
      String oldStr = match.group(2);
      String newStr = oldStr.replace("><", ">|<");
      newPattern = newPattern.substring(0, start) + newStr + newPattern.substring(end);
    }

    // Replace [] with (),  or (?! ) for negative lookahead.
    // If we use negative lookahead, we also have to consume one component.
    boolean isNegative = newPattern.contains("[^");
    if (isNegative) {
      newPattern = newPattern.replace("[^", "(?:(?!");
      newPattern = newPattern.replace("]", ")(?:/.*)*)");
    }
    else {
      newPattern = newPattern.replace("[", "(");
      newPattern = newPattern.replace("]", ")");
    }

    return newPattern;
  }
}
