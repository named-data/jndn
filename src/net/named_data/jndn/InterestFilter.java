/**
 * Copyright (C) 2015-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx interest-filter https://github.com/named-data/ndn-cxx
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

import net.named_data.jndn.util.Common;
import net.named_data.jndn.util.NdnRegexMatcher;

/**
 * An InterestFilter holds a Name prefix and optional regex match expression for
 * use in Face.setInterestFilter.
 */
public class InterestFilter {
  /**
   * Create an InterestFilter to match any Interest whose name starts with the
   * given prefix.
   * @param prefix The prefix Name. This makes a copy of the Name.
   */
  public InterestFilter(Name prefix)
  {
    prefix_ = new Name(prefix);
    regexFilter_ = null;
    regexFilterPattern_ = null;
  }

  /**
   * Create an InterestFilter to match any Interest whose name starts with the
   * given prefix.
   * @param prefixUri The URI of the prefix Name.
   */
  public InterestFilter(String prefixUri)
  {
    prefix_ = new Name(prefixUri);
    regexFilter_ = null;
    regexFilterPattern_ = null;
  }

  /**
   * Create an InterestFilter to match any Interest whose name starts with the
   * given prefix and the remaining components match the regexFilter regular
   * expression as described in doesMatch.
   * @param prefix The prefix Name. This makes a copy of the Name.
   * @param regexFilter The regular expression for matching the remaining name
   * components.
   */
  public InterestFilter(Name prefix, String regexFilter)
  {
    prefix_ = new Name(prefix);
    regexFilter_ = regexFilter;
    regexFilterPattern_ = makePattern(regexFilter);
  }

  /**
   * Create an InterestFilter to match any Interest whose name starts with the
   * given prefix URI and the remaining components match the regexFilter regular
   * expression as described in doesMatch.
   * @param prefixUri The URI of the prefix Name.
   * @param regexFilter The regular expression for matching the remaining name
   * components.
   */
  public InterestFilter(String prefixUri, String regexFilter)
  {
    prefix_ = new Name(prefixUri);
    regexFilter_ = regexFilter;
    regexFilterPattern_ = makePattern(regexFilter);
  }

  /**
   * Create an InterestFilter which is a copy of the given interestFilter.
   * @param interestFilter The InterestFilter with values to copy from.
   */
  public InterestFilter(InterestFilter interestFilter)
  {
    // Make a deep copy of the Name.
    prefix_ = new Name(interestFilter.prefix_);
    regexFilter_ = interestFilter.regexFilter_;
    regexFilterPattern_ = interestFilter.regexFilterPattern_;
  }

  /**
   * Check if the given name matches this filter. Match if name starts with this
   * filter's prefix. If this filter has the optional regexFilter then the
   * remaining components match the regexFilter regular expression.
   * For example, the following InterestFilter:
   *
   *    InterestFilter("/hello", "&lt;world&gt;&lt;&gt;+")
   *
   * will match all Interests, whose name has the prefix `/hello` which is
   * followed by a component `world` and has at least one more component after it.
   * Examples:
   *
   *    /hello/world/!
   *    /hello/world/x/y/z
   *
   * Note that the regular expression will need to match all remaining components
   * (e.g., there are implicit heading `^` and trailing `$` symbols in the
   * regular expression).
   * @param name The name to check against this filter.
   * @return True if name matches this filter, otherwise false.
   */
  public final boolean
  doesMatch(Name name)
  {
    if (name.size() < prefix_.size())
      return false;

    if (hasRegexFilter()) {
      // Perform a prefix match and regular expression match for the remaining
      // components.
      if (!prefix_.match(name))
        return false;

      return null != NdnRegexMatcher.match
        (regexFilterPattern_, name.getSubName(prefix_.size()));
    }
    else
      // Just perform a prefix match.
      return prefix_.match(name);
  }

  /**
   * Get the prefix given to the constructor.
   * @return The prefix Name which you should not modify.
   */
  public final Name
  getPrefix() { return prefix_; }

  /**
   * Check if a regexFilter was supplied to the constructor.
   * @return True if a regexFilter was supplied to the constructor.
   */
  public final boolean
  hasRegexFilter() { return regexFilter_ != null; }

  /**
   * Get the regex filter. This is only valid if hasRegexFilter() is true.
   * @return The regular expression for matching the remaining name components.
   */
  public final String
  getRegexFilter() { return regexFilter_; }

  /**
   * If regexFilter doesn't already have them, add ^ to the beginning and $ to
   * the end since these are required by NdnRegexMatcher.match.
   * @param regexFilter The regex filter.
   * @return The regex pattern with ^ and $.
   */
  private static String
  makePattern(String regexFilter)
  {
    String pattern = regexFilter;
    if (!pattern.startsWith("^"))
      pattern = "^" + pattern;
    if (!pattern.endsWith("$"))
      pattern = pattern + "$";

    return pattern;
  }

  private final Name prefix_;
  private final String regexFilter_;
  private final String regexFilterPattern_;
  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
