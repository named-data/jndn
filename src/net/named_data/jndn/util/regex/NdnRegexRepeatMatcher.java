/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Yingdi Yu <http://irl.cs.ucla.edu/~yingdi/>
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

package net.named_data.jndn.util.regex;

import java.util.regex.Pattern;
import net.named_data.jndn.Name;

public class NdnRegexRepeatMatcher extends NdnRegexMatcherBase {
  public NdnRegexRepeatMatcher
    (String expr, NdnRegexBackrefManager backrefManager, int indicator)
    throws NdnRegexMatcherBase.Error
  {
    super(expr, NdnRegexExprType.REPEAT_PATTERN, backrefManager);
    indicator_ = indicator;

    compile();
  }

  public boolean
  match(Name name, int offset, int len) throws NdnRegexMatcherBase.Error
  {
    matchResult_.clear();

    if (0 == repeatMin_)
      if (0 == len)
        return true;

    if (recursiveMatch(0, name, offset, len)) {
      for (int i = offset; i < offset + len; ++i)
        matchResult_.add(name.get(i));
      return true;
    }
    else
      return false;
  }

  /**
   * Compile the regular expression to generate more matchers when necessary.
   */
  protected void
  compile() throws NdnRegexMatcherBase.Error
  {
    NdnRegexMatcherBase matcher;

    if ('(' == expr_.charAt(0)) {
      matcher = new NdnRegexBackrefMatcher
        (expr_.substring(0, indicator_), backrefManager_);
      backrefManager_.pushRef(matcher);
      ((NdnRegexBackrefMatcher)matcher).lateCompile();
    }
    else
      matcher = new NdnRegexComponentSetMatcher
        (expr_.substring(0, indicator_), backrefManager_);

    matchers_.add(matcher);

    parseRepetition();
  }

  private boolean
  parseRepetition() throws NdnRegexMatcherBase.Error
  {
    int exprSize = expr_.length();
    final int MAX_REPETITIONS = 32767;

    if (exprSize == indicator_) {
      repeatMin_ = 1;
      repeatMax_ = 1;

      return true;
    }
    else {
      if (exprSize == (indicator_ + 1)) {
        if ('?' == expr_.charAt(indicator_)) {
          repeatMin_ = 0;
          repeatMax_ = 1;
          return true;
        }
        if ('+' == expr_.charAt(indicator_)) {
          repeatMin_ = 1;
          repeatMax_ = MAX_REPETITIONS;
          return true;
        }
        if ('*' == expr_.charAt(indicator_)) {
          repeatMin_ = 0;
          repeatMax_ = MAX_REPETITIONS;
          return true;
        }
      }
      else {
        String repeatStruct = expr_.substring(indicator_, exprSize);
        int rsSize = repeatStruct.length();
        int min = 0;
        int max = 0;

        if (Pattern.matches("\\{[0-9]+,[0-9]+\\}", repeatStruct)) {
          int separator = repeatStruct.indexOf(',');
          min = Integer.parseInt(repeatStruct.substring(1, separator));
          max = Integer.parseInt(repeatStruct.substring
            (separator + 1, rsSize - 1));
        }
        else if (Pattern.matches("\\{,[0-9]+\\}", repeatStruct)) {
          int separator = repeatStruct.indexOf(',');
          min = 0;
          max = Integer.parseInt
            (repeatStruct.substring(separator + 1, rsSize - 1));
        }
        else if (Pattern.matches("\\{[0-9]+,\\}", repeatStruct)) {
          int separator = repeatStruct.indexOf(',');
          min = Integer.parseInt(repeatStruct.substring(1, separator));
          max = MAX_REPETITIONS;
        }
        else if (Pattern.matches("\\{[0-9]+\\}", repeatStruct)) {
          min = Integer.parseInt(repeatStruct.substring(1, rsSize - 1));
          max = min;
        }
        else
          throw new NdnRegexMatcherBase.Error
            ("Error: RegexRepeatMatcher.ParseRepetition(): Unrecognized format " +
             expr_);

        if (min > MAX_REPETITIONS || max > MAX_REPETITIONS || min > max)
          throw new NdnRegexMatcherBase.Error
            ("Error: RegexRepeatMatcher.ParseRepetition(): Wrong number " + expr_);

        repeatMin_ = min;
        repeatMax_ = max;

        return true;
      }
    }

    return false;
  }

  private boolean
  recursiveMatch(int repeat, Name name, int offset, int len)
    throws NdnRegexMatcherBase.Error
  {
    int tried = len;
    NdnRegexMatcherBase matcher = matchers_.get(0);

    if (0 < len && repeat >= repeatMax_)
      return false;

    if (0 == len && repeat < repeatMin_)
      return false;

    if (0 == len && repeat >= repeatMin_)
      return true;

    while (tried >= 0) {
      if (matcher.match(name, offset, tried) &&
          recursiveMatch(repeat + 1, name, offset + tried, len - tried))
        return true;
      --tried;
    }

    return false;
  }

  private final int indicator_;
  private int repeatMin_ = 0;
  private int repeatMax_ = 0;
}
