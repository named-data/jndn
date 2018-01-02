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

import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.named_data.jndn.Name;

public class NdnRegexComponentMatcher extends NdnRegexMatcherBase {
  /**
   * Create a RegexComponent matcher from expr.
   * @param expr The standard regular expression to match a component.
   * @param backrefManager The back reference manager.
   * @param isExactMatch The flag to provide exact match.
   */
  public NdnRegexComponentMatcher
    (String expr, NdnRegexBackrefManager backrefManager, boolean isExactMatch)
    throws NdnRegexMatcherBase.Error
  {
    super(expr, NdnRegexExprType.COMPONENT, backrefManager);
    isExactMatch_ = isExactMatch;

    compile();
  }

  public NdnRegexComponentMatcher
    (String expr, NdnRegexBackrefManager backrefManager)
    throws NdnRegexMatcherBase.Error
  {
    super(expr, NdnRegexExprType.COMPONENT, backrefManager);
    isExactMatch_ = true;

    compile();
  }

  public boolean
  match(Name name, int offset, int len) throws NdnRegexMatcherBase.Error
  {
    matchResult_.clear();

    if (expr_.equals("")) {
      matchResult_.add(name.get(offset));
      return true;
    }

    if (isExactMatch_) {
      String targetStr = name.get(offset).toEscapedString();
      Matcher subResult = componentRegex_.matcher(targetStr);
      if (subResult.find()) {
        for (int i = 1; i <= subResult.groupCount(); ++i) {
          pseudoMatchers_.get(i).resetMatchResult();
          pseudoMatchers_.get(i).setMatchResult(subResult.group(i));
        }

        matchResult_.add(name.get(offset));
        return true;
      }
    }
    else
      throw new NdnRegexMatcherBase.Error
        ("Non-exact component search is not supported yet");

    return false;
  }

  /**
   * Compile the regular expression to generate more matchers when necessary.
   */
  protected void
  compile() throws NdnRegexMatcherBase.Error
  {
    componentRegex_ = Pattern.compile(expr_);

    pseudoMatchers_.clear();
    pseudoMatchers_.add(new NdnRegexPseudoMatcher());

    // Imitate C++ mark_count by just counting the number of open parentheses.
    if (expr_.contains("\\("))
      // We don't expect escaped parentheses, so don't try to handle them.
      throw new NdnRegexMatcherBase.Error
        ("Can't count subexpressions in regex with escaped parentheses: " + expr_);
    int markCount = 0;
    for (int i = 0; i < expr_.length(); ++i) {
      if (expr_.charAt(i) == '(')
        ++markCount;
    }

    for (int i = 1; i <= markCount; ++i) {
      NdnRegexPseudoMatcher pMatcher = new NdnRegexPseudoMatcher();
      pseudoMatchers_.add(pMatcher);
      backrefManager_.pushRef(pMatcher);
    }
  }

  private final boolean isExactMatch_;
  private Pattern componentRegex_;
  private final ArrayList<NdnRegexPseudoMatcher> pseudoMatchers_ =
    new ArrayList<NdnRegexPseudoMatcher>();
}
