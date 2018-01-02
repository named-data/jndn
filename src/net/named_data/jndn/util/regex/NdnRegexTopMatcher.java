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

import net.named_data.jndn.Name;

public class NdnRegexTopMatcher extends NdnRegexMatcherBase {
  public NdnRegexTopMatcher(String expr, String expand)
    throws NdnRegexMatcherBase.Error
  {
    super(expr, NdnRegexExprType.TOP);
    expand_ = expand;

    compile();
  }

  public NdnRegexTopMatcher(String expr) throws NdnRegexMatcherBase.Error
  {
    super(expr, NdnRegexExprType.TOP);
    expand_ = "";

    compile();
  }

  public final boolean
  match(Name name) throws NdnRegexMatcherBase.Error
  {
    isSecondaryUsed_ = false;

    matchResult_.clear();

    if (primaryMatcher_.match(name, 0, name.size())) {
      matchResult_.clear();
      for (Name.Component component : primaryMatcher_.getMatchResult())
        matchResult_.add(component);
      return true;
    }
    else {
      if (secondaryMatcher_ != null &&
          secondaryMatcher_.match(name, 0, name.size())) {
        matchResult_.clear();
        for (Name.Component component : secondaryMatcher_.getMatchResult())
          matchResult_.add(component);
        isSecondaryUsed_ = true;
        return true;
      }

      return false;
    }
  }

  public boolean
  match(Name name, int offset, int len) throws NdnRegexMatcherBase.Error
  {
    return match(name);
  }

  public Name
  expand(String expandStr) throws NdnRegexMatcherBase.Error
  {
    Name result = new Name();

    NdnRegexBackrefManager backrefManager =
      (isSecondaryUsed_ ? secondaryBackrefManager_ : primaryBackrefManager_);

    int backrefNo = backrefManager.size();

    String expand;

    if (!expandStr.equals(""))
      expand = expandStr;
    else
      expand = expand_;

    int[] offset = new int[] { 0 };
    while (offset[0] < expand.length()) {
      String item = getItemFromExpand(expand, offset);
      if (item.charAt(0) == '<')
        result.append(item.substring(1, item.length() - 1));

      if (item.charAt(0) == '\\') {
        int index = Integer.parseInt(item.substring(1, item.length()));

        if (0 == index) {
          for (Name.Component component : matchResult_)
            result.append(component);
        }
        else if (index <= backrefNo) {
          for (Name.Component component : backrefManager.getBackref
                                            (index - 1).getMatchResult())
            result.append(component);
        }
        else
          throw new NdnRegexMatcherBase.Error("Exceed the range of back reference");
      }
    }

    return result;
  }

  public Name
  expand() throws NdnRegexMatcherBase.Error
  {
    return expand("");
  }

  public static NdnRegexTopMatcher
  fromName(Name name, boolean hasAnchor) throws NdnRegexMatcherBase.Error
  {
    String regexStr = "^";

    for (int i = 0; i < name.size(); ++i) {
      regexStr += "<";
      regexStr += convertSpecialChar(name.get(i).toEscapedString());
      regexStr += ">";
    }

    if (hasAnchor)
      regexStr += "$";

    return new NdnRegexTopMatcher(regexStr);
  }

  public static NdnRegexTopMatcher
  fromName(Name name) throws NdnRegexMatcherBase.Error
  {
    return fromName(name, false);
  }

  protected void
  compile() throws NdnRegexMatcherBase.Error
  {
    String errMsg = "Error: RegexTopMatcher.Compile(): ";

    String expr = expr_;

    if ('$' != expr.charAt(expr.length() - 1))
      expr = expr + "<.*>*";
    else
      expr = expr.substring(0, expr.length() - 1);

    if ('^' != expr.charAt(0))
      secondaryMatcher_ = new NdnRegexPatternListMatcher
        ("<.*>*" + expr, secondaryBackrefManager_);
    else
      expr = expr.substring(1, expr.length());

    primaryMatcher_ = new NdnRegexPatternListMatcher
      (expr, primaryBackrefManager_);
  }

  static private String
  getItemFromExpand(String expand, int[] offset)
    throws NdnRegexMatcherBase.Error
  {
    int begin = offset[0];

    if (expand.charAt(offset[0]) == '\\') {
      ++offset[0];
      if (offset[0] >= expand.length())
        throw new NdnRegexMatcherBase.Error("Wrong format of expand string!");

      while (offset[0] < expand.length() &&
             expand.charAt(offset[0]) <= '9' && expand.charAt(offset[0]) >= '0') {
        ++offset[0];
        if (offset[0] > expand.length())
          throw new NdnRegexMatcherBase.Error("Wrong format of expand string!");
      }

      if (offset[0] > begin + 1)
        return expand.substring(begin, offset[0]);
      else
        throw new NdnRegexMatcherBase.Error("Wrong format of expand string!");
    }
    else if (expand.charAt(offset[0]) == '<') {
      ++offset[0];
      if (offset[0] >= expand.length())
        throw new NdnRegexMatcherBase.Error("Wrong format of expand string!");

      int left = 1;
      int right = 0;
      while (right < left) {
        if (expand.charAt(offset[0]) == '<')
          ++left;
        if (expand.charAt(offset[0]) == '>')
          ++right;

        ++offset[0];
        if (offset[0] >= expand.length())
          throw new NdnRegexMatcherBase.Error("Wrong format of expand string!");
      }

      return expand.substring(begin, offset[0]);
    }
    else
      throw new NdnRegexMatcherBase.Error("Wrong format of expand string!");
  }

  private static String
  convertSpecialChar(String str)
  {
    String newStr = "";
    for (int i = 0; i < str.length(); ++i) {
      char c = str.charAt(i);
      if (c == '.' ||
          c == '[' ||
          c == '{' ||
          c == '}' ||
          c == '(' ||
          c == ')' ||
          c == '\\' ||
          c == '*' ||
          c == '+' ||
          c == '?' ||
          c == '|' ||
          c == '^' ||
          c == '$') {
        newStr += '\\';
        newStr += c;
      }
      else
        newStr += c;
    }

    return newStr;
  }

  private final String expand_;
  private NdnRegexPatternListMatcher primaryMatcher_ = null;
  private NdnRegexPatternListMatcher secondaryMatcher_ = null;
  private final NdnRegexBackrefManager primaryBackrefManager_ =
     new NdnRegexBackrefManager();
  private final NdnRegexBackrefManager secondaryBackrefManager_ =
     new NdnRegexBackrefManager();
  private boolean isSecondaryUsed_ = false;
}
