/**
 * Copyright (C) 2015-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From PyNDN boost_info_parser by Adeola Bannis.
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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;

/**
 * A BoostInfoParser reads files in Boost's INFO format and constructs a
 * BoostInfoTree.
 */
public class BoostInfoParser {
  /**
   * Add the contents of the file to the root BoostInfoTree.
   * @param fileName The path to the INFO file.
   * @return The new root BoostInfoTree.
   */
  public BoostInfoTree
  read(String fileName) throws IOException
  {
    BufferedReader stream = new BufferedReader(new FileReader(fileName));
    // Use "try/finally instead of "try-with-resources" or "using"
    // which are not supported before Java 7.
    try {
      read(stream, root_);
    } finally {
      stream.close();
    }

    return root_;
  }

  /**
   * Add the contents of the input string to the root BoostInfoTree.
   * @param input The contents of the INFO file, with lines separated by "\n" or
   * "\r\n".
   * @param inputName Used for log messages, etc.
   * @return The new root BoostInfoTree.
   * @throws IOException
   */
  public BoostInfoTree
  read(String input, String inputName) throws IOException
  {
    BufferedReader stream = new BufferedReader(new StringReader(input));
    read(stream, root_);

    return root_;
  }

  /**
   * Write the root tree of this BoostInfoParser as file in Boost's INFO format.
   * @param fileName The output path.
   */
  public final void
  write(String fileName) throws IOException
  {
    BufferedWriter writer = new BufferedWriter(new FileWriter(fileName));
    try {
      writer.write("" + root_);
      writer.flush();
    }
    finally{
      writer.close();
    }
  }

  /**
   * Get the root tree of this parser.
   * @return The root BoostInfoTree.
   */
  public final BoostInfoTree
  getRoot() { return root_; }

  /**
   * Similar to Python's shlex.split, split s into an array of strings which are
   * separated by whitespace, treating a string within quotes as a single entity
   * regardless of whitespace between the quotes. Also allow a backslash to
   * escape the next character.
   * @param s The input string to split.
   * @param result This appends the split strings to result which is a list of
   * String. This does not first clear the list.
   */
  private static void
  shlex_split(String s, ArrayList<String> result)
  {
    if (s.length() == 0)
      return;
    String whiteSpace = " \t\n\r";
    int iStart = 0;

    while (true) {
      // Move iStart past whitespace.
      while (whiteSpace.indexOf(s.charAt(iStart)) >= 0) {
        ++iStart;
        if (iStart >= s.length())
          // Done.
          return;
      }

      // Move iEnd to the end of the token.
      int iEnd = iStart;
      boolean inQuotation = false;
      String token = "";
      while (true) {
        if (s.charAt(iEnd) == '\\') {
          // Append characters up to the backslash, skip the backslash and
          //   move iEnd past the escaped character.
          token += s.substring(iStart, iEnd);
          iStart = iEnd + 1;
          iEnd = iStart;
          if (iEnd >= s.length()) {
            // An unusual case: A backslash at the end of the string.
            break;
          }
        }
        else {
          if (inQuotation) {
            if (s.charAt(iEnd) == '\"') {
              // Append characters up to the end quote and skip.
              token += s.substring(iStart, iEnd);
              iStart = iEnd + 1;
              inQuotation = false;
            }
          }
          else {
            if (s.charAt(iEnd) == '\"') {
              // Append characters up to the start quote and skip.
              token += s.substring(iStart, iEnd);
              iStart = iEnd + 1;
              inQuotation = true;
            }
            else {
              if (whiteSpace.indexOf(s.charAt(iEnd)) >= 0)
                break;
            }
          }
        }

        ++iEnd;
        if (iEnd >= s.length())
            break;
      }

      token += s.substring(iStart, iEnd);
      result.add(token);
      if (iEnd >= s.length())
          // Done.
          return;

      iStart = iEnd;
    }
  }

  /**
   * Internal import method with an explicit context node.
   * @param stream The stream for reading the INFO content.
   * @param ctx The node currently being populated.
   * @return The ctx.
   */
  private BoostInfoTree
  read(BufferedReader stream, BoostInfoTree ctx) throws IOException
  {
    String line = null;
    while ((line = stream.readLine()) != null)
      ctx = parseLine(line.trim(), ctx);

    return ctx;
  }

  /**
   * Internal helper method for parsing INFO files line by line.
   */
  private BoostInfoTree
  parseLine(String line, BoostInfoTree context) throws IOException
  {
    // Skip blank lines and comments.
    int commentStart = line.indexOf(';');
    if (commentStart >= 0)
      line = line.substring(0, commentStart).trim();
    if (line.length() == 0)
      return context;

    // Usually we are expecting key and optional value.
    // Use ArrayList without generics so it works with older Java compilers.
    ArrayList<String> strings = new ArrayList<String>();
    shlex_split(line, strings);
    boolean isSectionStart = false;
    boolean isSectionEnd = false;
    for (int i = 0; i < strings.size(); ++i) {
      isSectionStart = (isSectionStart || "{".equals(strings.get(i)));
      isSectionEnd = (isSectionEnd || "}".equals(strings.get(i)));
    }

    if (!isSectionStart && !isSectionEnd) {
      String key = strings.get(0);
      String val = "";
      if (strings.size() > 1)
        val = strings.get(1);

      // If it is an "#include", load the new file instead of inserting keys.
      if ("#include".equals(key)) {
        BufferedReader stream = new BufferedReader(new FileReader(val));
        // Use "try/finally instead of "try-with-resources" or "using"
        // which are not supported before Java 7.
        try {
          context = read(stream, context);
        } finally {
          stream.close();
        }
      }
      else
        context.createSubtree(key, val);

      return context;
    }

    // OK, who is the joker who put a { on the same line as the key name?!
    int sectionStart = line.indexOf('{');
    if (sectionStart > 0) {
      String firstPart = line.substring(0, sectionStart);
      String secondPart = line.substring(sectionStart);

      BoostInfoTree ctx = parseLine(firstPart, context);
      return parseLine(secondPart, ctx);
    }

    // If we encounter a {, we are beginning a new context.
    // TODO: Error if there was already a subcontext here.
    if (line.charAt(0) == '{') {
      context = context.getLastChild();
      return context;
    }

    // If we encounter a }, we are ending a list context.
    if (line.charAt(0) == '}') {
      context = context.getParent();
      return context;
    }

    throw new Error("BoostInfoParser: input line is malformed");
  }

  private BoostInfoTree root_ = new BoostInfoTree();
}
