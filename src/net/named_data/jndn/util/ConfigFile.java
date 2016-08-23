/**
 * Copyright (C) 2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From https://github.com/named-data/ndn-cxx/blob/master/src/util/config-file.hpp
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
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A ConfigFile locates, opens, and parses a library configuration file, and
 * holds the values for the application to get.
 */
public class ConfigFile {
  /**
   * Locate, open, and parse a library configuration file.
   */
  public ConfigFile() throws IOException
  {
    path_ = findConfigFile();

    if (!path_.equals(""))
      parse();
  }

  /**
   * Get the value for the key, or a default value if not found.
   * @param key The key to search for.
   * @param defaultValue The default value if the key is not found.
   * @return The value, or defaultValue if the key is not found.
   */
  public final String
  get(String key, String defaultValue)
  {
    if (config_.containsKey(key))
      return config_.get(key);
    else
      return defaultValue;
  }

  /**
   * Get the path of the configuration file.
   * @return The path or an empty string if not found.
   */
  public final String
  getPath() { return path_; }

  /**
   * Get the configuration key/value pairs.
   * @return A map of key/value pairs.
   */
  public final Map<String, String>
  getParsedConfiguration() { return config_; }

  /**
   * Look for the configuration file in these well-known locations:
   *
   * 1. $HOME/.ndn/client.conf
   * 2. /etc/ndn/client.conf
   * We don't support the C++ #define value @SYSCONFDIR@.
   *
   * @return The path of the config file or an empty string if not found.
   */
  private static String
  findConfigFile()
  {
    // NOTE: Use File because java.nio.file.Path is not available before Java 7.
    File filePath = new File
      (new File(System.getProperty("user.home", "."), ".ndn"), "client.conf");
    if (filePath.exists())
      return filePath.getAbsolutePath();

    // Ignore the C++ SYSCONFDIR.

    filePath = new File("/etc/ndn/client.conf");
    if (filePath.exists())
      return filePath.getAbsolutePath();

    return "";
  }

  /**
   * Open path_, parse the configuration file and set config_.
   */
  private void
  parse() throws IOException
  {
    if (path_.equals(""))
      throw new Error
        ("ConfigFile::parse: Failed to locate the configuration file for parsing");

    BufferedReader input;
    try {
      input = new BufferedReader(new FileReader(path_));
    } catch (FileNotFoundException ex) {
      // We don't expect this to happen since we just checked for the file.
      throw new Error(ex.getMessage());
    }

    // Use "try/finally instead of "try-with-resources" or "using"
    // which are not supported before Java 7.
    try {
      String line;
      while ((line = input.readLine()) != null) {
        line = line.trim();
        if (line.equals("") || line.charAt(0) == ';')
          // Skip empty lines and comments.
          continue;

        int iSeparator = line.indexOf('=');
        if (iSeparator < 0)
          continue;

        String key = line.substring(0, iSeparator).trim();
        String value = line.substring(iSeparator + 1).trim();

        config_.put(key, value);
      }
    } finally {
      input.close();
    }
  }

  private String path_;
  private final HashMap<String, String> config_ = new HashMap<String, String>();
}
