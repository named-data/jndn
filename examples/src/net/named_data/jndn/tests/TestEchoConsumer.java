/**
 * Copyright (C) 2014-2017 Regents of the University of California.
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

package net.named_data.jndn.tests;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import net.named_data.jndn.Data;
import net.named_data.jndn.Face;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.OnData;
import net.named_data.jndn.OnTimeout;

class Counter1 implements OnData, OnTimeout {
  public void
  onData(Interest interest, Data data)
  {
    ++callbackCount_;
    System.out.println
      ("Got data packet with name " + data.getName().toUri());
    ByteBuffer content = data.getContent().buf();
    for (int i = content.position(); i < content.limit(); ++i)
      System.out.print((char)content.get(i));
    System.out.println("");
  }

  public int callbackCount_ = 0;

  public void onTimeout(Interest interest)
  {
    ++callbackCount_;
    System.out.println("Time out for interest " + interest.getName().toUri());
  }
}

public class TestEchoConsumer {
  public static void
  main(String[] args)
  {
    try {
      Face face = new Face();

      Counter1 counter = new Counter1();

      System.out.println("Enter a word to echo:");
      BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
      String word = reader.readLine();

      Name name = new Name("/testecho");
      name.append(word);
      System.out.println("Express name " + name.toUri());
      face.expressInterest(name, counter, counter);

      // The main event loop.
      while (counter.callbackCount_ < 1) {
        face.processEvents();

        // We need to sleep for a few milliseconds so we don't use 100% of
        //   the CPU.
        Thread.sleep(5);
      }
    }
    catch (Exception e) {
       System.out.println("exception: " + e.getMessage());
    }
  }
}
