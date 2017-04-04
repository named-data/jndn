/**
 * Copyright (C) 2015-2017 Regents of the University of California.
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

import java.nio.ByteBuffer;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import net.named_data.jndn.Data;
import net.named_data.jndn.Face;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.OnData;
import net.named_data.jndn.OnTimeout;
import net.named_data.jndn.ThreadPoolFace;
import net.named_data.jndn.transport.AsyncTcpTransport;

/**
 * This uses ThreadPoolFace to call expressInterest and show the content of the
 * fetched data packets. Because it uses ThreadPoolFace, the application doesn't
 * need to call processEvents.
 */
public class TestGetAsyncThreadPool {
  /**
   * Counter counts the number of calls to the onData or onTimeout callbacks and
   * does a thread pool shutdown when finished.
   */
  static class Counter implements OnData, OnTimeout {
    /**
     * Create a Counter to call threadPool.shutdown() after maxCallbackCount
     * calls to onData or onTimeout.
     * @param threadPool The thread pool for calling shutdown().
     * @param maxCallbackCount The max number of calls to onData or onTimeout.
     */
    public Counter(ScheduledExecutorService threadPool, int maxCallbackCount)
    {
      threadPool_ = threadPool;
      maxCallbackCount_ = maxCallbackCount;
    }

    public void
    onData(Interest interest, Data data)
    {
      System.out.println
        ("Got data packet with name " + data.getName().toUri());
      ByteBuffer content = data.getContent().buf();
      for (int i = content.position(); i < content.limit(); ++i)
        System.out.print((char)content.get(i));
      System.out.println("");

      if (++callbackCount_ >= maxCallbackCount_)
        // This will exit the program.
        threadPool_.shutdown();
    }

    public void onTimeout(Interest interest)
    {
      System.out.println("Time out for interest " + interest.getName().toUri());

      if (++callbackCount_ >= maxCallbackCount_)
        // This will exit the program.
        threadPool_.shutdown();
    }

    private final ScheduledExecutorService threadPool_;
    private final int maxCallbackCount_;
    private int callbackCount_ = 0;
  }

  public static void
  main(String[] args)
  {
    try {
      final ScheduledExecutorService threadPool = Executors.newScheduledThreadPool(2);
      Face face = new ThreadPoolFace
        (threadPool, new AsyncTcpTransport(threadPool),
         new AsyncTcpTransport.ConnectionInfo("memoria.ndn.ucla.edu"));

      // Counter will stop the threadPool after callbacks for all expressInterest.
      Counter counter = new Counter(threadPool, 3);

      // Try to fetch anything.
      Name name1 = new Name("/");
      System.out.println("Express name " + name1.toUri());
      face.expressInterest(name1, counter, counter);

      // Try to fetch using a known name.
      Name name2 = new Name("/ndn/edu/ucla/remap/demo/ndn-js-test/hello.txt/%FDX%DC5%1F");
      System.out.println("Express name " + name2.toUri());
      face.expressInterest(name2, counter, counter);

      // Expect this to time out.
      Name name3 = new Name("/test/timeout");
      System.out.println("Express name " + name3.toUri());
      face.expressInterest(name3, counter, counter);

      // The application will run until Counter calls threadPool.shutdown().
    }
    catch (Exception e) {
       System.out.println("exception: " + e.getMessage());
    }
  }
}
