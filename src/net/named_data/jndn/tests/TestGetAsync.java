/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.tests;

import java.nio.ByteBuffer;
import net.named_data.jndn.Data;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.ElementListener;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.transport.TcpTransport;
import net.named_data.jndn.util.Blob;

class Counter implements ElementListener {
  public void 
  onReceivedElement(ByteBuffer element) 
  {
    if (element.get(0) == 0x04) {
      ++callbackCount_;
      try {
        Data data = new Data();
        data.wireDecode(element);

        System.out.println
          ("Got data packet with name " + data.getName().toUri());
        ByteBuffer content = data.getContent().buf();
        for (int i = content.position(); i < content.limit(); ++i)
          System.out.print((char)content.get(i));
        System.out.println("");
      } 
      catch (EncodingException e) 
      {
        System.out.println("EncodingException " + e.getMessage());
      }
    }
  }
  
  public int callbackCount_ = 0;
}

public class TestGetAsync {
  public static void 
  main(String[] args) 
  {
    try {
      // Face face("C.hub.ndn.ucla.edu", 9695);
      
      Counter counter = new Counter();

      TcpTransport transport = null;
      {
        transport = new TcpTransport();
        // Connect to port 9695 until the testbed hubs use NDNx and are 
        //   connected to the test repo.
        transport.connect(new TcpTransport.ConnectionInfo
           ("ndn-remap-p02.it.ucla.edu", 9695), counter);
      }

      Name name1 = new Name("/");
      System.out.println("Express name " + name1.toUri());
      // face.expressInterest
      //   (name1, bind(&Counter::onData, &counter, _1, _2), 
      //    bind(&Counter::onTimeout, &counter, _1));
      {
        Interest interest = new Interest(name1, 4000.0);
        Blob encoding = interest.wireEncode();
        transport.send(encoding.buf());
      }

      // The main event loop.
      while (counter.callbackCount_ < 1) {
        //face.processEvents();
        {
          transport.processEvents();
        }
        // We need to sleep for a few milliseconds so we don't use 100% of 
        //   the CPU.
        Thread.sleep(5);
      }
    }
    catch (Throwable e) {
       System.out.println("exception: " + e.getMessage());
    }
  }
}
