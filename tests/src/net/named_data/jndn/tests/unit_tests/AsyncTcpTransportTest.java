package net.named_data.jndn.tests.unit_tests;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import net.named_data.jndn.transport.AsyncTcpTransport;

public class AsyncTcpTransportTest {
	int count = 0;
	int port = 3098;
	AsyncTcpTransport transport;

	@Before
	public void setup() {
		count = 0;
		ScheduledExecutorService pool = Executors.newScheduledThreadPool(3);
		transport = new AsyncTcpTransport(pool);
		AsyncTcpTransport.ConnectionInfo cinfo = new AsyncTcpTransport.ConnectionInfo("localhost", port, false);
		try {
			transport.connect(cinfo, null, null);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@After
	public void cleanup() {
		stopServer();
	}

	@Test
	public void testWithoutServerInitiallyOn() {
		for (int i = 0; i < 10; i++) {
			try {
				transport.send(ByteBuffer.wrap("ping1\n".getBytes()));
			} catch (IOException e) {

			}
		}

		startServer(port);


		// allow reconnect enough time to complete
		sleep(8000);

		// reset count
		count = 0;

		for (int i = 0; i < 5; i++) {
			try {
				transport.send(ByteBuffer.wrap("ping1\n".getBytes()));
			} catch (IOException e) {
			}
			sleep(1000);
		}

		// allow the server enough time to collect the pings
		sleep(1000);
		assertEquals(5, count);
	}

	@Test
	public void testWithServerRebootWhileSending() {
		startServer(port);

		for (int i = 0; i < 10; i++) {
			try {
				transport.send(ByteBuffer.wrap("ping1\n".getBytes()));
			} catch (IOException e) {
				e.printStackTrace();
			}
			sleep(1000);
		}

		// allow server to collect all the pings
		sleep(1000);

		assertEquals(10, count);

		stopServer();

		// readHandler.resetCount();

		count = 0;
		for (int i = 0; i < 5; i++) {
			try {
				transport.send(ByteBuffer.wrap("ping2\n".getBytes()));
			} catch (IOException e) {
			}
			sleep(1000);
		}

		// allow server if it is up to collect
		sleep(1000);
		assertEquals(0, count);

		startServer(port);

		for (int i = 0; i < 8; i++) {
			try {
				transport.send(ByteBuffer.wrap("ping3\n".getBytes()));
			} catch (IOException e) {
				fail();
			}
		}

		// allow server time to collect
		sleep(1000);
		assertEquals(8, count);
	}

	@Test
	public void testWithServerRebootWhileIdling() {
		int port = 3098;

		count = 0;

		startServer(port);

		ScheduledExecutorService pool = Executors.newScheduledThreadPool(3);
		AsyncTcpTransport transport = new AsyncTcpTransport(pool);
		AsyncTcpTransport.ConnectionInfo cinfo = new AsyncTcpTransport.ConnectionInfo("localhost", port, false);

		try {
			transport.connect(cinfo, null, null);
			for (int i = 0; i < 10; i++) {
				try {
					transport.send(ByteBuffer.wrap("ping1\n".getBytes()));
					sleep(2000);
				} catch (Throwable e) {
					e.printStackTrace();
				}
			}

			// sleep long time to make sure everybody is idling
			sleep(10000);

			stopServer();
			// reboot while everything is idling
			startServer(port);

			/*
			 * to trigger the reconnect we need at least two send try reason is
			 * the current channel thinks it is still connected but the first
			 * write will be completed the second write will fail which will
			 * trigger the reconnect logic
			 */
			for (int i = 0; i < 2; i++) {
				try {
					transport.send(ByteBuffer.wrap("ping4\n".getBytes()));
				} catch (IOException e) {
					e.printStackTrace();
				}
				sleep(1000);
			}

			// enough time to complete reconnect
			sleep(10000);
			count = 0;

			for (int i = 0; i < 2; i++) {
				try {
					transport.send(ByteBuffer.wrap("ping5\n".getBytes()));
				} catch (IOException e) {
					e.printStackTrace();
				}
			}

			sleep(1000);
			assertEquals(2, count);
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	private void sleep(long ms) {
		try {
			Thread.sleep(ms);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

	private void stopServer() {
		try {
			transport.send(ByteBuffer.wrap("exit\n".getBytes()));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		sleep(3000);
	}

	private void startServer(final int port) {
		new Thread(new Runnable() {
			public void run() {
				ServerSocket server = null;
				try {
					server = new ServerSocket(port);
					System.out.println("Server socket created");
					Socket socket = server.accept();
					System.out.println("client accepted");
					LineNumberReader reader = new LineNumberReader(new InputStreamReader(socket.getInputStream()));
					String line = null;
					while ((line = reader.readLine()) != null) {
						System.out.println("received:" + line);
						if ("exit".equals(line)) {
							System.out.println("shutdown server");
							break;
						} else {
							count++;
						}
					}
					reader.close();
					socket.close();
				} catch (Exception e) {
					e.printStackTrace();
				} finally {
					if (server != null) {
						try {
							server.close();
						} catch (IOException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
				}
			}
		}).start();
		sleep(10000);   //wait 10 sec for client to reconnect
	}
}
