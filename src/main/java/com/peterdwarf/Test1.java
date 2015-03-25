package com.peterdwarf;

import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class Test1 {
	Random r = new Random();

	public static void main(String[] args) {
		new Test1();
	}

	public Test1() {
		ExecutorService pool = Executors.newFixedThreadPool(200);
		for (int x = 0; x < 10000; x++) {
			pool.execute(new Runnable() {

				@Override
				public void run() {
					try {
						int s = r.nextInt(3000);
						Thread.sleep(s);
						System.out.println("end " + s);
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
				}

			});
		}

		pool.shutdown();
		try {
			if (!pool.awaitTermination(600, TimeUnit.SECONDS)) {
				pool.shutdownNow();
				if (!pool.awaitTermination(60, TimeUnit.SECONDS)) {
					System.err.println("Pool did not terminate");
				}
			}
		} catch (InterruptedException ie) {
			pool.shutdownNow();
			Thread.currentThread().interrupt();
		}
	}

}
