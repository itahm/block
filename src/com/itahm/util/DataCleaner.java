package com.itahm.util;

import java.io.File;
import java.util.Calendar;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

abstract public class DataCleaner implements Runnable{

	private final BlockingQueue<Long> queue = new LinkedBlockingQueue<>();
	private final Thread thread = new Thread(this);
	private File origin;
	private int depth;
	private boolean isRun = false;
	private boolean cancel = false;
	
	public DataCleaner() {
		this.thread.setDaemon(true);
		this.thread.start();
	}

	public boolean clean(File origin, int depth, int store) {
		if (!origin.isDirectory()) {
			return false;
		}
		
		this.origin = origin;
		this.depth = depth;
		
		Calendar c = Calendar.getInstance();
		
		c.set(Calendar.HOUR_OF_DAY, 0);
		c.set(Calendar.MINUTE, 0);
		c.set(Calendar.SECOND, 0);
		c.set(Calendar.MILLISECOND, 0);
		
		c.add(Calendar.DATE, store *-1);
		
		if (isRun) {
			return false;
		}
			
		this.queue.offer(c.getTimeInMillis());
			
		return isRun = true;
	}
	
	public void cancel() {
		if (isRun) {
			this.cancel = true;
		}
	}
	
	private long emptyLastData(File directory, long minDateMills, int depth) {
		File [] files = directory.listFiles();
		long count = 0;
		
		for (File file: files) {
			if (this.cancel) {
				return -1;
			}
			
			if (file.isDirectory()) {
				if (depth > 0) {
					count += emptyLastData(file, minDateMills, depth -1);
				}
				else {
					try {
						if (minDateMills > Long.parseLong(file.getName())) {
							if (deleteDirectory(file)) {
								count++;
								
								onDelete(file);
							}
						}
					}
					catch (NumberFormatException nfe) {
					}
				}
			}
		}
		
		return count;
	}
	
	public static boolean deleteDirectory(File directory) {
        if(!directory.exists() || !directory.isDirectory()) {
            return false;
        }
        
        File[] files = directory.listFiles();
        
        for (File file : files) {
            if (file.isDirectory()) {
                deleteDirectory(file);
            } else {
                file.delete();
            }
        }
         
        return directory.delete();
    }
	
	abstract public void onDelete(File file);
	abstract public void onComplete(long count, long elapse);
	
	@Override
	public void run() {
		long
			minDateMills
			,start;
		
		while (!this.thread.isInterrupted()) {
			start = System.currentTimeMillis();
			
			try {
				minDateMills = this.queue.take();
			} catch (InterruptedException ie) {
				break;
			}
			
			onComplete(emptyLastData(this.origin, minDateMills, this.depth), System.currentTimeMillis() - start);
			
			this.cancel = false;
			this.isRun = false;
		}
	}
	
	public void close() {
		this.thread.interrupt();
	}
	
}
