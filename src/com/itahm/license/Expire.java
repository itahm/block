package com.itahm.license;

import java.util.Calendar;
import java.util.Timer;
import java.util.TimerTask;

import com.itahm.util.Listener;

public class Expire extends TimerTask {

	private final static long PERIOD = 24 *60 *60 *1000;
	private final Listener listener;
	private final long expire;
	private Timer timer = null;
	
	/**
	 * 만료일 설정이 있을때 시작할때 한번, 매일 자정에 한번씩 확인
	 * 만료 확인시 통보
	 * 변경은 불가
	 * @param ms
	 * @param o
	 */
	public Expire(long ms, Listener o) {
		listener = o;
		expire = ms;
	
		if (!isExpired()) {
			timer = new Timer("com.itahm.license.Timer");
			
			schedule();
		}
	}

	private void schedule() {
		Calendar c = Calendar.getInstance();
		
		c.set(Calendar.DATE, c.get(Calendar.DATE) +1);
		c.set(Calendar.HOUR_OF_DAY, 0);
		c.set(Calendar.MINUTE, 0);
		c.set(Calendar.SECOND, 0);
		c.set(Calendar.MILLISECOND, 0);
		
		timer.schedule(this, c.getTime(), PERIOD);
	}
	
	public boolean isExpired() {
		return this.expire < Calendar.getInstance().getTimeInMillis();
	}
	
	@Override
	public void run() {
		if (isExpired()) {
			this.listener.onEvent(null, this);
			
			this.timer.cancel();
		}
	}
	
}
