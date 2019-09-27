package com.itahm.util;

public interface Listenable {
	public void addEventListener(Listener listener);
	public void removeEventListener(Listener listener);
	public void fireEvent(Object ...args);
}
