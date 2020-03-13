package com.itahm.http;

public interface Request {
	public Object getAttribute(String name);
	public String getHeader(String name);
	public String getMethod();
	public String getQueryString();
	public String getRequestedSessionId();
	public String getRequestURI();
	public String getRemoteAddr();
	public Session getSession();
	public Session getSession(boolean create);
	public void setAttribute(String name, Object o);
	public byte [] read();
}
