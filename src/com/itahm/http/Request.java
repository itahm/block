package com.itahm.http;

public interface Request {
	public byte [] read();
	public Session getSession();
	public Session getSession(boolean create);
	public String getMethod();
	public String getRequestURI();
	public String getQueryString();
	public String getRequestedSessionId();
	public String getHeader(String name);
}
