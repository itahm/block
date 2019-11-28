package com.itahm.http;

public interface Request {
	public String getHeader(String name);
	public String getMethod();
	public String getQueryString();
	public String getRequestedSessionId();
	public String getRequestURI();
	public String getRemoteAddr();
	public Session getSession();
	public Session getSession(boolean create);
	public byte [] read();
}
