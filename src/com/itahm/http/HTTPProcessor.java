package com.itahm.http;

import java.io.IOException;

public class HTTPProcessor extends Thread {
	
	private final HTTPServer server;
	private final Connection connection;
	private final Request request;
	
	public HTTPProcessor(HTTPServer server, Connection connection) {
		this.server = server;
		this.connection = connection;
		
		request = connection.createRequest();
		
		setDaemon(true);
		setName("ITAhM HTTPProcessor");
		
		start();
	}
	
	@Override
	public void run() {
		Response response = new Response();
		
		switch(this.request.getMethod().toLowerCase()) {
		case "head":
			
			break;
			
		case "get":
			this.server.doGet(this.request, response);
			
			break;
			
		case "post":
			this.server.doPost(this.request, response);
			
			break;
			
		default:
			response.setStatus(Response.Status.NOTALLOWED);
			response.setHeader("Allow", "GET HEAD POST");
		}
		
		Session session = this.request.getSession(false);
		
		if (session != null) {
			if (!session.id.equals(request.getRequestedSessionId())) {
				response.setHeader("Set-Cookie", String.format("%s=%s; HttpOnly", Session.ID, session.id));
			}
		}
		
		try {
			this.connection.write(response);
		} catch (IOException ioe) {
			System.err.print(ioe);
		}
	}
}
