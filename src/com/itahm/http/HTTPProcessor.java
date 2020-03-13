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
		
		switch(this.request.getMethod().toUpperCase()) {
		case "GET":
			this.server.doGet(this.request, response);
			
			break;
		case "OPTIONS":
			String origin = request.getHeader(com.itahm.http.Connection.Header.ORIGIN.toString());
			
			if (origin != null) {
				response.setHeader("Access-Control-Allow-Credentials", "true");
				response.setHeader("Access-Control-Allow-Origin", origin);
				response.setHeader("Access-Control-Allow-Methods","POST, GET, OPTIONS");
				response.setHeader("Allow", "GET, POST, OPTIONS");
				//response.setHeader("Access-Control-Allow-Methods","POST, GET, OPTIONS, PUT"); 
				//response.setHeader("Access-Control-Allow-Headers", "File-Name");
				//response.setHeader("Allow", "GET, POST, OPTIONS, PUT");
			}
			
			break;
		case "POST":
			this.server.doPost(this.request, response);
			
			break;
		/*case "PUT":
			this.server.doPut(this.request, response);
			
			break;*/
		default:
			response.setStatus(Response.Status.NOTALLOWED);
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
			ioe.printStackTrace();
		}
	}
}
