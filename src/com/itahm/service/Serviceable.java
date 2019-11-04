package com.itahm.service;

import com.itahm.http.Request;
import com.itahm.http.Response;
import com.itahm.json.JSONObject;

public interface Serviceable {
	public void start();
	public void stop();
	public boolean isRunning();
	public boolean service(Request request, Response response, JSONObject data);
}
