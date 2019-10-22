package com.itahm.service;

import com.itahm.http.Response;
import com.itahm.json.JSONObject;

public interface Serviceable {
	public void start();
	public void stop();
	public void service(JSONObject request, Response response);
}