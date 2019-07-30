package com.itahm.http;

import com.itahm.json.JSONObject;

public interface HTTPListener {
	public void sendEvent(JSONObject jsono, boolean broadcast);
}
