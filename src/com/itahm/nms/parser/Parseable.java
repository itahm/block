package com.itahm.nms.parser;

import java.util.List;
import java.util.Map;

import com.itahm.nms.Bean.CriticalEvent;
import com.itahm.nms.Bean.Max;
import com.itahm.nms.Bean.Value;

public interface Parseable {
	public List<Max> getTop(int count, boolean byRate);
	public CriticalEvent parse(long id, String index, Map<String, Value> oidMap);
	public void submit(long id);
	public void reset(long id);
}
