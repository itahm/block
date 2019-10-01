package com.itahm.block.parser;

import java.util.List;
import java.util.Map;

import com.itahm.block.Bean.CriticalEvent;
import com.itahm.block.Bean.Max;
import com.itahm.block.Bean.Value;

public interface Parseable {
	public List<Max> getTop(List<Long> list, boolean byRate);
	public CriticalEvent parse(long id, String index, Map<String, Value> oidMap);
	public void submit(long id);
	public void reset(long id);
}
