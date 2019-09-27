package com.itahm.block.parser;

import java.util.Map;

import com.itahm.block.Bean.Max;
import com.itahm.block.Bean.Value;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;

public class IFOutErrors implements Parseable {
	//private final Map<Long, Map<Integer, Long>> error = new TreeMap<>();
	private final Map<Long, Map<Integer, Value>> tmpMap = new HashMap<>();
	private final Map<Long, Max> publicMax = new HashMap<>();
	private final Map<Long, Max> max = new HashMap<>();
	
	@Override
	public void parse(long id, String idx, Map<String, Value> oidMap) {
		Value v = oidMap.get("1.3.6.1.2.1.2.2.1.20");
		
		if (v == null) {
			return;
		}
		
		Map<Integer, Value> tmpIndexMap = this.tmpMap.get(id);
		
		if (tmpIndexMap == null) {
			tmpMap.put(id, tmpIndexMap = new HashMap<Integer, Value>());
		}
		
		int index = Integer.valueOf(idx);
		Long l= parse(id, tmpIndexMap.get(index), Long.valueOf(v.value), v.timestamp);
		
		tmpIndexMap.put(index, v);
		
		if (l != null) {
			Max max = this.max.get(id);
			
			if (max == null || Long.valueOf(max.value) < l) {
				this.max.put(id, new Max(id, index, Long.toString(l)));
			}
			
			oidMap.put("1.3.6.1.4.1.49447.3.4", new Value(v.timestamp, Long.toString(l)));
		}
		
		tmpIndexMap.put(index, v);
	}
	
	private Long parse(long id, Value v, long errors, long timestamp) {
		if (v != null) {
			long diff = timestamp - v.timestamp;
			
			if (diff > 0) {
				return (errors - Long.valueOf(v.value)) / diff *1000;
			}
		}
		
		return null;
	}

	@Override
	public List<Max> getTop(List<Long> list, boolean byRate) {
		final Map<Long, Max> idMap = this.publicMax;
		
		List<Max> result = new ArrayList<>();
		
		Collections.sort(list, new Comparator<Long>() {

			@Override
			public int compare(Long id1, Long id2) {
				Max max1 = idMap.get(id1);
				Max max2 = idMap.get(id2);
				
				if (max1 == null) {
					if (max2 == null) {
						return -1;
					}
					else {
						return 1;
					}
				} else if (max2 == null) {
					return -1;
				}
				
				long l = Long.valueOf(max2.value) - Long.valueOf(max1.value);
				
				return l > 0? 1: l < 0? -1: 0;
			}
		});
		
		Max max;
		
		for (int i=0, _i=list.size(); i<_i; i++) {
			max = idMap.get(list.get(i));
			
			if (max != null) {
				result.add(max);
			}
		}
		
		return result;
	}

	@Override
	public void submit(long id) {
		this.publicMax.put(id, this.max.get(id));
		
		this.max.remove(id);
	}
	
	@Override
	public void reset(long id) {
		this.publicMax.remove(id);
	}

	@Override
	public String getOID(String oid) {
		return null;
	}

}
