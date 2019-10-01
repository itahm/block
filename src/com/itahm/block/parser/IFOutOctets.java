package com.itahm.block.parser;

import java.util.Map;

import com.itahm.block.Bean.CriticalEvent;
import com.itahm.block.Bean.Max;
import com.itahm.block.Bean.Value;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;

public class IFOutOctets implements Parseable {
	//private final Map<Long, Map<Integer, Long>> bps = new HashMap<>();
	private final Map<Long, Map<Integer, Value>> tmpMap = new HashMap<>();
	private final Map<Long, Max> publicMax = new HashMap<>();
	private final Map<Long, Max> max = new HashMap<>();
	private final Map<Long, Max> publicMaxRate = new HashMap<>();
	private final Map<Long, Max> maxRate = new HashMap<>();
	
	@Override
	public CriticalEvent parse(long id, String idx, Map<String, Value> oidMap) {
		long speed = 0;
		int index = Integer.valueOf(idx);
		Value v;
		Map<Integer, Value> tmpIndexMap = this.tmpMap.get(id);
		
		if (tmpIndexMap == null) {
			this.tmpMap.put(id, tmpIndexMap = new HashMap<Integer, Value>());
		}
		
		if ((v = oidMap.get("1.3.6.1.4.1.49447.3.5")) != null) {
			speed = Long.valueOf(v.value);
		} else if ((v = oidMap.get("1.3.6.1.2.1.2.2.1.5")) != null) {
			speed = Long.valueOf(v.value);
		}
		
		if (speed > 0) {
			v = oidMap.get("1.3.6.1.2.1.2.2.1.16");
			
			if (v != null) {
				Long l = parseBPS(id, tmpIndexMap.get(index), speed, Long.valueOf(v.value), v.timestamp);
				
				tmpIndexMap.put(index, new Value(v.timestamp, v.value));
				
				if (l != null) {
					Max max = this.max.get(id);
					Value bps = oidMap.get("1.3.6.1.4.1.49447.3.2");
					
					if (max == null || Long.valueOf(max.value) < l) {
						this.max.put(id, new Max(id, index, Long.toString(l), l *100 / speed));
					}
					
					max = this.maxRate.get(id);
					
					if (max == null || max.rate < l *100 / speed) {
						this.maxRate.put(id, new Max(id, index, Long.toString(l), l *100 / speed));
					}
					
					if (bps == null) {
						bps = new Value(v.timestamp, Long.toString(l));
						
						oidMap.put("1.3.6.1.4.1.49447.3.2", bps);
					} else {						
						bps.timestamp = v.timestamp;
						bps.value = Long.toString(l);
						
						if (bps.limit > 0) {
							boolean critical = l > bps.limit;
						
							if (bps.critical != critical) {
								bps.critical = critical;
								
								return new CriticalEvent(id, "0", "1.3.6.1.4.1.49447.3.2", critical, "송신");
							}
						}
					}
				}
			}
		}
		
		return null;
	}
	
	private Long parseBPS(long id, Value old, long speed, long octets, long timestamp) {
		if (old != null) {
			long diff = timestamp - old.timestamp;
			
			if (diff > 0) {
				return (octets - Long.valueOf(old.value)) *8000 / diff;
			}
		}
		
		return null;
	}

	@Override
	public List<Max> getTop(List<Long> list, boolean byRate) {
		List<Max> result = new ArrayList<>();
		
		if (byRate) {
			final Map<Long, Max> idMap = this.publicMaxRate;
			
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
					
					long l = max2.rate - max1.rate;
					
					if (l == 0) {
						l = Long.valueOf(max2.value) - Long.valueOf(max1.value);
					}
					
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
		}
		else {
			final Map<Long, Max> idMap = this.publicMax;
			
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
					
					if (l == 0) {
						l = max2.rate - max1.rate;
					}
					
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
		}
		
		return result;
	}
	
	@Override
	public void submit(long id) {
		this.publicMax.put(id, this.max.get(id));
		this.publicMaxRate.put(id, this.maxRate.get(id));
		
		this.max.remove(id);
		this.maxRate.remove(id);
	}

	@Override
	public void reset(long id) {
		this.publicMax.remove(id);
		this.publicMaxRate.remove(id);
	}

}
