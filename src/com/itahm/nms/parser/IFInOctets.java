package com.itahm.nms.parser;

import java.util.Map;

import com.itahm.nms.Bean.CriticalEvent;
import com.itahm.nms.Bean.Max;
import com.itahm.nms.Bean.Value;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;

public class IFInOctets implements Parseable {
	private final Map<Long, Map<Integer, Value>> oldMap = new HashMap<>();
	private final Map<Long, Max> publicMax = new HashMap<>();
	private final Map<Long, Max> max = new HashMap<>();
	private final Map<Long, Max> publicMaxRate = new HashMap<>();
	private final Map<Long, Max> maxRate = new HashMap<>();
	
	@Override
	public CriticalEvent parse(long id, String idx, Map<String, Value> oidMap) {
		long speed = 0;
		Value v;
		Map<Integer, Value> oldIndexMap = this.oldMap.get(id);
		
		if (oldIndexMap == null) {
			this.oldMap.put(id, oldIndexMap = new HashMap<Integer, Value>());
		}
		
		if ((v = oidMap.get("1.3.6.1.4.1.49447.3.5")) != null) {
			speed = Long.valueOf(v.value);
		} else if ((v = oidMap.get("1.3.6.1.2.1.31.1.1.1.15")) != null) {
			speed = Long.valueOf(v.value) *1000000L;
		} else if ((v = oidMap.get("1.3.6.1.2.1.2.2.1.5")) != null) {
			speed = Long.valueOf(v.value);
		}
		
		if (speed > 0) {
			v = oidMap.get("1.3.6.1.2.1.2.2.1.10");
			
			if (v != null) {
				int index;
				
				try {
					index = Integer.valueOf(idx);
				} catch (NumberFormatException nfe) {
					return null;
				}
				
				Long bps = parseBPS(id, oldIndexMap.get(index), speed, Long.valueOf(v.value), v.timestamp);
				
				oldIndexMap.put(index, new Value(v.timestamp, v.value));
				
				if (bps != null) {
					Max max = this.max.get(id);
					Value bpsValue = oidMap.get("1.3.6.1.4.1.49447.3.1");
					
					if (max == null || Long.valueOf(max.value) < bps) {
						this.max.put(id, new Max(id, index, Long.toString(bps), bps *100 / speed));
					}
					
					max = this.maxRate.get(id);
					
					if (max == null || max.rate < bps *100 / speed) {
						this.maxRate.put(id, new Max(id, index, Long.toString(bps), bps *100 / speed));
					}
					
					if (bpsValue == null) {
						oidMap.put("1.3.6.1.4.1.49447.3.1", new Value(v.timestamp, Long.toString(bps)));
					} else {						
						bpsValue.timestamp = v.timestamp;
						bpsValue.value = Long.toString(bps);
					}
					
					if (v.limit > 0) {
						boolean critical = bps *100 / speed > v.limit;
					
						if (v.critical != critical) {
							v.critical = critical;
							
							return new CriticalEvent(id, idx, "1.3.6.1.2.1.2.2.1.10", critical,
								String.format("수신 %d%%", bps *100 / speed));
						}
					} else if (v.critical) {
						v.critical = false;
						
						return new CriticalEvent(id, idx, "1.3.6.1.2.1.2.2.1.10", false,
							String.format("수신 %d%%", bps *100 / speed));
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
				octets -= Long.valueOf(old.value);
				
				return octets >= 0? (octets *8000 / diff) : null;
			}
		}
		
		return null;
	}


	@Override
	public List<Max> getTop(int count, boolean byRate) {
		final List<Long> keys = new ArrayList<>(this.publicMax.keySet());
		List<Max> result = new ArrayList<>();
		Max max;
		
		if (byRate) {
			Collections.sort(keys, new Comparator<Long>() {
	
				@Override
				public int compare(Long id1, Long id2) {
					Max max1 = publicMaxRate.get(id1);
					Max max2 = publicMaxRate.get(id2);
					
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
			
			for (int i=0, _i=Math.min(keys.size(), count); i<_i; i++) {
				max = publicMaxRate.get(keys.get(i));
				
				if (max != null) {
					result.add(max);
				}
			}
		}
		else {
			Collections.sort(keys, new Comparator<Long>() {
	
				@Override
				public int compare(Long id1, Long id2) {
					Max max1 = publicMax.get(id1);
					Max max2 = publicMax.get(id2);
					
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
			
			for (int i=0, _i=Math.min(keys.size(), count); i<_i; i++) {
				max = publicMax.get(keys.get(i));
				
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
	
	@Override
	public String toString() {
		return "IFINOCTETS";
	}

}
