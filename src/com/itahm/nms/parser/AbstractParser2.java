package com.itahm.nms.parser;

import java.util.Map;

import com.itahm.nms.Bean.Max;

import java.util.HashMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

abstract public class AbstractParser2 extends AbstractParser {
	
	protected Map<Long, Max> publicMaxRate = new HashMap<>();
	protected Map<Long, Max> maxRate = new HashMap<>();

	@Override
	public List<Max> getTop(int count, boolean byRate) {
		if (!byRate) {
			return super.getTop(count, byRate);
		}
		
		final List<Long> keys = new ArrayList<>(this.publicMaxRate.keySet());
		List<Max> result = new ArrayList<>();
		Max max;
		
		Collections.sort(keys, new Comparator<Long>() {
			
			@Override
			public int compare(Long id1, Long id2) {
				Max max1 = publicMaxRate.get(id1);
				Max max2 = publicMaxRate.get(id2);
				
				if (max1 == null && max2 == null) {
					return 0;
				}
				
				if (max1 == null) {
					return 1;
				}
				
				if (max2 == null) {
					return -1;
				}
				
				long l = max2.rate - max1.rate;
				
				return l > 0? 1: l < 0? -1: 0;
			}
		});
		
		for (int i=0, _i=Math.min(keys.size(), count); i<_i; i++) {
			max = publicMaxRate.get(keys.get(i));
			
			if (max != null) {
				result.add(max);
			}
		}
		
		return result;
	}
	
	@Override
	public void submit(long id) {
		super.submit(id);
		
		Max max = this.maxRate.remove(id);
		
		if (max != null) {
			this.publicMaxRate.put(id, max);
		}
	}
	
	@Override
	public void reset(long id) {
		super.reset(id);
		
		this.publicMaxRate.remove(id);
	}

}
