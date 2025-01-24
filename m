Return-Path: <kasan-dev+bncBC4LXIPCY4NRBEXOZO6AMGQEK3AF5HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F01FA1AE76
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Jan 2025 03:12:36 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-216717543b7sf40238195ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Jan 2025 18:12:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1737684755; cv=pass;
        d=google.com; s=arc-20240605;
        b=W+dCSOMQuREovOPAXelVebIy10mZbgBYdi4dzyucNjflB54ZH+VIyCpvlY2kVxG3mw
         wMq8pKgSDrxqYEhLqsrt3H49HcyWEgqqP/izsl0k4DsJL7A5USKYHjmtTlqQH3yiGR9V
         EiS84i6zjGx0g4k6yurjwUYZbhyLLfWrqUKLnzoFviJCJmLdBZEASkMlkXU6c2hVAS8/
         4FZ7EjtIMz9aqW8VXP6exskQbKfpSmfoR1gnodj0fHevPS5RziuMJtl0rsOwsD5Dsnw0
         Fonq9YGtYKfJjpoL8n9YO3tN3C5e/kIdUm5gKREAes1Ykm1X9oX6khp+vp130qPcNiNk
         uPgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=dSrMVnOF7JwD0OibNC/fjo0KO9cH6iUQz6fdOD/vo0M=;
        fh=vI2RvCJuhWjY1tiGc2jpP/Zk7IGR+u5ujVu0o9AoegQ=;
        b=Ve/ZRjH6Vl8hui+pU2Uovl/0rF4bdikTVNiErnnIZSsbhEue/9zBaoTTS5dABd0g+4
         ocwhuqX6/vzlvqkAtbQpqdz1HVRP1KwvzUIU8HXJGKmkwBeQezojmZSgFaPr7xQM0Yv7
         RlT2yubnD6f+KLZpfGiZnO0g2EhgC2xarQK3fTtz2SM0mo51wMfhWBt72TCJK0OTgvP/
         4rW6ucMdL/5FvtrhNlZbFDoMtlaGI0iGLJME4CJgc7vdF3Y4Y2tEcTk3FtYaM7q+nlo/
         fq3OSGIcHqZWZXRmTjDro1g1JQhLCTn3T1wf+PNhXtUTkJQdzGp7ETPz5HMjPXjsiDng
         QUag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=UDx6WXdp;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.9 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1737684755; x=1738289555; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dSrMVnOF7JwD0OibNC/fjo0KO9cH6iUQz6fdOD/vo0M=;
        b=SwFyk8mKYx3fUdnBJOtjnlt8unyw+x6eqqciUAd/4jvI6cRiTrLx2E6JVgGyjW4XIN
         03p77AgRIMPWHSbkFpwReJtL1PXi17T1jE10OF4tJDYOaGdfiqibYqO7woFgxagUjB8x
         ptmhqY0LESDVpPgB9O2sd9m3NYqmdrGKRtsbPGtK08qMe2P9giCEcNmbTLjhCjHi2e8C
         641q7V1bf/mwXOhxVYBRxnM9JIkdAvuu+QosNmwutcCfkmyKQfvvjXufZBSS54UIW6mO
         tumIIucxcvMZGHL5OyLGLMmi4ZHzrpbTzqm+t6bJfw3G2SXELbednTtTFHr/MfU39vq8
         jT4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1737684755; x=1738289555;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dSrMVnOF7JwD0OibNC/fjo0KO9cH6iUQz6fdOD/vo0M=;
        b=WbhgFjk4QZjMF5/PKqPuYHy4EFpQ/cyBQM2d7IERqgkHwAmNW8zqJA/5WV+vNIDGc6
         QIsr8DXNYDo2g7Ak+r6eSB+AUDRLEUGsJU1L6noeXqJXRLIHw8Py003KC8iC14iolMyU
         /MzZu7KGGX2pw+R/FYjaf1yF8meYfAIeJxc/LVi4eu+dqS9ilPwTgWytu5rrOCACS5Ry
         oYjP6R6j5Ig6LBtYRekUurYAlrSuMENYAvvUB5cjKcyIBSPjotO5g8EAiwtxKWw6uhD1
         QTWWop0aiMdFCuvNRqNz/SF9cA8jQV+31UlmO5Cwu/gyymHeblUBxxjNDHHiDODwlLOc
         xAYA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWMUYTVLNOBa9FhKpllLIVdSPrOP5yYWZYJMSezAsn1pb5sOGO5+JmwlrM492nmgvgbNgwKHg==@lfdr.de
X-Gm-Message-State: AOJu0YxzmGDEuXBsQCVfUrbPcik6tlbBNI3KuwxqA0RQZ34YjBK+gsug
	2gZjJpvt1/YMHpW6Cou9i/MNWFlqr42Bozv2po+GspQZCOFuXZP5
X-Google-Smtp-Source: AGHT+IHcq27QvlYnF0EcKJhkJo691WkOZ1IZcU6qG5sIo+LHXx5BzF2DBp25WzFJYLg/vh1BiYvQRg==
X-Received: by 2002:a17:902:f54f:b0:21d:3bd7:afdd with SMTP id d9443c01a7336-21d3bd7b341mr217196405ad.0.1737684754743;
        Thu, 23 Jan 2025 18:12:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:6c5:b0:216:2bd7:1c48 with SMTP id
 d9443c01a7336-21d994ee9e5ls11587875ad.2.-pod-prod-06-us; Thu, 23 Jan 2025
 18:12:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWB8fLj6kXDLrla/TnRjk2CyhZ8SpIiWoIVuC2VqhvNsGCelEKQwSdSnwHlLXM7jSe0G3Z7wkF8pQo=@googlegroups.com
X-Received: by 2002:a17:902:e5c2:b0:216:4e9f:4ed4 with SMTP id d9443c01a7336-21c355bf86dmr432204505ad.36.1737684753163;
        Thu, 23 Jan 2025 18:12:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1737684753; cv=none;
        d=google.com; s=arc-20240605;
        b=KrOylseebWhmj97mEP4+zMXn1948XQyeBIH5uwCPHSsQEuL+neHj185H8TxuXpeQTd
         MQyKxMKacl9w6tBALcEw9AarV9X+gvJtXmut3UYiaNRbSdDgd7+tzw5tW4aLv7mXPwcW
         tS5lKMDWQxy2jCsxqPPcXEXaQ5+lL9wfYRxDGnL3skeHAaBcX3EhFoee96Oo6zyou/I9
         J69Cewpdx1CF9OomkyyxHCSyQdAlBVXxDhYtX9c+0l83lzvL8mlV7hgJiSKUrxL8J7Ih
         0EiZAmNNSjyyeQfrcWKc0GD3NfaqvjJIvn5ff5DzYSNHUx/EQWnsPTROzO2aCFhBER8F
         mOxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=UPmM6acKSzQDeXlufKGeLR25eMLELY0p+Hjcp4bjlBk=;
        fh=I/RsOLeMVoGYsL6WM9jZNAWs01219/iXJXKodWQLYF4=;
        b=ZDAqcW0/GTMKrlRrD6qDFQFKO9iWL9cJFjgOcB+v2IEbWs/w+xhA2Wg67klKuMWiU9
         fSYtxPzmHz6tRq5JSzRjIlDNhL5K9U7/2SFeJkh0f3Tur11ZbN7iDvlIcxEbg1VVPmIm
         HzRaL2iioeggST4HUJbO4DT4/yXYZo4+D0dnyioEYltxv7wXiFjNggmWYA4yueDM8dDH
         NJj45xHk9Y4b6OknRsMvV3FyuPytCWHOJ6wH6q6VFGqMtcXf1Dx4B/A/Kb5M6BbEUo0N
         hk1G/2lIqeWpi86w1wjnCSkfsuD+sNVv9N82UNnZJq215TfbbWUW/nGGrH3UjQr7wRhn
         7zWQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=UDx6WXdp;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.9 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.9])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-21da3d99983si467095ad.1.2025.01.23.18.12.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 23 Jan 2025 18:12:33 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.198.163.9 as permitted sender) client-ip=192.198.163.9;
X-CSE-ConnectionGUID: 43OXRZbHRuqelH5EfSxBhQ==
X-CSE-MsgGUID: x/tQ145XTfWZ50Gf8qIEfw==
X-IronPort-AV: E=McAfee;i="6700,10204,11324"; a="48875989"
X-IronPort-AV: E=Sophos;i="6.13,230,1732608000"; 
   d="scan'208";a="48875989"
Received: from orviesa006.jf.intel.com ([10.64.159.146])
  by fmvoesa103.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 23 Jan 2025 18:12:31 -0800
X-CSE-ConnectionGUID: nXYMOnQESfGam5t5ZaclGw==
X-CSE-MsgGUID: 6JPi4DtnRJujUu4v4yIVnA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.13,230,1732608000"; 
   d="scan'208";a="107645960"
Received: from lkp-server01.sh.intel.com (HELO d63d4d77d921) ([10.239.97.150])
  by orviesa006.jf.intel.com with ESMTP; 23 Jan 2025 18:12:27 -0800
Received: from kbuild by d63d4d77d921 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1tb9BI-000c19-0j;
	Fri, 24 Jan 2025 02:12:24 +0000
Date: Fri, 24 Jan 2025 10:11:52 +0800
From: kernel test robot <lkp@intel.com>
To: "Jiao, Joey" <quic_jiangenj@quicinc.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Andrew Morton <akpm@linux-foundation.org>,
	Dennis Zhou <dennis@kernel.org>, Tejun Heo <tj@kernel.org>,
	Christoph Lameter <cl@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>
Cc: oe-kbuild-all@lists.linux.dev,
	Linux Memory Management List <linux-mm@kvack.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	workflows@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org, kernel@quicinc.com
Subject: Re: [PATCH 4/7] kcov: introduce new kcov KCOV_TRACE_UNIQ_CMP mode
Message-ID: <202501240959.61XLxBYF-lkp@intel.com>
References: <20250114-kcov-v1-4-004294b931a2@quicinc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250114-kcov-v1-4-004294b931a2@quicinc.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=UDx6WXdp;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.198.163.9 as permitted
 sender) smtp.mailfrom=lkp@intel.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=intel.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Hi Joey,

kernel test robot noticed the following build errors:

[auto build test ERROR on 9b2ffa6148b1e4468d08f7e0e7e371c43cac9ffe]

url:    https://github.com/intel-lab-lkp/linux/commits/Jiao-Joey/kcov-introduce-new-kcov-KCOV_TRACE_UNIQ_PC-mode/20250114-133713
base:   9b2ffa6148b1e4468d08f7e0e7e371c43cac9ffe
patch link:    https://lore.kernel.org/r/20250114-kcov-v1-4-004294b931a2%40quicinc.com
patch subject: [PATCH 4/7] kcov: introduce new kcov KCOV_TRACE_UNIQ_CMP mode
config: mips-randconfig-r073-20250124 (https://download.01.org/0day-ci/archive/20250124/202501240959.61XLxBYF-lkp@intel.com/config)
compiler: mips-linux-gcc (GCC) 14.2.0
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20250124/202501240959.61XLxBYF-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202501240959.61XLxBYF-lkp@intel.com/

All errors (new ones prefixed by >>):

   kernel/kcov.c: In function 'kcov_map_add':
>> kernel/kcov.c:309:60: error: 'struct kcov_entry' has no member named 'type'
     309 |                         if (entry->ent == ent->ent && entry->type == ent->type &&
         |                                                            ^~
   kernel/kcov.c:309:73: error: 'struct kcov_entry' has no member named 'type'
     309 |                         if (entry->ent == ent->ent && entry->type == ent->type &&
         |                                                                         ^~
>> kernel/kcov.c:310:34: error: 'struct kcov_entry' has no member named 'arg1'
     310 |                             entry->arg1 == ent->arg1 && entry->arg2 == ent->arg2) {
         |                                  ^~
   kernel/kcov.c:310:47: error: 'struct kcov_entry' has no member named 'arg1'
     310 |                             entry->arg1 == ent->arg1 && entry->arg2 == ent->arg2) {
         |                                               ^~
>> kernel/kcov.c:310:62: error: 'struct kcov_entry' has no member named 'arg2'
     310 |                             entry->arg1 == ent->arg1 && entry->arg2 == ent->arg2) {
         |                                                              ^~
   kernel/kcov.c:310:75: error: 'struct kcov_entry' has no member named 'arg2'
     310 |                             entry->arg1 == ent->arg1 && entry->arg2 == ent->arg2) {
         |                                                                           ^~
   kernel/kcov.c:343:48: error: 'struct kcov_entry' has no member named 'type'
     343 |                         area[start_index] = ent->type;
         |                                                ^~
   kernel/kcov.c:344:52: error: 'struct kcov_entry' has no member named 'arg1'
     344 |                         area[start_index + 1] = ent->arg1;
         |                                                    ^~
   kernel/kcov.c:345:52: error: 'struct kcov_entry' has no member named 'arg2'
     345 |                         area[start_index + 2] = ent->arg2;
         |                                                    ^~


vim +309 kernel/kcov.c

   290	
   291	static notrace inline void kcov_map_add(struct kcov_map *map, struct kcov_entry *ent,
   292						struct task_struct *t, unsigned int mode)
   293	{
   294		struct kcov *kcov;
   295		struct kcov_entry *entry;
   296		unsigned int key = hash_key(ent);
   297		unsigned long pos, start_index, end_pos, max_pos, *area;
   298	
   299		kcov = t->kcov;
   300	
   301		if ((mode == KCOV_MODE_TRACE_UNIQ_PC ||
   302		     mode == KCOV_MODE_TRACE_UNIQ_EDGE))
   303			hash_for_each_possible_rcu(map->buckets, entry, node, key) {
   304				if (entry->ent == ent->ent)
   305					return;
   306			}
   307		else
   308			hash_for_each_possible_rcu(map->buckets, entry, node, key) {
 > 309				if (entry->ent == ent->ent && entry->type == ent->type &&
 > 310				    entry->arg1 == ent->arg1 && entry->arg2 == ent->arg2) {
   311					return;
   312				}
   313			}
   314	
   315		entry = (struct kcov_entry *)gen_pool_alloc(map->pool, 1 << MIN_POOL_ALLOC_ORDER);
   316		if (unlikely(!entry))
   317			return;
   318	
   319		barrier();
   320		memcpy(entry, ent, sizeof(*entry));
   321		hash_add_rcu(map->buckets, &entry->node, key);
   322	
   323		if (mode == KCOV_MODE_TRACE_UNIQ_PC || mode == KCOV_MODE_TRACE_UNIQ_CMP)
   324			area = t->kcov_area;
   325		else
   326			area = kcov->map_edge->area;
   327	
   328		pos = READ_ONCE(area[0]) + 1;
   329		if (mode == KCOV_MODE_TRACE_UNIQ_PC || mode == KCOV_MODE_TRACE_UNIQ_EDGE) {
   330			if (likely(pos < t->kcov_size)) {
   331				WRITE_ONCE(area[0], pos);
   332				barrier();
   333				area[pos] = ent->ent;
   334			}
   335		} else {
   336			start_index = 1 + (pos - 1) * KCOV_WORDS_PER_CMP;
   337			max_pos = t->kcov_size * sizeof(unsigned long);
   338			end_pos = (start_index + KCOV_WORDS_PER_CMP) * sizeof(u64);
   339			if (likely(end_pos <= max_pos)) {
   340				/* See comment in __sanitizer_cov_trace_pc(). */
   341				WRITE_ONCE(area[0], pos);
   342				barrier();
   343				area[start_index] = ent->type;
   344				area[start_index + 1] = ent->arg1;
   345				area[start_index + 2] = ent->arg2;
   346				area[start_index + 3] = ent->ent;
   347			}
   348		}
   349	}
   350	

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202501240959.61XLxBYF-lkp%40intel.com.
