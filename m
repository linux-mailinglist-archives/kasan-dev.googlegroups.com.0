Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBUGRRCNQMGQEDIKWKBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E451615D91
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Nov 2022 09:22:41 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id t9-20020a2e7809000000b00277524ccb02sf3323615ljc.1
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Nov 2022 01:22:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667377360; cv=pass;
        d=google.com; s=arc-20160816;
        b=FozAT30PHHQOtXLXGVd6MlnsZ0MXgeWzOwuIBJt3BfEvV0Ehn9DSHoHvd7SOHIdUU3
         rOn5Ff8Fh1EJUj4Y8p7uv5wKg8vsS8AApMCq0zf2jbYXU8O5M+lp6YmbE+57XEiujhti
         +QPMhLPzxr0IVor1Ly5CpxnyepYc8svHZZ2AkdFVOnJbvQ0BHikHR97B7oYS+GX4t6w3
         Pb27Abg3+W4BYiEnZvS3iLVpyyCUMqvar/UOjtvxUmsoMsauD4E2ZBhoDQ2xZut+lgGJ
         IvIRNO8VytOR1AFA4OpSX/0wyJqfbdRzJ7Wr4Xod1Pm+PlFvO+BmLue7xuMT/0n5MN/9
         p+Lw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=WeoILa7raL9uYjXOA7DGOVAfzT/z1KO06+gWo8ySm2Q=;
        b=tm5VRpYEYiiEAlpyvslV9SbL77qAJtgLUKFUk71MidQiWREh4PMTk97iD3EY/wZ6AA
         LzoQfi1xwTBRQEMDpI8UGc4XcIt09DtY0gJmITxrDBPr6hMYH54MdIMYUyh+8kvKVVs+
         Gbjql2ia7M0vnQP9TdKrgcyVq5/QP7o83N7go+pG02Y2hQAOa3AZpvSBHN2I3tfihaWw
         jpGN7LaZH9asdBpU9sA0kDZ4/UQ0qTqkefcT+TYHzEnGF3aLTrMmdV5k4LG64bnJGUj8
         gQENrqQteS2E5QSDZ1SRh/GU7rfi6VE6sw0eV5PYvbuU0MpMMbjBQby4H0OAYE9UpNCD
         vupw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=HR0DbvwE;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=WeoILa7raL9uYjXOA7DGOVAfzT/z1KO06+gWo8ySm2Q=;
        b=IqDzRLsdSOZGqHtXArXCPzmrBKqG6CqLJvTjryajr+V0lJkdHA1kP78bQpKed6g3oS
         CR3IJL3qW/w3tiuGtkXuINsZvKOSvTFCL64I5bQiFoNNjScKns7DMwY7UgzXRgtq9Hul
         u6WPDsU8CmWUzzKf7/tAEx8ELzU0tPXFmxnM4zi640RfqvTDC6NLfjC2ZF7r1kANsr7V
         aQgRXFx9Z4Lv/3Zmw/PDNs+Vg83kEDEOu9yDSoQlXqTZlj9fmFe1Zi9PEEWLhxew+PZu
         pkzLE0C/igmL9IGGZKCDQUVCBL7EWobbxLcn8c4RSS4a2hIPtxiZcaV6CAL1B7wEnjno
         mc6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=WeoILa7raL9uYjXOA7DGOVAfzT/z1KO06+gWo8ySm2Q=;
        b=mmWlId8gtb11RhTjNczId2HeEjhgtgI1Nj+VcxPBSduN+Up6nt0s9DTIAdb64dkies
         9DIZfL4jHruOVj7PkJLmjjmpipHPKVPBoWEnkJbkrDZHwRbGVSwB6eq8xz+Ua2dWkEQR
         efjK5b3sko8LPS9gUcE4diZjVDSF0O6tMQyv2+NuPBjpi8i8ir2y9266+ZbGPlxHwbvI
         mnrUCDgV/LTK6RMS9H0uGIBj4j19FfhbMviHK0Hr8d5DJEJ34SCxiZXcDjAeUolp0l1m
         l73lAZTl8js0wgPBtqIyS0VOIb6J3V6eC+M1wsSErCynepOJx+opxAv30b7p6NkrazWc
         8LIA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0etm340ZX+TlfqQKnO7dfQB/4hNk+8b+Ewb4u0NDYn5DM8ECNG
	mT3rlBMm6TunfkZ0WVhYqDw=
X-Google-Smtp-Source: AMsMyM7loYEf1omiES2Vyrnc78zNK/K9bria/9AyGNDzaNk4PoFMMuZ5AgEPQ+SZY4m+Jp2MOdDBwQ==
X-Received: by 2002:a05:6512:1150:b0:4a2:7f90:79ea with SMTP id m16-20020a056512115000b004a27f9079eamr8456134lfg.180.1667377360388;
        Wed, 02 Nov 2022 01:22:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2116:b0:48b:2227:7787 with SMTP id
 q22-20020a056512211600b0048b22277787ls1167606lfr.3.-pod-prod-gmail; Wed, 02
 Nov 2022 01:22:38 -0700 (PDT)
X-Received: by 2002:ac2:4bcf:0:b0:4a2:c241:1979 with SMTP id o15-20020ac24bcf000000b004a2c2411979mr8988583lfq.89.1667377358781;
        Wed, 02 Nov 2022 01:22:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667377358; cv=none;
        d=google.com; s=arc-20160816;
        b=iu59LRE5RXPDx3HT+mQ+Ti3uAbm27UyeHH1bzsggb+jRDiKnDHZRTAct/2hsDe3BcB
         1I7BDTUY2X6vQX8LLhvxZon93uq4Jib7aWbre8ZxZFnnTBrdHgC0zZPO84QXwKxHwSwN
         7IOv9okJ1sv1Z2sTteriy2PaiOcvBtuqsmCEq4ZrBjIsKncguDMHU2tVIFkqGClUeDxJ
         yeWaUQr8xTlm5yZNHuxLnLK9e778paxG+Er3c6/exCNNHzUNcyohyzWrYmPVjH3P4MHn
         wMmMaeVH7b58vGi9sHCZUVKqiUg897NFhaAVxFRFmZCq3E4jv9pSXGXajmh5MQ09ZVD1
         WjKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=vPRiEjy3sfuyzgubEp1HGpBV7YGim3ifA/HV0tLfnYk=;
        b=n84XuC5uZ5/O/n9BpCy5FlqvMB/NOt+RZW9bwpUvZSZ18LqgcmdD7ciOYZh6lBEs2X
         +O3csJ2ndrcEULH4gQhwaGNoNqgxAbgCwoKttC4Q+j2cKvDzO8etx4+2LWue00fsOpHc
         VU1DZOrhB+cJONstx75ozOyUWl2azlKNfOrrD00lFkezGdUKIcHP7F7rOfKsQH/o99vq
         WvadJ/Dm5+89CiZvRgKHYk5m+sG4AHuBgwsJWEbO7A5m3ligRatloz0frLD2HOWjiK99
         gVYIXkPWYxtxvRpAz1se+cD2B/4zUxA5fuJriHbvBN1w0avjSmqmKu/6djFbcGxUr0RC
         pgWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=HR0DbvwE;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id k27-20020a05651c10bb00b002776daa0487si171626ljn.2.2022.11.02.01.22.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 02 Nov 2022 01:22:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id EA5B31F86C;
	Wed,  2 Nov 2022 08:22:37 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 924811376E;
	Wed,  2 Nov 2022 08:22:37 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id PpT3Is0oYmMuCAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Wed, 02 Nov 2022 08:22:37 +0000
Message-ID: <097d8fba-bd10-a312-24a3-a4068c4f424c@suse.cz>
Date: Wed, 2 Nov 2022 09:22:37 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.4.0
Subject: Re: [PATCH v6 1/4] mm/slub: enable debugging memory wasting of
 kmalloc
To: John Thomson <lists@johnthomson.fastmail.com.au>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Feng Tang <feng.tang@intel.com>, Andrew Morton
 <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Dmitry Vyukov
 <dvyukov@google.com>, Jonathan Corbet <corbet@lwn.net>,
 Andrey Konovalov <andreyknvl@gmail.com>, "Hansen, Dave"
 <dave.hansen@intel.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 Robin Murphy <robin.murphy@arm.com>, John Garry <john.garry@huawei.com>,
 Kefeng Wang <wangkefeng.wang@huawei.com>,
 Thomas Bogendoerfer <tsbogend@alpha.franken.de>, linux-mips@vger.kernel.org
References: <20220913065423.520159-1-feng.tang@intel.com>
 <20220913065423.520159-2-feng.tang@intel.com>
 <becf2ac3-2a90-4f3a-96d9-a70f67c66e4a@app.fastmail.com>
 <af2ba83d-c3f4-c6fb-794e-c2c7c0892c44@suse.cz> <Y180l6zUnNjdCoaE@feng-clx>
 <c4285caf-277c-45fd-8fc7-8a1d61685ce8@app.fastmail.com>
 <Y1+0sbQ3R4DB46NX@feng-clx>
 <9b71ae3e-7f53-4c9e-90c4-79d3d649f94c@app.fastmail.com>
 <Y2DReuPHZungAGsU@feng-clx>
 <53b53476-bb1e-402e-9f65-fd7f0ecf94c2@app.fastmail.com>
 <Y2DngwUc7cLB0dG7@hyeyoo>
 <29271a2b-cf19-4af9-bfe5-5bcff8a23fda@app.fastmail.com>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <29271a2b-cf19-4af9-bfe5-5bcff8a23fda@app.fastmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=HR0DbvwE;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 11/1/22 11:33, John Thomson wrote:
> On Tue, 1 Nov 2022, at 09:31, Hyeonggon Yoo wrote:
>> On Tue, Nov 01, 2022 at 09:20:21AM +0000, John Thomson wrote:
>>> On Tue, 1 Nov 2022, at 07:57, Feng Tang wrote:
>>> > Hi Thomson,
>>> >
>>> > Thanks for testing!
>>> >
>>> > + mips maintainer and mail list. The original report is here
>>> >
>>> > https://lore.kernel.org/lkml/becf2ac3-2a90-4f3a-96d9-a70f67c66e4a@app.fastmail.com/
>>>
>>> I am guessing my issue comes from __kmem_cache_alloc_lru accessing s->object_size when (kmem_cache) s is NULL?
>>> If that is the case, this change is not to blame, it only exposes the issue?
>>> 
>>> I get the following dmesg (note very early NULL kmem_cache) with the below change atop v6.1-rc3:
>>> 
>>> transfer started ......................................... transfer ok, time=2.02s
>>> setting up elf image... OK
>>> jumping to kernel code
>>> zimage at:     80B842A0 810B4EFC
>>> 
>>> Uncompressing Linux at load address 80001000
>>> 
>>> Copy device tree to address  80B80EE0
>>> 
>>> Now, booting the kernel...
>>> 
>>> [    0.000000] Linux version 6.1.0-rc3+ (john@john) (mipsel-buildroot-linux-gnu-gcc.br_real (Buildroot 2021.11-4428-g6b6741b) 12.2.0, GNU ld (GNU Binutils) 2.39) #61 SMP Tue Nov  1 18:04:13 AEST 2022
>>> [    0.000000] slub: kmem_cache_alloc called with kmem_cache: 0x0
>>> [    0.000000] slub: __kmem_cache_alloc_lru called with kmem_cache: 0x0
>>> [    0.000000] SoC Type: MediaTek MT7621 ver:1 eco:3
>>> [    0.000000] printk: bootconsole [early0] enabled
>>> [    0.000000] CPU0 revision is: 0001992f (MIPS 1004Kc)
>>> [    0.000000] MIPS: machine is MikroTik RouterBOARD 760iGS
>>> 
>>> normal boot
>>> 
>>> 
>>> diff --git a/mm/slub.c b/mm/slub.c
>>> index 157527d7101b..10fcdf2520d2 100644
>>> --- a/mm/slub.c
>>> +++ b/mm/slub.c
>>> @@ -3410,7 +3410,13 @@ static __always_inline
>>>  void *__kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
>>>  			     gfp_t gfpflags)
>>>  {
>>> -	void *ret = slab_alloc(s, lru, gfpflags, _RET_IP_, s->object_size);
>>> +	void *ret;
>>> +	if (IS_ERR_OR_NULL(s)) {
>>> +		pr_warn("slub: __kmem_cache_alloc_lru called with kmem_cache: %pSR\n", s);
>>> +		ret = slab_alloc(s, lru, gfpflags, _RET_IP_, 0);
>>> +	} else {
>>> +		ret = slab_alloc(s, lru, gfpflags, _RET_IP_, s->object_size);
>>> +	}
>>>  
>>>  	trace_kmem_cache_alloc(_RET_IP_, ret, s, gfpflags, NUMA_NO_NODE);
>>>  
>>> @@ -3419,6 +3425,8 @@ void *__kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
>>>  
>>>  void *kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)
>>>  {
>>> +	if (IS_ERR_OR_NULL(s))
>>> +		pr_warn("slub: kmem_cache_alloc called with kmem_cache: %pSR\n", s);
>>>  	return __kmem_cache_alloc_lru(s, NULL, gfpflags);
>>>  }
>>>  EXPORT_SYMBOL(kmem_cache_alloc);
>>> @@ -3426,6 +3434,8 @@ EXPORT_SYMBOL(kmem_cache_alloc);
>>>  void *kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
>>>  			   gfp_t gfpflags)
>>>  {
>>> +	if (IS_ERR_OR_NULL(s))
>>> +		pr_warn("slub: __kmem_cache_alloc_lru called with kmem_cache: %pSR\n", s);
>>>  	return __kmem_cache_alloc_lru(s, lru, gfpflags);
>>>  }
>>>  EXPORT_SYMBOL(kmem_cache_alloc_lru);
>>> 
>>> 
>>> Any hints on where kmem_cache_alloc would be being called from this early?
>>> I will start looking from /init/main.c around pr_notice("%s", linux_banner);
>>
>> Great. Would you try calling dump_stack(); when we observed s == NULL?
>> That would give more information about who passed s == NULL to these
>> functions.
>>
> 
> With the dump_stack() in place:
> 
> Now, booting the kernel...
> 
> [    0.000000] Linux version 6.1.0-rc3+ (john@john) (mipsel-buildroot-linux-gnu-gcc.br_real (Buildroot 2021.11-4428-g6b6741b) 12.2.0, GNU ld (GNU Binutils) 2.39) #62 SMP Tue Nov  1 19:49:52 AEST 2022
> [    0.000000] slub: __kmem_cache_alloc_lru called with kmem_cache ptr: 0x0
> [    0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted 6.1.0-rc3+ #62
> [    0.000000] Stack : 810fff78 80084d98 80889d00 00000004 00000000 00000000 80889d5c 80c90000
> [    0.000000]         80920000 807bd380 8089d368 80923bd3 00000000 00000001 80889d08 00000000
> [    0.000000]         00000000 00000000 807bd380 8084bd51 00000002 00000002 00000001 6d6f4320
> [    0.000000]         00000000 80c97ce9 80c97d14 fffffffc 807bd380 00000000 00000003 00000dc0
> [    0.000000]         00000000 a0000000 80910000 8110a0b4 00000000 00000020 80010000 80010000
> [    0.000000]         ...
> [    0.000000] Call Trace:
> [    0.000000] [<80008260>] show_stack+0x28/0xf0
> [    0.000000] [<8070cdc0>] dump_stack_lvl+0x60/0x80
> [    0.000000] [<801c1428>] kmem_cache_alloc+0x5c0/0x740
> [    0.000000] [<8092856c>] prom_soc_init+0x1fc/0x2b4
> [    0.000000] [<80928060>] prom_init+0x44/0xf0
> [    0.000000] [<80929214>] setup_arch+0x4c/0x6a8
> [    0.000000] [<809257e0>] start_kernel+0x88/0x7c0
> [    0.000000] 
> [    0.000000] SoC Type: MediaTek MT7621 ver:1 eco:3

The stack means CONFIG_TRACING=n, is that right?

That would mean
prom_soc_init()
  soc_dev_init()
    kzalloc() -> kmalloc()
      kmalloc_trace()  // after #else /* CONFIG_TRACING */
        kmem_cache_alloc(s, flags);

Looks like this path is a small bug in the wasting detection patch, as we
throw away size there.

AFAICS before this patch, we "survive" "kmem_cache *s" being NULL as
slab_pre_alloc_hook() will happen to return NULL and we bail out from
slab_alloc_node(). But this is a side-effect, not an intended protection.
Also the CONFIG_TRACING variant of kmalloc_trace() would have called
trace_kmalloc dereferencing s->size anyway even before this patch.

I don't think we should add WARNS in the slab hot paths just to prevent this
rare error of using slab too early. At most VM_WARN... would be acceptable
but still not necessary as crashing immediately from a NULL pointer is
sufficient.

So IMHO mips should fix their soc init, and we should look into the
CONFIG_TRACING=n variant of kmalloc_trace(), to pass orig_size properly.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/097d8fba-bd10-a312-24a3-a4068c4f424c%40suse.cz.
