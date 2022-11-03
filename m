Return-Path: <kasan-dev+bncBDWLZXP6ZEPRB67XR6NQMGQEZI3VX2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 695F8618646
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Nov 2022 18:35:56 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id r12-20020a05640251cc00b00463699c95aesf1839729edd.18
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Nov 2022 10:35:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667496956; cv=pass;
        d=google.com; s=arc-20160816;
        b=lTJCnIANJQAQxc6NeOe3m87r6JahneoPWcntV2gb8gGPpjSgrAJqRtndkkByPKUlg0
         WqUV2lDKFVFEpPZMNo+BtP8IkaVXGiDk/RaT+WfF3IxY2bM6sMhy09Mj03SB/dCFgNFZ
         KuSfwLqdfAVXrVBrHrPa8eD9G3E8DSq0Jl/gSX+/xII9J5VDT3qj3E+XlZ2pGhXiKw2e
         x9JkBMskxaTaFbN1U6AqilNVwV9UCJX0U+X7WY4myVczB4fwhRSu/+jG9hlSBxEF116W
         WBZ7+UGHwFMAJeN8hCTwt1K84VR5ZOXfNe0ZTypZZ/3XUCLvwL2GWuo+C5dX81urTErO
         egrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=gWTvVB/w2BbJtG8uyuyMcinmWnyb8HR9kaudVzNhC0o=;
        b=IkrI7U9mMXhzLcxJcfCk+fQeaRUYmI9b+ukxESC6HBnBxqkfCOs4nSUX+AQlzBghzb
         m1XbXbYvv3frVWFXK56ozPsg2y2Q62DrCKSKM1YWCf28G+cqMsunL6FAXgG08KCHYfc1
         fV0GZHd/N7VAZoB6oBqqewM6JdHaGAX9hmghW+FUP3jUk8OAW5yA9+CV68hBVdTl8RoD
         yO67Rq9dfBm1pZeixKrsQ+GtV438SqBjWBSMA37tdwE4FACeRXPaC9sMwAhDMpRlC2tr
         kSp67TL739zHHrRkvhQdTXC3n0grqd1J6vnu6L63pA/ib0xBr1qf4GJQpmHagyVFDxpL
         XtGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=H8+o9jGi;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=gWTvVB/w2BbJtG8uyuyMcinmWnyb8HR9kaudVzNhC0o=;
        b=AnG+0UXgow0pM6koYsIGIFo3jaW9y6gLS50jAgUedb+VinRKivVincScBE6sgImNAO
         sDRKrVhsCQL/x5Xz/Rft1vppjug3OmnEJhlNzVhoEHFjIA9geG5B6VVWEWuC/uJ1ZzNA
         noT83scZ7dIwr7dyiJ2HiRrrXAC2BKoPG7R9y6WAjAiwHDGjnBoTGPytzEmEXP//gSlN
         nP2LWnAlZz7VRd+vRSbjqT0P54N4OPZUmGhYCjIeGukc3ZQFdPlQm4VrbJh9XkE95/Wx
         1ndu6EeduJ5DekIgXUb4qDYS3c2Est6Y2MJxQs+lSzaPDzrtRQy+pibeCQ4nml/tqnst
         wYZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :references:cc:to:from:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gWTvVB/w2BbJtG8uyuyMcinmWnyb8HR9kaudVzNhC0o=;
        b=OquTODZr7k4gOSSCEb/7HBr1wMDaQAftwLimmfnMXAB0Og84YKOdPKoGmn3pyR2LJU
         AF6QIocI1Km8Vz2OtsOpDdbPCkIj0ALXys072gAC4NCG21Pf6x5Gz+0o5SZwh38n64VP
         PJrnWYe+z3tHvlBOxdGh31SAVg1OpQhAHlfha/6d2+Wxo2s6OIt/l5T5DogLJMauvq4e
         Hkx7rH5vDHedOMBbYd1GJ/iksr/d7fQDwykCUTI9/63vfH5jz695YZAzIMwEbcBxkrDH
         MAv1MFFZqPgwfR6RyMIKdACf6qVLnie9te98BfyrBzfhBAOYObsLqrhDaSB2XJ6YZVA6
         rOWQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0Iy28+ZFyhm8xJWB+UYgNxEd7oSTKHthism/qyDKudknuxB+zE
	Qkr9lT1Q9K8Kt0CR4DJJXRA=
X-Google-Smtp-Source: AMsMyM746iqA2Ko9X+30Qgf2gV+HblzDpnghwqfxiQyEDZ/nJqT6xfdIOQCCkJV9xKG38wPs41unxw==
X-Received: by 2002:a17:906:7199:b0:7ad:fa6c:71b7 with SMTP id h25-20020a170906719900b007adfa6c71b7mr12223022ejk.24.1667496956079;
        Thu, 03 Nov 2022 10:35:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:79c8:b0:78d:e7b8:d105 with SMTP id
 m8-20020a17090679c800b0078de7b8d105ls1635402ejo.8.-pod-prod-gmail; Thu, 03
 Nov 2022 10:35:54 -0700 (PDT)
X-Received: by 2002:a17:906:eecb:b0:73c:5c85:142b with SMTP id wu11-20020a170906eecb00b0073c5c85142bmr30544303ejb.433.1667496954695;
        Thu, 03 Nov 2022 10:35:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667496954; cv=none;
        d=google.com; s=arc-20160816;
        b=XvUYOqTDAA7gDkj+SB9ywC0tI0Mp+EygjdzLlV2QUlSAP0Mw3KSh8AI4t2oInsM6ON
         Fw81XssBDTLcw5+qzHQLg02EKVZFiBFzxJ2dDmjG/cWsXoUG46ToPhRBgszKfsT3zcbc
         ebNU25cHHkXWqGGLhKwmP1fYcQ3ZI7n1o3hC2rDKdnUkK56g5ScLglE3PIbLTMrfIq5C
         yBBaaGjuzmPmCPE6GX875fxOCrdc8bKOvlnT66k9yS/aEm7UI0JE1m0nAbbkPstZwdE4
         hUrxyGhUpyZSG8ka/74i5+zMgsrxXnBJWRM9vdVptbTiQ15QQcZp9MgNwRA61V8zcSkY
         ocIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=x5fPxg74k9nDezbbPmuSdS/AXJ08qTd6qzUcL/CU6Ro=;
        b=YsCFEEh6nwxERZCwbU6BkPNcpG9lz3k2gmvkskRvR2FhIGsV7kDZd0AtVkDmWfqsy1
         tW12uzXJz25P8qdbfdNVT0gQDyCEfPqIAavVPf8IsaDmOgMspC0yI29/iYHOpR/OVI8q
         kF7LwfjOaelnvD0bwCx4r2yFvXX6NUQIlBom/fGQ+8/3CaaQaOFL/wziwpMCU+QDy7Tw
         Nj4Ic5Ubeuz79K4Ta3hFMZSE54Ox8O3LNROw20NHuDXt877D6yRzUF3dxdPYpS6KdPFz
         gJZMw8pZ1ZlvxshNUqzB+Hv9uAazZP9IQBiLSV/DEt0CfxFpX+JRVmYsg3IAlGgX2pjX
         JefQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=H8+o9jGi;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id ib18-20020a1709072c7200b007ae2368c8cdsi67322ejc.2.2022.11.03.10.35.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 03 Nov 2022 10:35:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 457FF21C2D;
	Thu,  3 Nov 2022 17:35:54 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id DFF1A13AAF;
	Thu,  3 Nov 2022 17:35:53 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id jLTXNfn7Y2NKZQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Thu, 03 Nov 2022 17:35:53 +0000
Message-ID: <55ace2db-80b6-04db-e8b5-03bd3b5061cf@suse.cz>
Date: Thu, 3 Nov 2022 18:35:53 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.4.0
Subject: Re: [PATCH v6 1/4] mm/slub: enable debugging memory wasting of
 kmalloc
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>, Feng Tang <feng.tang@intel.com>
Cc: John Thomson <lists@johnthomson.fastmail.com.au>,
 Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>,
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
 Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
 "linux-mips@vger.kernel.org" <linux-mips@vger.kernel.org>,
 Kees Cook <keescook@chromium.org>
References: <Y1+0sbQ3R4DB46NX@feng-clx>
 <9b71ae3e-7f53-4c9e-90c4-79d3d649f94c@app.fastmail.com>
 <Y2DReuPHZungAGsU@feng-clx>
 <53b53476-bb1e-402e-9f65-fd7f0ecf94c2@app.fastmail.com>
 <Y2DngwUc7cLB0dG7@hyeyoo>
 <29271a2b-cf19-4af9-bfe5-5bcff8a23fda@app.fastmail.com>
 <097d8fba-bd10-a312-24a3-a4068c4f424c@suse.cz> <Y2NXiiAF6V2DnBrB@feng-clx>
 <f88a5d34-de05-25d7-832d-36b3a3eddd72@suse.cz> <Y2PNLENnxxpqZ74g@feng-clx>
 <Y2PR45BW2mgLLMwC@hyeyoo> <8f2cc14c-d8b3-728d-7d12-13f2c1b0d8a0@suse.cz>
In-Reply-To: <8f2cc14c-d8b3-728d-7d12-13f2c1b0d8a0@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=H8+o9jGi;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

On 11/3/22 17:57, Vlastimil Babka wrote:
> On 11/3/22 15:36, Hyeonggon Yoo wrote:
>> On Thu, Nov 03, 2022 at 10:16:12PM +0800, Feng Tang wrote:
>>> On Thu, Nov 03, 2022 at 09:33:28AM +0100, Vlastimil Babka wrote:
>>> [...]
>>> > >> AFAICS before this patch, we "survive" "kmem_cache *s" being NULL as
>>> > >> slab_pre_alloc_hook() will happen to return NULL and we bail out from
>>> > >> slab_alloc_node(). But this is a side-effect, not an intended protection.
>>> > >> Also the CONFIG_TRACING variant of kmalloc_trace() would have called
>>> > >> trace_kmalloc dereferencing s->size anyway even before this patch.
>>> > >> 
>>> > >> I don't think we should add WARNS in the slab hot paths just to prevent this
>>> > >> rare error of using slab too early. At most VM_WARN... would be acceptable
>>> > >> but still not necessary as crashing immediately from a NULL pointer is
>>> > >> sufficient.
>>> > >> 
>>> > >> So IMHO mips should fix their soc init, 
>>> > > 
>>> > > Yes, for the mips fix, John has proposed to defer the calling of prom_soc_init(),
>>> > > which looks reasonable.
>>> > > 
>>> > >> and we should look into the
>>> > >> CONFIG_TRACING=n variant of kmalloc_trace(), to pass orig_size properly.
>>> > > 
>>> > > You mean check if the pointer is NULL and bail out early. 
>>> > 
>>> > No I mean here:
>>> > 
>>> > #else /* CONFIG_TRACING */
>>> > /* Save a function call when CONFIG_TRACING=n */
>>> > static __always_inline __alloc_size(3)                                   
>>> > void *kmalloc_trace(struct kmem_cache *s, gfp_t flags, size_t size)
>>> > {       
>>> >         void *ret = kmem_cache_alloc(s, flags);
>>> >                     
>>> >         ret = kasan_kmalloc(s, ret, size, flags);
>>> >         return ret;
>>> > }
>>> > 
>>> > we call kmem_cache_alloc() and discard the size parameter, so it will assume
>>> > s->object_size (and as the side-effect, crash if s is NULL). We shouldn't
>>> > add "s is NULL?" checks, but fix passing the size - probably switch to
>>> > __kmem_cache_alloc_node()? and in the following kmalloc_node_trace() analogically.
>>>  
>>> Got it, thanks! I might have missed it during some rebasing for the
>>> kmalloc wastage debug patch.
>> 
>> That was good catch and I missed too!
>> But FYI I'm suggesting to drop CONFIG_TRACING=n variant:
>> 
>> https://lore.kernel.org/linux-mm/20221101222520.never.109-kees@kernel.org/T/#m20ecf14390e406247bde0ea9cce368f469c539ed
>> 
>> Any thoughts?
> 
> I'll get to it, also I think we were pondering that within your series too,
> but I wanted to postpone in case somebody objects to the extra function call
> it creates.
> But that would be for 6.2 anyway while I'll collect the fix here for 6.1.

On second thought, the fix is making the inlined kmalloc_trace() expand to a
call that had 2 parameters and now it has 5, which seems to me like a worse
thing (code bloat) than the function call. With the other reasons to ditch
the CONFIG_TRACING=n variant I'm inclined to just do it right now.

>>> 
>>> How about the following fix?
>>> 
>>> Thanks,
>>> Feng
>>> 
>>> ---
>>> From 9f9fa9da8946fd44625f873c0f51167357075be1 Mon Sep 17 00:00:00 2001
>>> From: Feng Tang <feng.tang@intel.com>
>>> Date: Thu, 3 Nov 2022 21:32:10 +0800
>>> Subject: [PATCH] mm/slub: Add missing orig_size parameter for wastage debug
>>> 
>>> commit 6edf2576a6cc ("mm/slub: enable debugging memory wasting of
>>> kmalloc") was introduced for debugging kmalloc memory wastage,
>>> and it missed to pass the original request size for kmalloc_trace()
>>> and kmalloc_node_trace() in CONFIG_TRACING=n path.
>>> 
>>> Fix it by using __kmem_cache_alloc_node() with correct original
>>> request size.
>>> 
>>> Fixes: 6edf2576a6cc ("mm/slub: enable debugging memory wasting of kmalloc")
>>> Suggested-by: Vlastimil Babka <vbabka@suse.cz>
>>> Signed-off-by: Feng Tang <feng.tang@intel.com>
>>> ---
>>>  include/linux/slab.h | 9 +++++++--
>>>  1 file changed, 7 insertions(+), 2 deletions(-)
>>> 
>>> diff --git a/include/linux/slab.h b/include/linux/slab.h
>>> index 90877fcde70b..9691afa569e1 100644
>>> --- a/include/linux/slab.h
>>> +++ b/include/linux/slab.h
>>> @@ -469,6 +469,9 @@ void *__kmalloc_node(size_t size, gfp_t flags, int node) __assume_kmalloc_alignm
>>>  							 __alloc_size(1);
>>>  void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t flags, int node) __assume_slab_alignment
>>>  									 __malloc;
>>> +void *__kmem_cache_alloc_node(struct kmem_cache *s, gfp_t flags, int node,
>>> +				size_t orig_size, unsigned long caller) __assume_slab_alignment
>>> +									 __malloc;
>>>  
>>>  #ifdef CONFIG_TRACING
>>>  void *kmalloc_trace(struct kmem_cache *s, gfp_t flags, size_t size)
>>> @@ -482,7 +485,8 @@ void *kmalloc_node_trace(struct kmem_cache *s, gfp_t gfpflags,
>>>  static __always_inline __alloc_size(3)
>>>  void *kmalloc_trace(struct kmem_cache *s, gfp_t flags, size_t size)
>>>  {
>>> -	void *ret = kmem_cache_alloc(s, flags);
>>> +	void *ret = __kmem_cache_alloc_node(s, flags, NUMA_NO_NODE,
>>> +					    size, _RET_IP_);
>>>  
>>>  	ret = kasan_kmalloc(s, ret, size, flags);
>>>  	return ret;
>>> @@ -492,7 +496,8 @@ static __always_inline __alloc_size(4)
>>>  void *kmalloc_node_trace(struct kmem_cache *s, gfp_t gfpflags,
>>>  			 int node, size_t size)
>>>  {
>>> -	void *ret = kmem_cache_alloc_node(s, gfpflags, node);
>>> +	void *ret = __kmem_cache_alloc_node(s, gfpflags, node,
>>> +					    size, _RET_IP_);
>>>  
>>>  	ret = kasan_kmalloc(s, ret, size, gfpflags);
>>>  	return ret;
>>> -- 
>>> 2.34.1
>>> 
>>> 
>>> 
>> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/55ace2db-80b6-04db-e8b5-03bd3b5061cf%40suse.cz.
