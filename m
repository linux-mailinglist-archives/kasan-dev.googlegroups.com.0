Return-Path: <kasan-dev+bncBDXYDPH3S4OBBC4MXDFQMGQESCGI7VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id BBDE5D3A4D6
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 11:23:08 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-64cfbb4c464sf4006580a12.2
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 02:23:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768818188; cv=pass;
        d=google.com; s=arc-20240605;
        b=KLGI5dYhvmXg3u6X++KzVX3VLp/kOWSMG/bQlm8h9EHLsBAdnQf9YAPTiDtcn+J9k6
         lw5V3+YByM72LI7LcdNVsTkKIwHEJ4nS9OzBFnEelPoweIRzbd5RrheyQ5NNCDbSMJrc
         X14opUodIvNKhz6T6dTrCehSrhtgCCpMpzraE6OD40glPCDJcWbrS8/FkxrjCKpD++w3
         FM2rtDcgS7LJVNSCzFWZbLcl9AuwegNDkuSDwjNnQBWHrjeG9b3vPf2VE90n+Ddz6hKB
         00KPHyMxac5aBlBOFes04Lu5zM7rUXHgV+IoWjtojxMFaJEdgAqffZtQRhpn/HM5qPiN
         Nxqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:references:cc
         :to:from:content-language:subject:user-agent:mime-version:date
         :message-id:sender:dkim-signature;
        bh=KJ/h1qPYwswnRDePyCbOCko5dsBC2OSRkGHvOgt/2Pg=;
        fh=FFu/D3eon+kGYig9TbWlBheYmI/lNRqH2qs94rsxle8=;
        b=K0fAOqKahxUJMo9gWL+gkutgBceJp0MLRJu0UWC8MLaMBd+e4Her4B8XENzQHq1i5J
         hMama9xppmxFh6dj+KOOIkJkhLrrJR/9wprAaGjffpL9mYzGEZGLtL+Qv7ahVb7p5/3Z
         WtTt6DjLqCxBY0e/Sy3pRElIkjyP0khDkHQzinXhBx3G2LQr6M8tt7EhSNtdz8O85OQS
         tAbjyb5yiXP7HSzFunHLx527UWzKjtxMHTjCwk5eF+/KFOn7XcSt7G14cJfA3/adbzyr
         ZB3eeBvfBwo4RrFkIrzFKf/IpQ4TeWMQ1SCB7kxUIJ5lOZbot1J3choO4u9Ismilmc4m
         uwHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=rzUalRp0;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=rzUalRp0;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768818188; x=1769422988; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KJ/h1qPYwswnRDePyCbOCko5dsBC2OSRkGHvOgt/2Pg=;
        b=PrO4NtzeJyY6sxpNNJqMolKzobqhNtMp36jsEDUdfyrRhfa3cv1ylEcj/tc1U5KXgC
         Juk5QkgkpOhPf7ghaH4CnL5poeBxYTGG7Wo+NqWhHMD7WUWC4O9QopBYzBRrfZuJK0VL
         aklfiSDLRAuk4LXl6OVMvw3DdGircsa7F/STZSNP1SOS09uZcVPyhXBBMj2zC9xN9IOY
         o9SS4hq41Zck8zT6UD0No0JQZHEBsHkE5DGWJ3U++iho2/0D4GgeZta9CJb0Rq6JH70y
         wZeF11hG3VMlKJidqOOex+PRunKZz65pH+rmDJW0dqP7DcFt7fkDt2rTKnJq9SzKSyAb
         QzLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768818188; x=1769422988;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:references:cc:to:from:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=KJ/h1qPYwswnRDePyCbOCko5dsBC2OSRkGHvOgt/2Pg=;
        b=Fo7DgdzKor4wESUPXR2Xf/1u4sl1TjsdOlEKiOubY3IZBz8qEdWe29I+0kW+Rgwps8
         hwJWf+4Yww8FqvHR9brib9ZDNPAwzEPktqdsTA4n+cCbKOP+ZGdOWEyEIiLybMwYdGHu
         4CZ/B9BVatzJBtpg6SrkhUtJgBeYNU6UXGNiun8FOjJUDToNjHfzJ6iAi1NXtp9T32RD
         qOVgvnyC9WLMrJ9lvJ49bbHAEojwvA4w2+dS6jMp6wDr8nQUcMQvjLP7akY4hnQSo0/J
         9BXT3JdefSBTdBvCii6ka2dkQwXf3gRb2UQH6M/r5PSHrCE4RiPWBTF5YZqGOEA3jBx9
         sv0A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWuAEbgCh9LO5ydWsyd1r1W9NJmI5U5u9N0T331ewR/jHiuIbsKC9FAM56ZmSzz84Au7og1mA==@lfdr.de
X-Gm-Message-State: AOJu0YyNVy1pxg4mLYJ0rxzQ5r0X+N+/E+wpQVuh5meYsePluPG/cU/l
	ih2x3zV/u2hfzViVaz7HPiZYhcs3Z1F3d2+cVokdxzbIpCtucOI+rj9d
X-Received: by 2002:a05:6402:3592:b0:64d:498b:aefd with SMTP id 4fb4d7f45d1cf-654524d421cmr7987617a12.5.1768818188043;
        Mon, 19 Jan 2026 02:23:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HZDtfosOMH1fHaQyA7IU1KNCoLpJ9DDTObpvba9Rq2Lg=="
Received: by 2002:a05:6402:a254:20b0:64b:aa13:8b3e with SMTP id
 4fb4d7f45d1cf-6541c5da4f8ls3159678a12.1.-pod-prod-02-eu; Mon, 19 Jan 2026
 02:23:06 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW7BjmJd5GCg8oRbmAXs47n5PS7GTBMUGUpqnvN1snGDUUAvZCTAo+UUSFvSN5NDaEnoI0/Kq14vW0=@googlegroups.com
X-Received: by 2002:a05:6402:5209:b0:649:815e:3fac with SMTP id 4fb4d7f45d1cf-65452cca24fmr8414338a12.23.1768818185836;
        Mon, 19 Jan 2026 02:23:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768818185; cv=none;
        d=google.com; s=arc-20240605;
        b=eTqvsvBWeUy8+l95dv3J3jl8PV+H2UsP5pbNRs3MZQLeU9zqBOuIrWSIOI1Pugli4w
         7IEcM56zHvpjwhXRow96GHBfi7M8tzntmT7bbs7mPGQWp7zvXd3qHaBuTkD7HqiKI+TG
         NRB6Q7KyZFIJXqipF2j0XosTCf3ilV/1wHtDb0hiOCjaGGGDja7YOyrvW/rrDIOsBYwd
         lpgATCRu9cuYM+/nABN7sqwJjRcJ59SaXcRaKv3PYt1BgpM25qqfSrpgybP3+Zau+GPj
         pSS+JJo3vz1vKYUAXRC9Go235xQCF6XkNWwSKHJgNrEBv0AjhLvC2tr2ViIp41GxIoLR
         vecQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:references:cc:to
         :from:content-language:subject:user-agent:mime-version:date
         :message-id:dkim-signature:dkim-signature:dkim-signature
         :dkim-signature;
        bh=9LPIZza5xMgwGATkmayqvdDkw9ZyBilQW7+UyjARpNY=;
        fh=KDJM2J+CluSNuZFMRpSGdSzTe0G9RbhFzt5xcVD9hkE=;
        b=lZdTqXNutJYlOBZMZ0Pj77XDk7dlowg6dbhkzvgh1pF7imiBHDqtdl2kcv8DgsYkUJ
         BPBLqmufZpyfZ9Ggp+5tose4jvICi7CPZlesWfy/GSI4iIRdHicbxbAZSZ3gzpUSuwk9
         7t4XRT0XObCcmnIPm0BWmH/0XO7/e+LYXXaagFtrVWV/PJ0w1+CwsaZe+BJO9u/f2Pbw
         OHl0II7fAquhUrlNyxJD/uqQKVvef64w6cOenGSBbDmeKBtQSKt7n3ZB6QV36dA+jOdF
         iA22EfTdICV2ffZKV8iojnjwo5OwIFXunnt9B02o3V9dMglFtyXUeCMuRjNffibCRyR2
         2HpA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=rzUalRp0;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=rzUalRp0;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-654532cef9dsi206946a12.6.2026.01.19.02.23.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Jan 2026 02:23:05 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 3C9EC5BD46;
	Mon, 19 Jan 2026 10:23:05 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 07B923EA65;
	Mon, 19 Jan 2026 10:23:05 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id jRWXAAkGbmndCgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 19 Jan 2026 10:23:05 +0000
Message-ID: <008029ff-3fd8-49cf-8aa7-71b98dc15be9@suse.cz>
Date: Mon, 19 Jan 2026 11:23:04 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 07/21] slab: make percpu sheaves compatible with
 kmalloc_nolock()/kfree_nolock()
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Petr Tesarik <ptesarik@suse.com>, Christoph Lameter <cl@gentwo.org>,
 David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
 Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-7-5595cb000772@suse.cz>
 <aW2zmf4dXL5C_Iu2@hyeyoo> <e4831aab-40e6-48ec-a4b9-1967bd0d6a4c@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <e4831aab-40e6-48ec-a4b9-1967bd0d6a4c@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -4.30
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	ARC_NA(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[17];
	RCVD_TLS_ALL(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo]
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=rzUalRp0;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=rzUalRp0;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 1/19/26 11:09, Vlastimil Babka wrote:
> On 1/19/26 05:31, Harry Yoo wrote:
>> On Fri, Jan 16, 2026 at 03:40:27PM +0100, Vlastimil Babka wrote:
>>> Before we enable percpu sheaves for kmalloc caches, we need to make sure
>>> kmalloc_nolock() and kfree_nolock() will continue working properly and
>>> not spin when not allowed to.
>>> 
>>> Percpu sheaves themselves use local_trylock() so they are already
>>> compatible. We just need to be careful with the barn->lock spin_lock.
>>> Pass a new allow_spin parameter where necessary to use
>>> spin_trylock_irqsave().
>>> 
>>> In kmalloc_nolock_noprof() we can now attempt alloc_from_pcs() safely,
>>> for now it will always fail until we enable sheaves for kmalloc caches
>>> next. Similarly in kfree_nolock() we can attempt free_to_pcs().
>>> 
>>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>>> ---
>> 
>> Looks good to me,
>> Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
> 
> Thanks.
> 
>> 
>> with a nit below.
>> 
>>>  mm/slub.c | 79 ++++++++++++++++++++++++++++++++++++++++++++-------------------
>>>  1 file changed, 56 insertions(+), 23 deletions(-)
>>> 
>>> diff --git a/mm/slub.c b/mm/slub.c
>>> index 706cb6398f05..b385247c219f 100644
>>> --- a/mm/slub.c
>>> +++ b/mm/slub.c
>>> @@ -6703,7 +6735,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
>>>  
>>>  	if (likely(!IS_ENABLED(CONFIG_NUMA) || slab_nid(slab) == numa_mem_id())
>>>  	    && likely(!slab_test_pfmemalloc(slab))) {
>>> -		if (likely(free_to_pcs(s, object)))
>>> +		if (likely(free_to_pcs(s, object, true)))
>>>  			return;
>>>  	}
>>>  
>>> @@ -6964,7 +6996,8 @@ void kfree_nolock(const void *object)
>>>  	 * since kasan quarantine takes locks and not supported from NMI.
>>>  	 */
>>>  	kasan_slab_free(s, x, false, false, /* skip quarantine */true);
>>> -	do_slab_free(s, slab, x, x, 0, _RET_IP_);
>>> +	if (!free_to_pcs(s, x, false))
>>> +		do_slab_free(s, slab, x, x, 0, _RET_IP_);
>>>  }
>> 
>> nit: Maybe it's not that common but should we bypass sheaves if
>> it's from remote NUMA node just like slab_free()?
> 
> Right, will do.

However that means sheaves will help less with the defer_free() avoidance
here. It becomes more obvious after "slab: remove the do_slab_free()
fastpath". All remote object frees will be deferred. Guess we can revisit
later if we see there are too many and have no better solution...

>>>  EXPORT_SYMBOL_GPL(kfree_nolock);
>>>  
>>> @@ -7516,7 +7549,7 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
>>>  		size--;
>>>  	}
>>>  
>>> -	i = alloc_from_pcs_bulk(s, size, p);
>>> +	i = alloc_from_pcs_bulk(s, flags, size, p);
>>>  
>>>  	if (i < size) { >  		/*
>>> 
>> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/008029ff-3fd8-49cf-8aa7-71b98dc15be9%40suse.cz.
