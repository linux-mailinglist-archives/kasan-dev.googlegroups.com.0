Return-Path: <kasan-dev+bncBDXYDPH3S4OBBMELYGVQMGQE7PBF2XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 56EDE806B21
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Dec 2023 10:58:10 +0100 (CET)
Received: by mail-yb1-xb37.google.com with SMTP id 3f1490d57ef6-db084a0a2e9sf5956659276.2
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Dec 2023 01:58:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701856689; cv=pass;
        d=google.com; s=arc-20160816;
        b=P88hTi/XxNxXyTpIRqChermYOi3j/FVpomVov3w+0F38sonSD1xuO0uorgs+Tq7vY8
         3w3zXPbd1Es/Y3o3XVcMNW4nO9HlsClYzuSrfvQwM4Nl7V0yWYD1WXA6mki94u4LYVz1
         mjg9BLjkLbLAyct5lwA6nbE60pcyXsZ7L3byZujIPM2cd5z9DQ6xkh/a/pdXEmWHm6ez
         RRqsLVrUkpfN1J0/uymFt1TGnvB+KCDT9RWa4Z7jrXWrQtGpVL5Aso+l0iB/EbJQuNTO
         q7JkQglNqJGU0nr2V8vZTtzrkDaEL6F2OqUefREMUx3xp7mzWJ46bRh2bjcIe2aRdjF3
         8GtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=tERQd/G1EXOyCXSjVJtMHc4Z1Gmxmlc4i9vZorXQxlo=;
        fh=9X7yEfYxJ/tFgIQ5VFuCUNBLLeevXlUaPxar/RtzLRg=;
        b=pbuGdm5nPCVn7nqHLUwrfbUfLAGmW9wSX0m/nOxvgMeLAfhxRke+TiZ6YX9I4xHduL
         4tuVc8eqWExZ4cULj9jl+Eb5km7D0BQ3n1A+S5+b6CCGJhF5O5wlICp22ohNQ/mraMiv
         B1i/AFW5ieLKwCVaIL2nWRqB8u84Y3QMNi4l8wghs8liOG8MQGVFq9SLHaCtNWaeabGw
         u8d/pXLuhVCz+M/Dcxv5mB+JsWIUqccKoWi9KmS2BbVxBSP+uzXMVgZMEwyrYdDABGvc
         /2z3eOG23LhGZntzZmP7DwmAjHbdl7XlAbHKLpW9vUJrL6Sh9sZjzq9mjXKcYc1opBIx
         31PQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=TyDveYqJ;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701856689; x=1702461489; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=tERQd/G1EXOyCXSjVJtMHc4Z1Gmxmlc4i9vZorXQxlo=;
        b=m3SpJ9v+NWGfDb3SG4zkX4GwKR+DEtA7OgbD8DCCrmgQl+k9o0Mj1gRTRQk0aiZoZ6
         +oNkP5xxLBt5s5Uz9LguCmq1K0IoocQLQ6VOx1zm9TA9nD5zlaCh6mK6DY4oWk2XhO+l
         3ceYd4OknyypuELPGkUSZIuMJwEuLUoALAiXyrAWAa6mFqyj9LV9xN7K1kI049rU5C10
         Z2gLoHqsa8YdIQwQtjgLDD/9Eb8zXrNFRvqv9brNE5+mT8eB6Ufi/VqbiIP4PB2njeKQ
         f+qZCqmSJWB6ZYVioCTHzlIHjSCuhw4buP5c6vKJwWAFCveeE1LMyfvlX9wFrcwBmNBU
         Bb3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701856689; x=1702461489;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tERQd/G1EXOyCXSjVJtMHc4Z1Gmxmlc4i9vZorXQxlo=;
        b=O868HiHW8Gdl3G3DxM5FTKkyZOptmMFhITjwoBxY2NqlmFc55qrwyXfUZ30SazgXy7
         k/BuMyLvsRfYNGRQKRTTs9rS5EgMIoMw7JcZDK3/iMsnHN2fFMOi2GqUVTu7aRPc03oD
         DcT3NVFx0iGV/b+GpOEoCFkp6wCrCSgQnOZGmtR9FeeenU5G1bRKWy4PedbcbBX2dsr1
         +oUgDBA5GcNUP2MDIiwy/3O1vcVNtb8Qy2VUC2usmW1EVDiqgFP4qENIb3zkFzQ9YRiU
         yH4l3xF9LXrbBXoy5VdJHPrX9E7rCvno4kp2ijnLV1WyQdNM+d02quxPKTfVUe7hfU8O
         8/jg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzFmeeppYGNQTs75kklX1ZWXeC6FdjjPJzLbhXn4KWjtBcbD8Qp
	IHp/VGm+dmysCVX1Zcjh4R8=
X-Google-Smtp-Source: AGHT+IFDa3uRTzLpaOoyoqu/XrK3uLzIVdBtglA7VKskRcpaOkHZJU2gY564bh1sWV3xJyhR+QngkA==
X-Received: by 2002:a5b:4c1:0:b0:db7:dad0:60bd with SMTP id u1-20020a5b04c1000000b00db7dad060bdmr392187ybp.74.1701856689025;
        Wed, 06 Dec 2023 01:58:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:3145:0:b0:d85:e5d1:b8c6 with SMTP id x66-20020a253145000000b00d85e5d1b8c6ls165884ybx.2.-pod-prod-08-us;
 Wed, 06 Dec 2023 01:58:08 -0800 (PST)
X-Received: by 2002:a81:484c:0:b0:5d7:1941:2c36 with SMTP id v73-20020a81484c000000b005d719412c36mr433782ywa.99.1701856687931;
        Wed, 06 Dec 2023 01:58:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701856687; cv=none;
        d=google.com; s=arc-20160816;
        b=BW/ztgOkOD4fTOwTku38moPPpkEDnnjpuu5gx1hjyWFF4JKsvKMXSLV4SnCuqAG/xj
         kSbcLHQTYkiE4+VsKboji9AHGjg9w94/xl8eaqBcZcETpe5pDZH++ZT6nA6QOzRapoEI
         AsoE6oLSkf00qXwRjFMlD5o9DY/zfNYBaoqhYD1RY/FiHlOeDbP67vZu+VL2ip3+7kuS
         WAkqSxX6h8l2ideJhnwYk1w+CLCCfcLzPPjoOsRQ47tmESrqbBHSexKvAha/mHzmMng+
         Rz0N1lpLybqyHBHfBp70CxiFYLZjlxQ4pZjbAFiKXiswCFxToOcql88X5bad57UoH+zr
         5ezg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=8sXZ1VnaFvD+d6tTkWgPtcPa6GYEwUd43mPhrV5ynPM=;
        fh=9X7yEfYxJ/tFgIQ5VFuCUNBLLeevXlUaPxar/RtzLRg=;
        b=zNcYPAoyhJFFjca7xZ6dMfi375AzVJKWROsXd6TVCbfTdaOUMvfFCJEHg7z4DaY8on
         qPUtGaGdsUVcL3DSWFkx/0TXp830hboiihO2maBd4PkWvK3fgJAzZ9v9UZgDVY978O/B
         SSOLlXE/2bUaF12O1XxtBCpsOFjYt0hmCwjIl0iOdg4gUwhk8xxMqDaSwjbOWW27iIUo
         BBRdRs/aO/B8GIgl70MWiKJdGKi47H5LqGOfWAukX8rT45vlhYzF6JbGB5kVIHjqfVYz
         a6soH98UwDYRYLIKwCOZl9zkg//LtmdDA9nwnq8wojOvwb6dUJG3Sio3XnVZcQOC8UPp
         nIoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=TyDveYqJ;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id bn18-20020a056130081200b007c56697eaefsi1148546uab.1.2023.12.06.01.58.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Dec 2023 01:58:07 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id D07F221F4E;
	Wed,  6 Dec 2023 09:58:05 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id AFFE413408;
	Wed,  6 Dec 2023 09:58:05 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id HN+WKq1FcGVxTgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 06 Dec 2023 09:58:05 +0000
Message-ID: <79e29576-12a2-a423-92f3-d8a7bcd2f0ce@suse.cz>
Date: Wed, 6 Dec 2023 10:58:05 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.15.1
Subject: Re: [PATCH 4/4] mm/slub: free KFENCE objects in slab_free_hook()
Content-Language: en-US
To: Chengming Zhou <chengming.zhou@linux.dev>,
 Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Alexander Potapenko
 <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
References: <20231204-slub-cleanup-hooks-v1-0-88b65f7cd9d5@suse.cz>
 <20231204-slub-cleanup-hooks-v1-4-88b65f7cd9d5@suse.cz>
 <44421a37-4343-46d0-9e5c-17c2cd038cf2@linux.dev>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <44421a37-4343-46d0-9e5c-17c2cd038cf2@linux.dev>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Flag: NO
X-Spamd-Result: default: False [-2.80 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 MID_RHS_MATCH_FROM(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 BAYES_HAM(-3.00)[100.00%];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 RCPT_COUNT_TWELVE(0.00)[14];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,bytedance.com:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,linux.dev,gmail.com,google.com,kvack.org,vger.kernel.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Score: -2.80
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=TyDveYqJ;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1
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

On 12/5/23 14:27, Chengming Zhou wrote:
> On 2023/12/5 03:34, Vlastimil Babka wrote:
>> When freeing an object that was allocated from KFENCE, we do that in the
>> slowpath __slab_free(), relying on the fact that KFENCE "slab" cannot be
>> the cpu slab, so the fastpath has to fallback to the slowpath.
>> 
>> This optimization doesn't help much though, because is_kfence_address()
>> is checked earlier anyway during the free hook processing or detached
>> freelist building. Thus we can simplify the code by making the
>> slab_free_hook() free the KFENCE object immediately, similarly to KASAN
>> quarantine.
>> 
>> In slab_free_hook() we can place kfence_free() above init processing, as
>> callers have been making sure to set init to false for KFENCE objects.
>> This simplifies slab_free(). This places it also above kasan_slab_free()
>> which is ok as that skips KFENCE objects anyway.
>> 
>> While at it also determine the init value in slab_free_freelist_hook()
>> outside of the loop.
>> 
>> This change will also make introducing per cpu array caches easier.
>> 
>> Tested-by: Marco Elver <elver@google.com>
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> ---
>>  mm/slub.c | 22 ++++++++++------------
>>  1 file changed, 10 insertions(+), 12 deletions(-)
>> 
>> diff --git a/mm/slub.c b/mm/slub.c
>> index ed2fa92e914c..e38c2b712f6c 100644
>> --- a/mm/slub.c
>> +++ b/mm/slub.c
>> @@ -2039,7 +2039,7 @@ static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
>>   * production configuration these hooks all should produce no code at all.
>>   *
>>   * Returns true if freeing of the object can proceed, false if its reuse
>> - * was delayed by KASAN quarantine.
>> + * was delayed by KASAN quarantine, or it was returned to KFENCE.
>>   */
>>  static __always_inline
>>  bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
>> @@ -2057,6 +2057,9 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
>>  		__kcsan_check_access(x, s->object_size,
>>  				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);
>>  
>> +	if (kfence_free(kasan_reset_tag(x)))
> 
> I'm wondering if "kasan_reset_tag()" is needed here?

I think so, because AFAICS the is_kfence_address() check in kfence_free()
could be a false negative otherwise. In fact now I even question some of the
other is_kfence_address() checks in mm/slub.c, mainly
build_detached_freelist() which starts from pointers coming directly from
slab users. Insight from KASAN/KFENCE folks appreciated :)

> The patch looks good to me!
> 
> Reviewed-by: Chengming Zhou <zhouchengming@bytedance.com>

Thanks!

> Thanks.
> 
>> +		return false;
>> +
>>  	/*
>>  	 * As memory initialization might be integrated into KASAN,
>>  	 * kasan_slab_free and initialization memset's must be
>> @@ -2086,23 +2089,25 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
>>  	void *object;
>>  	void *next = *head;
>>  	void *old_tail = *tail;
>> +	bool init;
>>  
>>  	if (is_kfence_address(next)) {
>>  		slab_free_hook(s, next, false);
>> -		return true;
>> +		return false;
>>  	}
>>  
>>  	/* Head and tail of the reconstructed freelist */
>>  	*head = NULL;
>>  	*tail = NULL;
>>  
>> +	init = slab_want_init_on_free(s);
>> +
>>  	do {
>>  		object = next;
>>  		next = get_freepointer(s, object);
>>  
>>  		/* If object's reuse doesn't have to be delayed */
>> -		if (likely(slab_free_hook(s, object,
>> -					  slab_want_init_on_free(s)))) {
>> +		if (likely(slab_free_hook(s, object, init))) {
>>  			/* Move object to the new freelist */
>>  			set_freepointer(s, object, *head);
>>  			*head = object;
>> @@ -4103,9 +4108,6 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
>>  
>>  	stat(s, FREE_SLOWPATH);
>>  
>> -	if (kfence_free(head))
>> -		return;
>> -
>>  	if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
>>  		free_to_partial_list(s, slab, head, tail, cnt, addr);
>>  		return;
>> @@ -4290,13 +4292,9 @@ static __fastpath_inline
>>  void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
>>  	       unsigned long addr)
>>  {
>> -	bool init;
>> -
>>  	memcg_slab_free_hook(s, slab, &object, 1);
>>  
>> -	init = !is_kfence_address(object) && slab_want_init_on_free(s);
>> -
>> -	if (likely(slab_free_hook(s, object, init)))
>> +	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
>>  		do_slab_free(s, slab, object, object, 1, addr);
>>  }
>>  
>> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/79e29576-12a2-a423-92f3-d8a7bcd2f0ce%40suse.cz.
