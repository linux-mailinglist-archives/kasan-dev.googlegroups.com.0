Return-Path: <kasan-dev+bncBDXYDPH3S4OBBUNIQPFQMGQENUAC3IA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id E910DD0871F
	for <lists+kasan-dev@lfdr.de>; Fri, 09 Jan 2026 11:11:31 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-38302c10113sf14405031fa.0
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Jan 2026 02:11:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767953491; cv=pass;
        d=google.com; s=arc-20240605;
        b=eVg8gdzTnvTJSGzvWqm39SFvC0NXpdbdWZp89NpuMEzC3XLuKWXV5SUfcsdVCkv81h
         GPSOHeT2FM7caq3btBZEF5FljYJkjbAWnQxi2TOyfyRpQtQltRbGBFFLQtQ++JXRc25Y
         OlJG0OByfNLNfmLCXpZydVnVGS0QAaUuv6FAcAUhRSN6jIxacwHHrRH2bBynFbZkhM8j
         SRwDJIII3qfKJ73lpaOP//H079Gvx+zF5ARtMCQPf+1a60fUVeoShkd+Rn7jb9vY6R9I
         E3PF8IgEuaNQUhoRpDQQPyTfLtg4sa8FNRE18hxWHf6l1Q1mF1vBi6ow8pNhRpJyhPVP
         I38g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=MeoU3cMGfXlAGwDf6rU1I+bx1sKLaEl6/ku2dpfOmwc=;
        fh=gv/2u9s4WrbNPcf/I1jVDz/E+4bOYJ4llIBLcWM6/vg=;
        b=ipLlUyO9fyLJPSxHbZQt+V/Zw9Cp7GW20nGD8SREdo2TgxCoT0Kco0kOW+yqfWCpK6
         NCCEPh/57dvsNMq6mFDrSV0Ktgp4spk9KtN6o2a03dVlZJdNLTr1d07tRPz98yOoo812
         W1FHak+A7fqAqfgbJO5Lplfrag1BBqyBE2kMyez6F4KddRCHnYisA+P0fyJE71jVS9ny
         H7YYmso++QsWkJ+9lmW2VvvlH5me1xg4U8Elk00M4BfYxmiFgFWoH2++9rXYVRkSq6Lc
         urh0UiJ0YyNIof2ykSVNiJKrxt8aq20gmKR1Aa2nC+ETW/6S3hsMTVIXksbCgsm5UpZR
         tVag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jYDrvCuk;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jYDrvCuk;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767953491; x=1768558291; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MeoU3cMGfXlAGwDf6rU1I+bx1sKLaEl6/ku2dpfOmwc=;
        b=A0L+i4zL2HBmCpz5LBMuCtcvrOVh3TxGXjKJRY/bxU/ktWw6kT4t0DvJUvtQVxbxdW
         n3yMfeDYYWwNCYbY2wM2LdCQVEVmc1Fl366D+PKLflkVe83fJm7QrmsYMxjW9dvG6Q3j
         8px1mzO23Wj45tuF4CBLnQ8wAOLNE/witd1OD625ArOMFCQOHOZ9OsJIyLTG2wVzqVHy
         6fKCUyzldqXNrp04nKQZKsXJHRXZ7Dbndm868nu0UHs+vYyFkPW3OyjPzQ0wfAQY3vW6
         RXC7DayugwRpwY7dx43OlxXEiEfarIwjq5mLC7+LvetLIR4WITvni6PKe4EW8gXcHnX3
         o+Sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767953491; x=1768558291;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=MeoU3cMGfXlAGwDf6rU1I+bx1sKLaEl6/ku2dpfOmwc=;
        b=qes5RcR56x/xahe+up/ENeXpYfJHMLVvxIq0grHbysD6Vxb+C2ywZFJk+Ud9wJmMkg
         ndfav5GuF/vYt/vN9p2vB/3d4J2CwyaFlFcY85c6g5OLf84et0L7rtdKZv9KZygV1Igo
         f7OpRKiaqHN79wULurOnVWW1jpGG5WiQgLqVRwwRsV2sM+eAjNf7d9CtEzaCNkq3XmM+
         94O33bapx8zmn+LkeryzhCTBks7jSqnRyE4axb9CcsTON8kX4d5VadeT4Umv42htMFR8
         yw3WUrdpnuV9Qxb7e4iV8YT2Rtvomtf+zNpFqDtF1AG00zTHK4xTeenNZOpD7douq4cO
         Db4Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWfY93b95k5LnWZJ2iNw8eskJzZFyPkGsTcImVS2mPc+N4lU7TAY3Adur4qsdcJ0aPITYfC9Q==@lfdr.de
X-Gm-Message-State: AOJu0YwcWz88jqZoFWMA8E01DbDGxixZofmJAyYNW+MRh5qpGvhG9jO0
	Y68RZnNweygoa2GqXZuNhCwnWgxYwosFcXEbY5MIjwBkoeVi/SxmEPBK
X-Google-Smtp-Source: AGHT+IEZMaSqzrAEnPTVSeDkVFzQLqrV59rl/JgSksoZYqaJPmm0SYyRyYTFejVlMVPlSXranjtDow==
X-Received: by 2002:a2e:b88c:0:b0:37b:575d:6403 with SMTP id 38308e7fff4ca-382ff65d404mr24160391fa.6.1767953490673;
        Fri, 09 Jan 2026 02:11:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZsHpIrW9s8CrXxFa95uw1NfNLeDF79IUCi7Rvou2a3+g=="
Received: by 2002:a05:651c:4410:20b0:37f:b4e0:a50c with SMTP id
 38308e7fff4ca-382e91b6ef3ls4735941fa.0.-pod-prod-03-eu; Fri, 09 Jan 2026
 02:11:27 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVkMdOiXm2+AGOoJB3NFW6KmrNfQhLwP67BgpKsbK6eMCk0kkPzBUGKBA/26KpFxZdJjXf4R33L7+g=@googlegroups.com
X-Received: by 2002:a2e:b88b:0:b0:383:25e7:88e8 with SMTP id 38308e7fff4ca-38325e78df1mr1097281fa.13.1767953487518;
        Fri, 09 Jan 2026 02:11:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767953487; cv=none;
        d=google.com; s=arc-20240605;
        b=HqunZMIcBZirOyX42MbisyISZTQmWJr4UprwAj7ecLwfOj6ooXltxKVhH/MeMeuNyn
         Bm5W+/8njpT3TPSwphjLU1k/ipzR9yyNAOzM4iLHqDHrUzYsQI+eFzlp878qY8ALJGd0
         ak3gS25bt08erAp/l3LdUYfC/VwGi/7vbDDyJyGD1xltgdvJAhCFD9nRfinsvnuMLhHi
         b6XwFtMyq+vW6Ep6NbuO0yDR3rI6egm2I7uEv7vdxGacLtCL8lOC8moq/ldpsyEvooou
         t6ke5Tz0IkEq2AvofBWQEx15V9CjtOCclcJ59Z4DDgdOT8Ulc4ohUl98zCi9uuZrKjLU
         AEjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=OeuS+cvfUoQlEy8DHNi+SqxMUrSUL35iDWvtyKO6N2g=;
        fh=lHkFV9K/xCYP4TZvEP9eQPk/i1dfhZdJRbTI+EwbyJ0=;
        b=D+Q9GH13W6AS3QBKQGw5odf7HeRf/bYUdZBuiBJNf/ENy3gb+Xgzc8feCBK0Txxf51
         Hey6gL1RjWwvXw3b5wU5DV1Rbc8Sw69nPYu/EGQFYDWm03SICLniAMwOsSFXNddpeHLq
         6IWki8N/mPtKJXfdb35mqRd/+BMRaTxalIrbJrOMMMZpFEHVVuDVpbzuS/eoiKz8grFO
         LGgydMdNhg07P1cvwPEO4lgqfwqDq2i4hxHacqN9Vm5Pwipj+L75lrBDth1fn+4aursU
         r/SXyvXGOoor7iBTlt6DE/Y0vtKr8G9hwdCioifBEfOE47dJOU8Vfj/w/p4wb9IbI6CZ
         CZyA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jYDrvCuk;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jYDrvCuk;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3831a5fadf5si333451fa.5.2026.01.09.02.11.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 09 Jan 2026 02:11:27 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id BCDCE33A6D;
	Fri,  9 Jan 2026 10:11:26 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 9FA133EA63;
	Fri,  9 Jan 2026 10:11:26 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id gTGnJk7UYGlzLQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 09 Jan 2026 10:11:26 +0000
Message-ID: <4fca7893-60bd-41da-844f-971934de19b6@suse.cz>
Date: Fri, 9 Jan 2026 11:11:26 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 14/19] slab: simplify kmalloc_nolock()
Content-Language: en-US
To: Hao Li <hao.li@linux.dev>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
 <20251023-sheaves-for-all-v1-14-6ffa2c9941c0@suse.cz>
 <4ukrk3ziayvxrcfxm2izwrwt3qrmr4fcsefl4n7oodc4t2hxgt@ijk63r4f3rkr>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <4ukrk3ziayvxrcfxm2izwrwt3qrmr4fcsefl4n7oodc4t2hxgt@ijk63r4f3rkr>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -4.30
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	ARC_NA(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	MIME_TRACE(0.00)[0:+];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[linux-foundation.org,gentwo.org,google.com,linux.dev,oracle.com,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCPT_COUNT_TWELVE(0.00)[16];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_DN_SOME(0.00)[]
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=jYDrvCuk;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=jYDrvCuk;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 12/16/25 03:35, Hao Li wrote:
> On Thu, Oct 23, 2025 at 03:52:36PM +0200, Vlastimil Babka wrote:
>> @@ -5214,27 +5144,13 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
>>  	if (ret)
>>  		goto success;
>>  
>> -	ret = ERR_PTR(-EBUSY);
>> -
>>  	/*
>>  	 * Do not call slab_alloc_node(), since trylock mode isn't
>>  	 * compatible with slab_pre_alloc_hook/should_failslab and
>>  	 * kfence_alloc. Hence call __slab_alloc_node() (at most twice)
>>  	 * and slab_post_alloc_hook() directly.
>> -	 *
>> -	 * In !PREEMPT_RT ___slab_alloc() manipulates (freelist,tid) pair
>> -	 * in irq saved region. It assumes that the same cpu will not
>> -	 * __update_cpu_freelist_fast() into the same (freelist,tid) pair.
>> -	 * Therefore use in_nmi() to check whether particular bucket is in
>> -	 * irq protected section.
>> -	 *
>> -	 * If in_nmi() && local_lock_is_locked(s->cpu_slab) then it means that
>> -	 * this cpu was interrupted somewhere inside ___slab_alloc() after
>> -	 * it did local_lock_irqsave(&s->cpu_slab->lock, flags).
>> -	 * In this case fast path with __update_cpu_freelist_fast() is not safe.
>>  	 */
>> -	if (!in_nmi() || !local_lock_is_locked(&s->cpu_slab->lock))
>> -		ret = __slab_alloc_node(s, alloc_gfp, node, _RET_IP_, size);
>> +	ret = __slab_alloc_node(s, alloc_gfp, node, _RET_IP_, size);
>>  
>>  	if (PTR_ERR(ret) == -EBUSY) {
> 
> After Patch 10 is applied, the logic that returns `EBUSY` has been
> removed along with the `s->cpu_slab` logic. As a result, it appears that
> `__slab_alloc_node` will no longer return `EBUSY`.

True, I missed that, thanks.
Since we can still get failures due to the cpu_sheaves local lock held, I
think we could just do the single retry with a larger bucket if ret is NULL.
Whlle it may be NULL for other reasons (being genuinely out of memory and
the limited context not allowing reclaim etc), it wouldn't hurt, and it's
better than to introduce returning EBUSY into various paths.

>>  		if (can_retry) {
>> @@ -7250,10 +7166,6 @@ void __kmem_cache_release(struct kmem_cache *s)
>>  {
>>  	cache_random_seq_destroy(s);
>>  	pcs_destroy(s);
>> -#ifdef CONFIG_PREEMPT_RT
>> -	if (s->cpu_slab)
>> -		lockdep_unregister_key(&s->lock_key);
>> -#endif
>>  	free_percpu(s->cpu_slab);
>>  	free_kmem_cache_nodes(s);
>>  }
>> 
>> -- 
>> 2.51.1
>> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4fca7893-60bd-41da-844f-971934de19b6%40suse.cz.
