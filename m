Return-Path: <kasan-dev+bncBDXYDPH3S4OBBY7CUPFQMGQE4LBX35A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0805CD24D42
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 14:53:41 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id ffacd0b85a97d-42fd46385c0sf472757f8f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 05:53:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768485220; cv=pass;
        d=google.com; s=arc-20240605;
        b=fjtzMZQmqwuxxGM92TvWVzfQXR2IPq4tNU+gFFB9m7nemjWj5TlXTu7lltwMKYTo4n
         cC0bu76Uaq1wzjt534nMMBvw2+BV+IpwbOHy967HhzjvA8zkv2PLx7B1RR+T18mHJTyS
         PJM0yE4lxWI0ySwv8z95eGaFFMnDqPu/IT5PT4uVrhIPtiaO7IAIatozGs0RW09PlNsV
         CWAZ3JmVjrEe4X5Xecx8LueboxURaPdOI0sonzV5yNbqUl4u/eFbCCxB3tWeXt791Iw5
         isqpVRI8GN517uq+KZtI9irllnYSFFrI4ODBCPmdAkRoKvawLES29RH1PCy5K2z9+F10
         02Qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=tobR8o9Wz/3AHeGoWys2vwDQ5Un7+ILT3VIHzekob7M=;
        fh=ES2kgAJXT9e8HgVnPCBX8jlAfn99NDTClsxe0N6suSk=;
        b=b5DzljKsqfUB997ybJtnQrPAuC8HgAp3j6sFXBB4DZS1j3limZACqKGLIT4wHoab+8
         Ed2hviZeevI9vQuLlZyAqtyBm6jD79l6WJ3sI10fmFCYTX9YgIsG+Xd9abRuHtwa1mOG
         2egwTG78Z7l0cRtGYfkKui95/KT7Qg7gXwAunAr9UUzuhpvZs7Pt58zBrTyiGnm0Psal
         BPytKNSSqWFFmZCSeopuA1pMqMRUs0v76cvBt8A6oqkpyiqtcoy+rU7M2/M/g75/xB0M
         n9J58q73V6z8Ld0iVnVqmq+cxt+ysHIoDxsIfz57PpPdfUJ/X4+V1Z5EQ039ELDaNeIM
         8YFg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=BGvS6CKB;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=BGvS6CKB;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768485220; x=1769090020; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=tobR8o9Wz/3AHeGoWys2vwDQ5Un7+ILT3VIHzekob7M=;
        b=drEne77dL6TK90GCF25Bcj/8Rcf+/QtnEc2I9AXb6VjHYMV0OAv2qTvj+7jhr73IeB
         rvLbm+tvaangISi8kixqn7XpGkEuYsVLUMdaLP+Q6VBxHYBgBNfK+L8gIhwY3/cnrzBn
         +shQTujHloCdqastszDnwHpMctjYIavXKKNO8TpUp3iftbzUmC12sfoA3iJOKbO34d0b
         WvprvdF/2ymC/I9R5rBPYB9FLdmk7O8GBebaAKtQWolhvhuK/hJLi1eUyjny6+XR7jIO
         YzPuac69XSbur7C+HFYqSnRYafBN5rfukHvQ8Ap6bc+5Yi1yECtyMiziIH7stLb3BFKV
         KEEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768485220; x=1769090020;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tobR8o9Wz/3AHeGoWys2vwDQ5Un7+ILT3VIHzekob7M=;
        b=vuPAB2OGI5mN9LoxlesobOqlLzeF+sWQ2Z19Tc0sBcbTrg9z6jUO60ryevyMnw5STy
         sSOmnzX9aKxdiX0blyWrIFZdG02mfrhPsFSpquX3ITXW8/br7yFQHb3gmwd9BMAeoC6C
         3VkcyxLPhEEIGyMkKxvx3WfxKP5lICyeBqNLd0HjS4+dgHSpS+2xJ5qmJSQHF2viHex6
         upC/Z1nluHOXD51OTRHpjzOKM2CYF1BJsBPKd0qMfkm3wCauGWD830QnUOFYl0AECwz+
         F37BOhNp1ag7YsZYVQqCtNcCBp2wJO3UUpNXuSH0f/AUW8fKv37oHUVqHYjlLEhpdWQg
         GP4Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWBgWLhWjxw+X091iENSq00mDJsLKM8MVcJlgDYvljrEeMMwii2v0SHgRqJlUYOJqGgp6T3+Q==@lfdr.de
X-Gm-Message-State: AOJu0Ywv8eyztGCfTMuGBu3fjqgKW0WSTf6jGUYgCFjI3Z2S7KiEo9OL
	u5b20pq2RCW0Qoroh4v3QaqZEPj+I899KSXirt+5tYypwSPAgFXjILEd
X-Received: by 2002:a05:600c:6287:b0:477:79f8:daa8 with SMTP id 5b1f17b1804b1-47ee3391744mr86597345e9.17.1768485219987;
        Thu, 15 Jan 2026 05:53:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FBL6g38rILO6BTnouu6KNcPvTnceAzHFULdVyQsBo5EA=="
Received: by 2002:a05:600c:3110:b0:477:5d33:983b with SMTP id
 5b1f17b1804b1-47f3b7acfb3ls6093035e9.2.-pod-prod-01-eu; Thu, 15 Jan 2026
 05:53:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVSQg6cwoiery8P7W29wb9vWeX1JvggF8YrCEqVdmW+kFrU6JujWJb5NL/ZzsBD8urvjtjCH9TqK4c=@googlegroups.com
X-Received: by 2002:a05:600c:3acb:b0:477:7b9a:bb0a with SMTP id 5b1f17b1804b1-47ee339174fmr65166305e9.21.1768485217581;
        Thu, 15 Jan 2026 05:53:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768485217; cv=none;
        d=google.com; s=arc-20240605;
        b=UA4E32MrYGAKnu3i9dkuTYaDBRY/rrRaO7pwZOAHNcQoY+FHZuOJMuEWYz1d8cqLhS
         gZqdsmrDa6tUgvai/kf0v5cMoZzO94gA7NFtv963V9ZQYuP7KjcXokByDclhJBEWNdYD
         p4Ko4wXm1FBBYwbA9UsyKRAOdYccRzIZy4X0kxZ5DhSf6UeKP97NHyeWyKSJMFDktXWo
         YrkARO1rEEE2uEeqhUTEgjsPA10rIYCkKVgk26NGPIWNnf/s+sk91hvaHzeqtut83aBO
         lVIMdvDCQGMtwNLR5nItnJo/7OqgcxRVwX/Hrc7wouej9UP9V0r4tNipufg9p6TCx4iN
         adMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=T6ReUDa8OO9JhozmVpJl2INs7RyRAxlBOkfOTzlca2k=;
        fh=F0Ugs/KnYVMrxGPEYvOB808vqz5Ww/CfFkiIgtC+gfU=;
        b=E2rFNmFHsZl5dUAL0jyBZRDEVYl+bKag92T0kM/B1AKZuV1V6cXjyksvXTc75mga/0
         I1K6SY0vJIJdXlikVHaO4get0s4sgWTWxnfjvjxD56xeeBUevujoyn7Foqx99Fu97MOZ
         zmyLMEEuVSQj6kcZ5/U4/QZcZ8Xl6qyua8XTCCRjn7GLCIoxlMbqGfYiPnBjeEKuiCFn
         k/8jd3ZXIARD6sqDSahPp3rFZGNVFSo8CcVILPAJ7/mcUpINLJf6Rakg/Ls3Zo8IQB+Q
         3qFbc3hjh0SLxe3n9F7Xopy6mNL2ebgSohUT9ZOx9eey8wXO0703z2TX11WWmJ+z4guH
         qlgw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=BGvS6CKB;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=BGvS6CKB;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47ee2734356si532575e9.2.2026.01.15.05.53.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Jan 2026 05:53:37 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 2D2535BCDE;
	Thu, 15 Jan 2026 13:53:37 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 0D9363EA63;
	Thu, 15 Jan 2026 13:53:37 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id kNb/AmHxaGkrRQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 15 Jan 2026 13:53:37 +0000
Message-ID: <3aa7a303-677d-4ef5-8df1-b3c0fdfcc787@suse.cz>
Date: Thu, 15 Jan 2026 14:53:36 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC v2 09/20] slab: remove cpu (partial) slabs usage from
 allocation paths
Content-Language: en-US
To: Hao Li <hao.li@linux.dev>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-9-98225cfb50cf@suse.cz>
 <3k4wy7gavxczpqn63jt66423fqa3wvdztigvbmejbvcpbr7ld2@fbylldpeuvgi>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <3k4wy7gavxczpqn63jt66423fqa3wvdztigvbmejbvcpbr7ld2@fbylldpeuvgi>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -4.30
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	ARC_NA(0.00)[];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCPT_COUNT_TWELVE(0.00)[17];
	RCVD_TLS_ALL(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FROM_HAS_DN(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid]
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=BGvS6CKB;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=BGvS6CKB;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 1/14/26 07:07, Hao Li wrote:
>> @@ -4836,68 +4558,31 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
>>  	if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
>>  		freelist = alloc_single_from_new_slab(s, slab, orig_size, gfpflags);
>>  
>> -		if (unlikely(!freelist)) {
>> -			/* This could cause an endless loop. Fail instead. */
>> -			if (!allow_spin)
>> -				return NULL;
>> -			goto new_objects;
>> +		if (likely(freelist)) {
>> +			goto success;
>>  		}
>> +	} else {
>> +		alloc_from_new_slab(s, slab, &freelist, 1, allow_spin);
> 
> IIUC, when CONFIG_SLUB_DEBUG is enabled, each successful new_slab() call
> should have a matching inc_slabs_node(), since __kmem_cache_shutdown()
> rely on the accounting done by inc_slabs_node(). Here
> alloc_single_from_new_slab() does call inc_slabs_node(), but
> alloc_from_new_slab() doesn't. Could this mismatch cause any issues?

Great spot, thanks a lot! Yes we should do inc_slabs_node() here.

>>  
>> -		if (s->flags & SLAB_STORE_USER)
>> -			set_track(s, freelist, TRACK_ALLOC, addr,
>> -				  gfpflags & ~(__GFP_DIRECT_RECLAIM));
>> -
>> -		return freelist;
>> -	}
>> -
>> -	/*
>> -	 * No other reference to the slab yet so we can
>> -	 * muck around with it freely without cmpxchg
>> -	 */
>> -	freelist = slab->freelist;
>> -	slab->freelist = NULL;
>> -	slab->inuse = slab->objects;
>> -	slab->frozen = 1;
>> -

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3aa7a303-677d-4ef5-8df1-b3c0fdfcc787%40suse.cz.
