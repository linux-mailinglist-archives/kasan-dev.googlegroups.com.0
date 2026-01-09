Return-Path: <kasan-dev+bncBDXYDPH3S4OBB2PSQLFQMGQE44LBUTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id ADED3D07BF4
	for <lists+kasan-dev@lfdr.de>; Fri, 09 Jan 2026 09:16:42 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-64b735f514dsf4975751a12.3
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Jan 2026 00:16:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767946602; cv=pass;
        d=google.com; s=arc-20240605;
        b=lgXLB4ddArwFtY4Q85x6MxSaIYK9z+2jX1oglIB3o9mhHH9/SGGCb5FLWQGHjYk3gL
         8aAl3hdPhRVa2GnveWEFP9sGOkl9/DlCRy594KqEAS2tzKDUlyUyMsb9WInw0LLugRi1
         S7UnOkX3y7sznNpDZVFhOk+QcOe0AsRtRqe9yEGHJkCIIx98y6YEn+s/xU1fAbtsLICx
         OlYsfxVNTsOPQ3ANqKPY6CkTxIyHfqIvAVxv8QAvwcggZwssarcaU5RaYjOhZ2IiEl8p
         mhZjsokYKTnrMrE8nLsWeLpEejz4SDry4JAfbehntiDMfJ+VnfzCiNoB35vV0d1MaqjJ
         2qlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=wpYLnjgVp8N6SAnsqN12aMSLhiydQpxZAVujeOOKX9I=;
        fh=0uPAvKLMm8/lX7ZRVPUN/l7YONJDuufMNDJPwRDfTt4=;
        b=UG4AloAtt4+CBhZt3pYT5dU4S2WoP0hXUaIVjDrNwvZQMib5KKUoJpNPQmzPMUwN+M
         fAAi5hSr1kv0s2tCqSSa2RO+kH7TBRVt/vgq6dfgKw6Qq+gXctNCEoxnLPBQnUOtBIAm
         Ltw0jUfnRg6aeVZeE8nGxPHpoKBjonJA4YyOyN+3Dbk7RnFEMtf8ur2xwnVoL0REAd4G
         WNPI8hba+HbFa0/zNUqMcQuF1SKNELXKPWRElf4HrFh2pXUOl0WFGHIBYG0+7bfd73Nq
         6jE0DTULNIH45+CdX6YsI2SESFVe9TFfkLkYec2FH5NUa1/EMXvpM3+1n6PjTyt2WMEW
         9OHg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=FkPvOdy0;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=FkPvOdy0;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767946602; x=1768551402; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wpYLnjgVp8N6SAnsqN12aMSLhiydQpxZAVujeOOKX9I=;
        b=rBmQ4aCjZdNoNdWFBr5A2bpQXYkO7bofffKplo9Y+/CE6iOZRGxhb1XYgTWDs1gJVS
         Amo4o9s+kPpQMuEmLLOe5+1CQhHH/5MaFpEslQAVqu9F3AsdexolbZqR/mQMR2zbLzJd
         f4V5fBt4ICvymYNcRZPfup+JQysSc84URz5BaBoPHLQsejRuqeOFDj7qTb53OoMiVQnX
         t1UWvyBXi/KFSTl5A7Hdmo3dlOs3sD7QMHY4uuKg5IZGRXDq1p4V0WXvDdWzIAuBFbOo
         F52wTy30V7wOjktjQ+fjDWPIHhNdu6I6hyBzlBkybnh1pGPw8x55bk3Yvx9bJvlJRKCd
         bMeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767946602; x=1768551402;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=wpYLnjgVp8N6SAnsqN12aMSLhiydQpxZAVujeOOKX9I=;
        b=kRCftUsWcPwReIDbxgwRqXYA384PEZg610xwZbwuRC1nQFjRIvgtaaThS1jnnw4DBc
         xlGHEpbLEk5XoFrfG+0Vke6+0NZQ650vY75VSWegWIMKaXg7PVYmaxFnq2Pn368Vj1pg
         pJWdjVXviR2XGSVzg+x6uB3KSLlluwXoAULmq7Jzi5dTSN+fOqtkQWJjZx5EB7fITUsa
         mC5u3fmz9GN5AqisgYKvY617+fQxuAiK6auANsWn4Tpja63+IYkNN82Ux8oqyqjkE6j3
         rdDkDtaONKXVmvlFFE+k/Tuc5zjyWRfyvK37ZpsMbkTHoBqXrCZin1xDZg71cM+vDpEK
         TDHg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW6hu/wLFPN7Dyal205L/6Qzc50Xg2j1eDA/KEgDIzxl5ZWdmSk9nGofmn+AxMQ6XMMl1OBpQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz5xiWhOg9UB+4WE1+0S74CmFnfVN5YTB8gQMCqpLRHermXw7ol
	cUNEjajZ0wvBSCrGy4G0YOHkTifGyrLz4vTuH+vPmn7M/fzztJbbyJ4Z
X-Google-Smtp-Source: AGHT+IGlt14gaxcrDtE30eL5pVDQ/qKKBrsHteURJhZxYCcsV8NHMj3SL+ejwGjsIF9yO1LGzDpmFQ==
X-Received: by 2002:a05:6402:5206:b0:640:ebe3:dd55 with SMTP id 4fb4d7f45d1cf-65097dcd89fmr7761529a12.6.1767946601850;
        Fri, 09 Jan 2026 00:16:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbS1wsqjh3FFPlifDu+aUehdBqPIuK7c+YgTmm5tWeTPQ=="
Received: by 2002:a50:fc13:0:b0:64b:643e:9559 with SMTP id 4fb4d7f45d1cf-650748c9c1dls825112a12.1.-pod-prod-07-eu;
 Fri, 09 Jan 2026 00:16:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVd1zH6+mDdqo18B79xekAT7cNAb+vIavPr1sg7srtlcplMf/XP3DA6kqTFch3PLvHCKV3MCT7HDhU=@googlegroups.com
X-Received: by 2002:a05:6402:3494:b0:649:69da:6218 with SMTP id 4fb4d7f45d1cf-65097ce4f19mr8110549a12.0.1767946599182;
        Fri, 09 Jan 2026 00:16:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767946599; cv=none;
        d=google.com; s=arc-20240605;
        b=iEOuBYwB39K+WOT/sasArZza7NI+rVmzyFsMoNLFOVOc1azqkQkxF6g54DWHOZCtQ6
         J80A3WmwYJHOqg38HCSEnlEJ6a7v5W57hC1MJf+NOHStdY2h6+4R/D4g34lJE6xCQRgD
         oeWU0kQ9nP2n4mO71Wkgwpmv4L6HLqRL7FAHw+EFqI6JcidNm6e6qALAYHAb6QBMEk6m
         x01FqeYvVW9lW0iJJ3/D13KKyGS+5MtZLYAF0A0hT6yqjVbvcRtSkTCG5PelOmCb2os7
         +fbnLVenN2mD2EWPOTJU5vSI50KxB79NRw0IERiodf5xnUSr9+d7vOg5huOddpef5kKf
         cQFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=G1ZOpYG1RRBOh0980GoYceIDOSrHq5NcrrJc5uKkl0U=;
        fh=JXcTcagT4qpq4la91joDZG8MPM9MnBisU8vfXW5myog=;
        b=UZptw/xF9GhFgi/VRQVyW0U4udXDUXuW4v1+bf7mjNjypddH63zfwuAZyX5GAPXbQ9
         jOjVNG1mtRNuGbEoYyAeK95Vz/F9GSqeyVQH7H4oloWvBnPt6bxyvaXGJWkqyZZG1Zaw
         GzzVlkoe/3hxhELVqEITT/Vuo3imgtvQzz1K8CBa9Emq+6JeqtBBSVFoG9MomoHrH3Fg
         YLKP0EooiNFybqUHvoTR2LzAonWMunbqil72JMzxZyKGAMWQ0QKu5reFS5CZqLRTLtXT
         Ew8LkjjPmw72bDU974aCkb1x/4tQzj09USSrQYkUwlozMRN1JfT2iFr+wmnVXRWPk/po
         BEVg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=FkPvOdy0;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=FkPvOdy0;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6508d70535dsi193769a12.3.2026.01.09.00.16.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 09 Jan 2026 00:16:39 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 5C7B55D26F;
	Fri,  9 Jan 2026 08:16:38 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 3D9E33EA63;
	Fri,  9 Jan 2026 08:16:38 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id rTO2Dma5YGnkOwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 09 Jan 2026 08:16:38 +0000
Message-ID: <28e6827e-f689-45d9-b2b5-804a8aafad2e@suse.cz>
Date: Fri, 9 Jan 2026 09:16:37 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 10/19] slab: remove cpu (partial) slabs usage from
 allocation paths
Content-Language: en-US
To: Chris Mason <clm@meta.com>, Roman Gushchin <roman.gushchin@linux.dev>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Harry Yoo <harry.yoo@oracle.com>, Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com,
 Petr Tesarik <ptesarik@suse.com>, "Paul E . McKenney" <paulmck@kernel.org>
References: <20251024142927.780367-1-clm@meta.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <20251024142927.780367-1-clm@meta.com>
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
	RCPT_COUNT_TWELVE(0.00)[18];
	RCVD_TLS_ALL(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[linux-foundation.org,gentwo.org,google.com,oracle.com,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.com];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo]
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=FkPvOdy0;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=FkPvOdy0;       dkim=neutral (no key)
 header.i=@suse.cz header.s=susede2_ed25519;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 10/24/25 16:29, Chris Mason wrote:
> On Thu, 23 Oct 2025 15:52:32 +0200 Vlastimil Babka <vbabka@suse.cz> wrote:
> 
>> We now rely on sheaves as the percpu caching layer and can refill them
>> directly from partial or newly allocated slabs. Start removing the cpu
>> (partial) slabs code, first from allocation paths.
>> 
>> This means that any allocation not satisfied from percpu sheaves will
>> end up in ___slab_alloc(), where we remove the usage of cpu (partial)
>> slabs, so it will only perform get_partial() or new_slab().
>> 
>> In get_partial_node() we used to return a slab for freezing as the cpu
>> slab and to refill the partial slab. Now we only want to return a single
>> object and leave the slab on the list (unless it became full). We can't
>> simply reuse alloc_single_from_partial() as that assumes freeing uses
>> free_to_partial_list(). Instead we need to use __slab_update_freelist()
>> to work properly against a racing __slab_free().
>> 
>> The rest of the changes is removing functions that no longer have any
>> callers.
>>
> 
> Hi Vlastimil,
> 
> We're trying out the AI patch review automation on the BPF commits and it had
> some questions about a few of these.  Since the goal is to actually test the
> automation, I'm putting them in unedited, but I did try and make sure they
> were valid before sending.
> 
> This one seems pretty unlikely but still worth fixing:
> 
>>
>> diff --git a/mm/slub.c b/mm/slub.c
>> index e2b052657d11..bd67336e7c1f 100644
>> --- a/mm/slub.c
>> +++ b/mm/slub.c
> 
> [ ... ]
> 
>> @@ -3575,15 +3532,15 @@ static bool get_partial_node_bulk(struct kmem_cache *s,
>>  }
>>
>>  /*
>> - * Try to allocate a partial slab from a specific node.
>> + * Try to allocate object from a partial slab on a specific node.
>>   */
>> -static struct slab *get_partial_node(struct kmem_cache *s,
>> -				     struct kmem_cache_node *n,
>> -				     struct partial_context *pc)
>> +static void *get_partial_node(struct kmem_cache *s,
>> +			      struct kmem_cache_node *n,
>> +			      struct partial_context *pc)
>>  {
>> -	struct slab *slab, *slab2, *partial = NULL;
>> +	struct slab *slab, *slab2;
>>  	unsigned long flags;
>> -	unsigned int partial_slabs = 0;
>> +	void *object;
>>
>>  	/*
>>  	 * Racy check. If we mistakenly see no partial slabs then we
>> @@ -3599,54 +3556,54 @@ static struct slab *get_partial_node(struct kmem_cache *s,
>>  	else if (!spin_trylock_irqsave(&n->list_lock, flags))
>>  		return NULL;
>>  	list_for_each_entry_safe(slab, slab2, &n->partial, slab_list) {
>> +
>> +		unsigned long counters;
>> +		struct slab new;
>> +
>>  		if (!pfmemalloc_match(slab, pc->flags))
>>  			continue;
> 
> Can get_partial_node() return an uninitialized pointer? The variable
> 'object' is declared but never initialized. If all slabs in the partial
> list fail the pfmemalloc_match() check, the loop completes without
> setting 'object', then returns it at the end of the function.
> 
> In the previous version, the equivalent 'partial' variable was explicitly
> initialized to NULL. When all slabs were skipped, NULL was returned.

By the way, there was another bug in this patch, causing a severe memory
leak, which the AI unfortunately didn't flag. Petr reported it during
performance testing and it took me more than a day to find it. Oh well :)

Wonder if things got better since then perhaps, and your or Roman's tools
would find it today? :)

>>
>>  		if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
>> -			void *object = alloc_single_from_partial(s, n, slab,
>> +			object = alloc_single_from_partial(s, n, slab,
>>  							pc->orig_size);
>> -			if (object) {
>> -				partial = slab;
>> -				pc->object = object;
>> +			if (object)
>>  				break;
>> -			}
>>  			continue;
>>  		}
>>
>> -		remove_partial(n, slab);
>> -
>> -		if (!partial) {
>> -			partial = slab;
>> -			stat(s, ALLOC_FROM_PARTIAL);
>> -
>> -			if ((slub_get_cpu_partial(s) == 0)) {
>> -				break;
>> -			}
>> -		} else {
>> -			put_cpu_partial(s, slab, 0);
>> -			stat(s, CPU_PARTIAL_NODE);
>> -
>> -			if (++partial_slabs > slub_get_cpu_partial(s) / 2) {
>> -				break;
>> -			}
>> -		}
>> +		/*
>> +		 * get a single object from the slab. This might race against
>> +		 * __slab_free(), which however has to take the list_lock if
>> +		 * it's about to make the slab fully free.
>> +		 */
>> +		do {
>> +			object = slab->freelist;
>> +			counters = slab->counters;
>> +			new.freelist = get_freepointer(s, object);
>> +			new.counters = counters;
>> +			new.inuse++;
>> +		} while (!__slab_update_freelist(s, slab,
>> +			object, counters,
>> +			new.freelist, new.counters,
>> +			"get_partial_node"));
>> +
>> +		if (!new.freelist)
>> +			remove_partial(n, slab);
>>  	}
>>  	spin_unlock_irqrestore(&n->list_lock, flags);
>> -	return partial;
>> +	return object;
>>  }
> 
> [ ... ]
> 
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/28e6827e-f689-45d9-b2b5-804a8aafad2e%40suse.cz.
