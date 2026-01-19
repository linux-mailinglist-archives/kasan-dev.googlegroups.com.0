Return-Path: <kasan-dev+bncBDXYDPH3S4OBBXU2XDFQMGQEPVFFBKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x639.google.com (mail-ej1-x639.google.com [IPv6:2a00:1450:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FCD2D3A5E9
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 11:54:23 +0100 (CET)
Received: by mail-ej1-x639.google.com with SMTP id a640c23a62f3a-b8768832f9bsf54064066b.3
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 02:54:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768820063; cv=pass;
        d=google.com; s=arc-20240605;
        b=CgeRsPeBIanmxhEVtS7GQ5NPbk/nsRjNMK0+Ph0hSjP0XmPfoDScWhseE8PZwP3KrR
         koVbPKsg9BW8jjAIdENokMlegSOyOJbJRsX+GsX+QDjlqcED9EpGFegqCsNb9sbnulMz
         aMDrpOtEBdWGs/6bNVonHbcxbEwYg0GkiMvfAsP+ohsnZF2M3mughOnWLpGax9Tai7mN
         kWXru9/FrRRKN/j9EaX7IDdR52XQ/7QM1SQ0dUJ6LbUgAfHFerQwjcm5nqQRaUsZJ32i
         Er4zGjrT0iJ/0++F0guB4BnOBb8BpFiqclLfD51zHmxO9/x7uoBWUi6OeoKiSQzI7W00
         Dlqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=Iv8LvVl8HYMUIlM2E5e9Ushaayt/w/s90P3Os9iTDlw=;
        fh=cVpjwhHwHOjC7R887zKpQLWN9B6W84oP1Mhmuy3x2eY=;
        b=Q/wRb7qoL+pX1oxs7ho1KktrmKivnv4gS44VRhz1b8qsbkioiyT/gKhkjZhP3dKgY7
         4RpMDuv9TxjcppwRunEH/aYngB75ZeVCB/GpfVZwHBn5eKTwR2cdybF5uZnq9NbPRbp7
         EfFRZ2P6Sdn5BQlAk65jPwGYSK6k5NFepRM+XQ+YWrUDYNjOehfWNRa1a/OEo0cwQ5Mb
         /NL3ghsYvCm9+U92hew+tCJt6bDAdQFcjV1hezv0wxfd71QnU9AweimOWcIM68zZVzg3
         0nXTw3cA0ki6H6H9/Y5Le6nO5+OtukuYHqvUPftNpu+g1P7G3X4/MTgciyjM8Seqq3aJ
         3gFg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="i+G/wKzO";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="i+G/wKzO";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768820063; x=1769424863; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Iv8LvVl8HYMUIlM2E5e9Ushaayt/w/s90P3Os9iTDlw=;
        b=mho/yRGOs8ivs/U6m6Rg1trGohrEjyi/B2IREiXnY7F9DAnDzcC0QqXQ18XNjSj9o9
         gai7JWu4v6z46z6DIdtefvWmg8eXAfcs91gAJj9AeRB/Oh/lCoNxfpADmHm25wcTD/yM
         0LbemVzI3PYW7SSxmFYBZGZsVjGtMMVW49BwgQhjxxkhfex2BUPYi7GrApMVtxJpWkVx
         aYX1RD5t4Wxp+JJnuRwIzDF+1gdco7QPKCAvH5M2jB0+R3zyLNOPEc0xVaBoMdhMOVGe
         foe7Km2F2SyjjaZD2fR5GKbBB7GxqSc9hBnP902OCQ5BS4D+5j0Lz8uf7WFMdF247WgW
         SucQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768820063; x=1769424863;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Iv8LvVl8HYMUIlM2E5e9Ushaayt/w/s90P3Os9iTDlw=;
        b=s7cIm+NweWG18lg8wBwL1bczmfJy7l923qI0GJM0BYKISUcir7tLq3SXbNhKi3+esu
         upHpxmQOmoms1/zkVr+hroZmXf06iE9BBh69Q4PK+bqYaabJnU+N1pnThUFNaztiaq4U
         F68ZkUgJs1OZav6QpZrI29AZ7zRI+MS2IkQXW49vSEJMSnqSi69XM5pVC3PtsjO6hRuv
         v6tY+6OnNLi/hbmYBGJ/UCPd8s68SRTqwVxcK/czzWoplw4RhRvFHcEF8XSl39FSsIhO
         SkB432FooevHoq2zpVU+DwZm0UVGefTtEXiYC9lMks3f5icAEYW4Ryuo83HlOrc8zXDb
         cLtA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWOYL5mEtpayiLyIVe72RoI5scK2jd+n6cMONQydAjk3zQpRK4MxIj5jxjiWKHFGSV79/DWHg==@lfdr.de
X-Gm-Message-State: AOJu0YyOGi4ZJZry79j665jIKxmMOR6VJAhYaN1n6PFOWLoEORb3AJev
	jb+A0vcCoF8263U/Heiy+grsdd+2YbbpffCKbT4NURLQcs+lFBLaAMq0
X-Received: by 2002:a05:6402:27c8:b0:64b:4e7a:bbc8 with SMTP id 4fb4d7f45d1cf-65452cca932mr5127484a12.5.1768820062672;
        Mon, 19 Jan 2026 02:54:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+E3AVRwT5hzZ2JaboJMZgrR8qJrdFK8p7idYn5jxtJi4Q=="
Received: by 2002:a05:6402:3246:10b0:64b:a683:5c87 with SMTP id
 4fb4d7f45d1cf-6541c6d7b17ls4158289a12.1.-pod-prod-04-eu; Mon, 19 Jan 2026
 02:54:20 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXWKX/LcDj0Zj4cQlh+lqYHhwYsQM+WJrGqENeftkGSWeBAP1Q4E6sjRszSPzfPVtv7jqGe5LSbcG0=@googlegroups.com
X-Received: by 2002:a05:6402:2116:b0:640:c460:8a90 with SMTP id 4fb4d7f45d1cf-654b955cfcfmr8569293a12.12.1768820060191;
        Mon, 19 Jan 2026 02:54:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768820060; cv=none;
        d=google.com; s=arc-20240605;
        b=FDHZaFA78lTUfKYc2+0eBVTLn8OQzd5uwlpjc3voufPEFWxmMl1dIBid3nBh15bV/n
         RfpYuK32mr2C+T2iakCs3uA0wTnMrOBwGuMbXOsXErZ5SzPXWg/h9vn1KFJmr7Xselod
         TmMr2RoXC/xv6eHutmf9rHGbMQeiMQM9r/CLihHTz99UGZqXUFIFdNAwKNIUwlsznz1m
         GdmPI/G0bJrpMkDCMeFH4LC72alP4ncu/aqWWSU5GHK3g+SphKcI325yUYBpLWxn8upB
         lHW7mmEDuQxdyChV9TmMcDwPxV3ONNsIjKAGLGTvFjqmouMTLTcGC+XmiSFejjydtG7X
         P7Wg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=ey0pNkWH40RKae/z7UghicYKnJcQmjtLJWpIQMJLIMw=;
        fh=KDJM2J+CluSNuZFMRpSGdSzTe0G9RbhFzt5xcVD9hkE=;
        b=EtJif3u671jVVlTfG5+jg0/j8ojPsJXsItJWkLai4jAvAYeAFDCU1DaxEtioRmMSWA
         eaMOQ/QvNBJQ8S6TUMAj6IGkQJzuLxchgRNC9HztQPtWtnLlcdyBM83CpiUr1jHp8bLK
         9iwmjwrqBjgxY2ghgkHNlfJyg5ecXv+RbXgh8eJWqVnLp6hlo9I9IwFY9CVK/O3KYpou
         P2Iftzm5buOoPsDPvCF8djG95mhE3eA7JWKOCkKjPlTkSFqifYqelrEfyiWDF0D8WweW
         vMJ0LvhMiNIlMJDk7eeA7YL62X26LbYAVWGb70Tmxa41vM7FjDW0j4Zi2MSIOlAIbZSh
         wjhw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="i+G/wKzO";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="i+G/wKzO";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-654532cebc4si242759a12.5.2026.01.19.02.54.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Jan 2026 02:54:20 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 136C55BD6E;
	Mon, 19 Jan 2026 10:54:19 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id DB6473EA63;
	Mon, 19 Jan 2026 10:54:18 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 1ZyyM1oNbmkGKQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 19 Jan 2026 10:54:18 +0000
Message-ID: <e106a4d5-32f7-4314-b8c1-19ebc6da6d7a@suse.cz>
Date: Mon, 19 Jan 2026 11:54:18 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 09/21] slab: add optimized sheaf refill from partial
 list
Content-Language: en-US
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
 <20260116-sheaves-for-all-v3-9-5595cb000772@suse.cz>
 <aW3SJBR1BcDor-ya@hyeyoo>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <aW3SJBR1BcDor-ya@hyeyoo>
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,suse.cz:email,imap1.dmz-prg2.suse.org:helo]
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="i+G/wKzO";
       dkim=neutral (no key) header.i=@suse.cz;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="i+G/wKzO";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 1/19/26 07:41, Harry Yoo wrote:
> On Fri, Jan 16, 2026 at 03:40:29PM +0100, Vlastimil Babka wrote:
>> At this point we have sheaves enabled for all caches, but their refill
>> is done via __kmem_cache_alloc_bulk() which relies on cpu (partial)
>> slabs - now a redundant caching layer that we are about to remove.
>> 
>> The refill will thus be done from slabs on the node partial list.
>> Introduce new functions that can do that in an optimized way as it's
>> easier than modifying the __kmem_cache_alloc_bulk() call chain.
>> 
>> Extend struct partial_context so it can return a list of slabs from the
>> partial list with the sum of free objects in them within the requested
>> min and max.
>> 
>> Introduce get_partial_node_bulk() that removes the slabs from freelist
>> and returns them in the list.
>> 
>> Introduce get_freelist_nofreeze() which grabs the freelist without
>> freezing the slab.
>> 
>> Introduce alloc_from_new_slab() which can allocate multiple objects from
>> a newly allocated slab where we don't need to synchronize with freeing.
>> In some aspects it's similar to alloc_single_from_new_slab() but assumes
>> the cache is a non-debug one so it can avoid some actions.
>> 
>> Introduce __refill_objects() that uses the functions above to fill an
>> array of objects. It has to handle the possibility that the slabs will
>> contain more objects that were requested, due to concurrent freeing of
>> objects to those slabs. When no more slabs on partial lists are
>> available, it will allocate new slabs. It is intended to be only used
>> in context where spinning is allowed, so add a WARN_ON_ONCE check there.
>> 
>> Finally, switch refill_sheaf() to use __refill_objects(). Sheaves are
>> only refilled from contexts that allow spinning, or even blocking.
>> 
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> ---
>>  mm/slub.c | 284 +++++++++++++++++++++++++++++++++++++++++++++++++++++++++-----
>>  1 file changed, 264 insertions(+), 20 deletions(-)
>> 
>> diff --git a/mm/slub.c b/mm/slub.c
>> index 9bea8a65e510..dce80463f92c 100644
>> --- a/mm/slub.c
>> +++ b/mm/slub.c
>> @@ -3522,6 +3525,63 @@ static inline void put_cpu_partial(struct kmem_cache *s, struct slab *slab,
>>  #endif
>>  static inline bool pfmemalloc_match(struct slab *slab, gfp_t gfpflags);
>>  
>> +static bool get_partial_node_bulk(struct kmem_cache *s,
>> +				  struct kmem_cache_node *n,
>> +				  struct partial_context *pc)
>> +{
>> +	struct slab *slab, *slab2;
>> +	unsigned int total_free = 0;
>> +	unsigned long flags;
>> +
>> +	/* Racy check to avoid taking the lock unnecessarily. */
>> +	if (!n || data_race(!n->nr_partial))
>> +		return false;
>> +
>> +	INIT_LIST_HEAD(&pc->slabs);
>> +
>> +	spin_lock_irqsave(&n->list_lock, flags);
>> +
>> +	list_for_each_entry_safe(slab, slab2, &n->partial, slab_list) {
>> +		struct freelist_counters flc;
>> +		unsigned int slab_free;
>> +
>> +		if (!pfmemalloc_match(slab, pc->flags))
>> +			continue;
>> +		/*
>> +		 * determine the number of free objects in the slab racily
>> +		 *
>> +		 * due to atomic updates done by a racing free we should not
>> +		 * read an inconsistent value here, but do a sanity check anyway
>> +		 *
>> +		 * slab_free is a lower bound due to subsequent concurrent
>> +		 * freeing, the caller might get more objects than requested and
>> +		 * must deal with it
>> +		 */
>> +		flc.counters = data_race(READ_ONCE(slab->counters));
>> +		slab_free = flc.objects - flc.inuse;
>> +
>> +		if (unlikely(slab_free > oo_objects(s->oo)))
>> +			continue;
> 
> When is this condition supposed to be true?
> 
> I guess it's when __update_freelist_slow() doesn't update
> slab->counters atomically?

Yeah. Probably could be solvable with WRITE_ONCE() there, as this is only
about hypothetical read/write tearing, not seeing stale values. Or not? Just
wanted to be careful.

>> +
>> +		/* we have already min and this would get us over the max */
>> +		if (total_free >= pc->min_objects
>> +		    && total_free + slab_free > pc->max_objects)
>> +			break;
>> +
>> +		remove_partial(n, slab);
>> +
>> +		list_add(&slab->slab_list, &pc->slabs);
>> +
>> +		total_free += slab_free;
>> +		if (total_free >= pc->max_objects)
>> +			break;
>> +	}
>> +
>> +	spin_unlock_irqrestore(&n->list_lock, flags);
>> +	return total_free > 0;
>> +}
>> +
>>  /*
>>   * Try to allocate a partial slab from a specific node.
>>   */
>> +static unsigned int alloc_from_new_slab(struct kmem_cache *s, struct slab *slab,
>> +		void **p, unsigned int count, bool allow_spin)
>> +{
>> +	unsigned int allocated = 0;
>> +	struct kmem_cache_node *n;
>> +	unsigned long flags;
>> +	void *object;
>> +
>> +	if (!allow_spin && (slab->objects - slab->inuse) > count) {
>> +
>> +		n = get_node(s, slab_nid(slab));
>> +
>> +		if (!spin_trylock_irqsave(&n->list_lock, flags)) {
>> +			/* Unlucky, discard newly allocated slab */
>> +			defer_deactivate_slab(slab, NULL);
>> +			return 0;
>> +		}
>> +	}
>> +
>> +	object = slab->freelist;
>> +	while (object && allocated < count) {
>> +		p[allocated] = object;
>> +		object = get_freepointer(s, object);
>> +		maybe_wipe_obj_freeptr(s, p[allocated]);
>> +
>> +		slab->inuse++;
>> +		allocated++;
>> +	}
>> +	slab->freelist = object;
>> +
>> +	if (slab->freelist) {
>> +
>> +		if (allow_spin) {
>> +			n = get_node(s, slab_nid(slab));
>> +			spin_lock_irqsave(&n->list_lock, flags);
>> +		}
>> +		add_partial(n, slab, DEACTIVATE_TO_HEAD);
>> +		spin_unlock_irqrestore(&n->list_lock, flags);
>> +	}
>> +
>> +	inc_slabs_node(s, slab_nid(slab), slab->objects);
> 
> Maybe add a comment explaining why inc_slabs_node() doesn't need to be
> called under n->list_lock?

Hm, we might not even be holding it. The old code also did the inc with no
comment. If anything could use one, it would be in
alloc_single_from_new_slab()? But that's outside the scope here.

>> +	return allocated;
>> +}
>> +
>>  /*
>>   * Slow path. The lockless freelist is empty or we need to perform
>>   * debugging duties.

>> +new_slab:
>> +
>> +	slab = new_slab(s, pc.flags, node);
>> +	if (!slab)
>> +		goto out;
>> +
>> +	stat(s, ALLOC_SLAB);
>> +
>> +	/*
>> +	 * TODO: possible optimization - if we know we will consume the whole
>> +	 * slab we might skip creating the freelist?
>> +	 */
>> +	refilled += alloc_from_new_slab(s, slab, p + refilled, max - refilled,
>> +					/* allow_spin = */ true);
>> +
>> +	if (refilled < min)
>> +		goto new_slab;
> 
> It should jump to out: label when alloc_from_new_slab() returns zero
> (trylock failed).
> 
> ...Oh wait, no. I was confused.
> 
> Why does alloc_from_new_slab() handle !allow_spin case when it cannot be
> called if allow_spin is false?

The next patch will use it so it seemed easier to add it already. I'll note
in the commit log.

>> +out:
>> +
>> +	return refilled;
>> +}
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e106a4d5-32f7-4314-b8c1-19ebc6da6d7a%40suse.cz.
