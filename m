Return-Path: <kasan-dev+bncBDXYDPH3S4OBBG46RHEAMGQEJQVYUSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id BD257C1C71B
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 18:30:05 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-3667d52cb6asf636751fa.2
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 10:30:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761759005; cv=pass;
        d=google.com; s=arc-20240605;
        b=DwMmT6WDhPhOYGNIEqfAaYsZOnX8YFB18ekVkEhPCidEzD7XlOc1+lVW1DgHnpO3M+
         GPIfN9s1n/ThkTutVSRrfuXXLHkgsriQK2NYuLgTKWga6IehHOIBfcqqmULy6+IMYBjZ
         TRJJr74eLeJzpStCTEvzac15n5j/7nR1YbVLZuevYXHEhv9Fde0kRlSjpvgNzmQ1/uuf
         1Ppwa9/TJV2ai7FtQqEI1x/2v/CzIWqO61Vnum0KZeloSPfWFNuGqPJhElCA8PPRnqQ0
         I/tCs64WtludJfZNvdbgxDIr5NpESk0xLL9ZqUscpYC9iQyLfAgqb6WA4KVAVytZKVCi
         7irw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=lubuC0BgJrD67exRlVJloIGXtSR9KgnZ5cjHPixczhk=;
        fh=ny4XQPEIHwswBnHyC2L7yOAabvIKXbffLxcZZRk27BE=;
        b=GgqvqJ7RiVdjsvAzB4q/dP9GuuOx9GivQCJU8GqdfTouh/jJJ/Xn0uj4a6Pvp5pUq4
         3UA2Hv5/DOArQydlZVmY6ASnmn4CoVTfR+TDxRZ2keN83Tjv3myQELUYUVgk+0uEB/oi
         LN6szIZZZIvtWVoajI7nFZWXgMQW7v07egDr0IXucSD97vWmydffTXSSs2EcI5XmYf9Z
         pUhjZeSjCcupIwbL0sI9OLZV7Pj44RfuowUXLu4qSVLrxcSkkhq/+PKOIWXXyNsDTQDH
         YXfM6Xry5t9owbA/Tlah3RUQEVlbIdd3v3E/Hz4Rpy796hfArGkl+/tzNY2sngfpAbxt
         rM1w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=LVEIVOaQ;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=LVEIVOaQ;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=ctF9xyK7;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761759005; x=1762363805; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=lubuC0BgJrD67exRlVJloIGXtSR9KgnZ5cjHPixczhk=;
        b=tR8i/yoR0RkXw6toA8mke1I17PyvLfKPkXv2fjc8GPxoR2if9wIlpSLwbUK4uwnBfX
         /QxraeAmq2pGNIiJC3buwB4zCLWVH6eYOtZQ+u0ytkFVEZbAgg28LgiTu6CwvL+r1RGW
         SX06LRht8sP4LjqIUPCFTvLAkVdP1HYOxMuQ39FGQroVlnBvmYQjEj8Gd59SQW2kbIo9
         m7iSlIL2uEulbcxCy9qV5F2K9OOkFxgwGcoTxdf2iIe17Oken4uQFsOG8fTLqt7TnsLF
         Wt1e1w9ZMJVBlc98f1jpTEDNF8iD0ItBuCpd0UvQBzz2VOLODOg02LwyO1jbSL/PBeca
         KZWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761759005; x=1762363805;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=lubuC0BgJrD67exRlVJloIGXtSR9KgnZ5cjHPixczhk=;
        b=U25AyNE5M1gNJruji/j2/QYKod8n/VDBwBGHfsdu9r8WRwCzmOhc2l5xAIMiGCSC9L
         mNOLMg+KezxpD56hcKEzQ9P9nqbPkimcKPevAKPlNQgq0Uh6GWYspMzAyspx85nBYDQu
         OEWPaz4g6h0z0+bK9JVYf4V6fy/AYlaTe8RyDIePub8eM+yaMxtD6L4H7icsOnjpcUOl
         luktiMR1KpCSTJV8asXU+6b6rWdGI7ABcWzfjAUHz67fCVi4LxoLjFBu2aV47eCuVFD2
         ddXIlSOZOVeo6gbOO2v0Kj7rQrHE4WxKVbDzldpBVsABRcle+P66afsvlkhb5lbwPfuP
         V7Mg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXHbhqCmh1tbwGuLG1qdvJclmz5A1H1qkYhifMcjyY99UE12qWz2lRi68KSLBakcp5JaRjjFg==@lfdr.de
X-Gm-Message-State: AOJu0YzWgTBBZ5gsCcEdinORTMVLgDR0itU42k3kACpYurC0DONQgQyI
	aKTVPU7L3avK2juckuakArgtFPmj+5Tm8FA5Nj213axZ7FJC6EEEFt5F
X-Google-Smtp-Source: AGHT+IHKB0jNVetZC6mPAxhuxCGiD3R7jqfC3/zNDPWwy07Ns+w6mCJk2ncGJVXr4qzTvu83oIHo5g==
X-Received: by 2002:a05:651c:a04a:b0:36c:173:148 with SMTP id 38308e7fff4ca-37a10939665mr729771fa.6.1761759004584;
        Wed, 29 Oct 2025 10:30:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aW9RU+5VZ4Pdi9lvAQ//aD76uwX00QOYJrYadeRcMnHw=="
Received: by 2002:a05:651c:2354:10b0:336:aebe:27fd with SMTP id
 38308e7fff4ca-37a10a63dacls405491fa.2.-pod-prod-09-eu; Wed, 29 Oct 2025
 10:30:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWD885ngAPqQhe3IXaWwNi5ApcTsg1gkZgkLNMi4Qw52OWcEgVEw4ZjwPoFE21V0TPZ4GWMA4zZbss=@googlegroups.com
X-Received: by 2002:a2e:bcc4:0:b0:378:d540:4d57 with SMTP id 38308e7fff4ca-37a10957cb5mr862641fa.20.1761759001490;
        Wed, 29 Oct 2025 10:30:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761759001; cv=none;
        d=google.com; s=arc-20240605;
        b=bKjzwN2/mLpplTWSoUPOl54DjnRGcCxV7FJL8XhnpziX5fF8XzQWlDhlJKid6wzq9l
         sU2xZvEdFIO9DaeyoT4TsIldDusgWsxgS92UyGjejha40wEj9hrG89HhZBNNAUNHYSKs
         NiwPdRRZI22RLKbbhvhj3r9+IrjZ4m1b9gFtzq28WxEKWYd/Zd5fkARMxDy+Tg2TdUVz
         ifKXdlh+DvrX+bAWFKj0Jjj6w2N1YrQSHIYhjFJCfgG1zQ7eUGU1L69oFv6wi/HKPYMu
         9aETxnq9pChAVB/Rz3qzl9hwqmMHu2MgeFSUG8EZ1ZA7bebq30yMHKMwFnoRnZ47QbsH
         E1Cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=oRycsl2hppTtVF2hMtZZwaQ8XfejV47sf0TtOJTd2k4=;
        fh=o5F+zdD+BrF1g389dqaHWhI8yyYLrSzZl2Fw5mCrJ38=;
        b=SNMF2YoPnqW10bIgerQ2tARl9PkDhpCOSkUjrFWj6+OdJxBPhBl1/A6ohqAt2xAHgs
         8pgTNhHUd3GM8Lq1pZbjOHKPUEcRUN9nmUSnNhkmxmJ8yLyK0gQfkcUaN0d26i5l0VlE
         jcAsYw4Sms2+cOR4CsuCJ/0Dwsl4wgyy/E18lDNU3RdtCp61Zp7V07OAGtB9Y4B4UWjR
         AcIhilCkMIdFMfZ5HwJITOTYqabjNX21Q1V293E6ZCBF68T1k3soLjJ3mv7LAxt4cLDy
         T2llNSx1PsK1WFP4jLSP8MPsWFCyw+k1eQkJxdS7lshVcyDftHhHd5sk83dTrFhDS6Ss
         /mkA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=LVEIVOaQ;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=LVEIVOaQ;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=ctF9xyK7;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-378eef14fa4si2831631fa.4.2025.10.29.10.30.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 10:30:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 9C6873410D;
	Wed, 29 Oct 2025 17:30:00 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 7E70C1396A;
	Wed, 29 Oct 2025 17:30:00 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id sfBnHhhPAml+ZwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 29 Oct 2025 17:30:00 +0000
Message-ID: <1e4e6ddd-e4a4-4f3a-ae47-93b69d25ff88@suse.cz>
Date: Wed, 29 Oct 2025 18:30:00 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 07/19] slab: make percpu sheaves compatible with
 kmalloc_nolock()/kfree_nolock()
Content-Language: en-US
To: Chris Mason <clm@meta.com>
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
References: <20251024140416.642903-1-clm@meta.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <20251024140416.642903-1-clm@meta.com>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-0.999];
	MIME_GOOD(-0.10)[text/plain];
	ARC_NA(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[16];
	RCVD_TLS_ALL(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[linux-foundation.org,gentwo.org,google.com,linux.dev,oracle.com,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,suse.cz:email,imap1.dmz-prg2.suse.org:helo]
X-Spam-Flag: NO
X-Spam-Score: -4.30
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=LVEIVOaQ;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=LVEIVOaQ;       dkim=neutral (no key)
 header.i=@suse.cz header.s=susede2_ed25519 header.b=ctF9xyK7;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted
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

On 10/24/25 16:04, Chris Mason wrote:
> On Thu, 23 Oct 2025 15:52:29 +0200 Vlastimil Babka <vbabka@suse.cz> wrote:
> 
>> Before we enable percpu sheaves for kmalloc caches, we need to make sure
>> kmalloc_nolock() and kfree_nolock() will continue working properly and
>> not spin when not allowed to.
>> 
>> Percpu sheaves themselves use local_trylock() so they are already
>> compatible. We just need to be careful with the barn->lock spin_lock.
>> Pass a new allow_spin parameter where necessary to use
>> spin_trylock_irqsave().
>> 
>> In kmalloc_nolock_noprof() we can now attempt alloc_from_pcs() safely,
>> for now it will always fail until we enable sheaves for kmalloc caches
>> next. Similarly in kfree_nolock() we can attempt free_to_pcs().
>>
> 
> Hi Vlastimil,
> 
> We're trying out the AI patch review automation on the BPF commits and it had
> some questions about a few of these.  Since the goal is to actually test the
> automation, I'm putting them in unedited, but I did try and make sure they
> were valid before sending.
> 
> This one is a little verbose for s/NULL/ERR_PTR/ suggestions, but:
> 
>> diff --git a/mm/slub.c b/mm/slub.c
>> index ecb10ed5acfe..5d0b2cf66520 100644
>> --- a/mm/slub.c
>> +++ b/mm/slub.c
> 
> [ ... ]
> 
>> @@ -2990,7 +2998,8 @@ barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empty)
>>   * barn. But if there are too many full sheaves, reject this with -E2BIG.
>>   */
>>  static struct slab_sheaf *
>> -barn_replace_full_sheaf(struct node_barn *barn, struct slab_sheaf *full)
>> +barn_replace_full_sheaf(struct node_barn *barn, struct slab_sheaf *full,
>> +			bool allow_spin)
>>  {
>>  	struct slab_sheaf *empty;
>>  	unsigned long flags;
>> @@ -3001,7 +3010,10 @@ barn_replace_full_sheaf(struct node_barn *barn, struct slab_sheaf *full)
>>  	if (!data_race(barn->nr_empty))
>>  		return ERR_PTR(-ENOMEM);
>>
>> -	spin_lock_irqsave(&barn->lock, flags);
>> +	if (likely(allow_spin))
>> +		spin_lock_irqsave(&barn->lock, flags);
>> +	else if (!spin_trylock_irqsave(&barn->lock, flags))
>> +		return NULL;
> 
> barn_replace_full_sheaf() now returns NULL when the trylock fails, in
> addition to its existing ERR_PTR(-ENOMEM) and ERR_PTR(-E2BIG) returns.

Good catch, cool it can find such bugs.
I'll return ERR_PTR(-EBUSY) which should be compatible with the callers.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1e4e6ddd-e4a4-4f3a-ae47-93b69d25ff88%40suse.cz.
