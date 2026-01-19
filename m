Return-Path: <kasan-dev+bncBDXYDPH3S4OBBZEFXDFQMGQEYPEUBDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id B35A7D3A448
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 11:09:41 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-4801ad6e51csf33755745e9.2
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 02:09:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768817381; cv=pass;
        d=google.com; s=arc-20240605;
        b=SYCE4RsRdq16OU2kyIh8YVAE8aL1NPba+fH1dSEkkq0CGLy6wIHQ9mddv7YJ+hT4iL
         suMqjVSvW/MrhDOQM+26REX2cqs+yskZCzuN5dDWvefM7A98dHFtQgv/+P3MrMhRB3ZF
         76BikfoO34QDkD8Mcn9DJYHdztkXGTrY56RJs8kcjA2uzugDRyWU3Q6k84ggeWR6EtGL
         O8siXwZSBf9WwRyM8+NoSf8qODFy9O8X/LWKoEwUHs3uSQ9p9IgYKwMas3UqUdz2XCaJ
         I7DYCnf/Pcca5px/RDlriQ/hKb40GJYZiPcwrc4I3XtWRZY/MVv//Bi/69wLGN2TlvTd
         RCzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=1VMhqGjkRy8bFOSIjbdcQcKdYbePbqJUwCZLiqIzawo=;
        fh=ARsXSrTg/fEwtbTOZIgFwQtR16PRY4O7OegZp61YSGk=;
        b=WE0VN+tON/V9rwsFceYVOwxmWyr3kRKAc1nJjWhb0OCsuFy1MmQ8pKhU4WAZ3oaXx3
         kLJyV7hJ88JhGAsHIHqvDsd5uSLEgejnTBl4Hs6OIeyS8FehmtXJlz5dB+AHwvnUuVfy
         ANgPZ5bWfWSPsTSgsKqIamGZbwq8vp+tfjG3Y+ipo1H/hvBVXaSuE9++a3uYDDoCKKaR
         JSMvjWwBXqO6qXy+hbsXNoXm5CVTNviSwBioCaOoKwwWaJiWtyiOG33/K1JY4YQJ2QvN
         xC1DvGLooQpCHxwV6ssmnETbBS3tvgjbjK+uvcfFbmoL0qxGKs2QKKDgJsqQUdw/J2k0
         SCcg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ScKxdrxs;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ScKxdrxs;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768817381; x=1769422181; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1VMhqGjkRy8bFOSIjbdcQcKdYbePbqJUwCZLiqIzawo=;
        b=JkcAkR4cZDA3NwtgdIoVCnjwwONQlmstRkfoluSzKfd+DYVRfVjo39KFtl8L6u+Y+H
         iaRuRwQwkbUgaBHsHSnE+hwJcdqei94KO4SLH0+leh584ih2RHziVeXxfkCJcGh0z0Rl
         OqGf/Ie0YYFKW0QNo7vdl8tO4FQ6M9tkd9NyBqDr/jAua6BHzXyUztiw9vAxNeobtxgH
         jsdxlmv3H90fAr/Qu5KtXyMpxnPOqk2J0I/NNHb7j6SgyPZcCKLr/gE/LrLdzwJKQ6h6
         zbLZ6JNwmpIEQfhh00Lg9D+WLZ+CYkx6GuVvGsrAatN9VN1ai4QuvPCKSdzSRCELLivO
         nR4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768817381; x=1769422181;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1VMhqGjkRy8bFOSIjbdcQcKdYbePbqJUwCZLiqIzawo=;
        b=a66THB4a4It/UQbOWAydYAAW4WD3XItEBNlrA38kTy2O55KdivNQEQnSVpDBVtxxT8
         P6faePiyL+U01zGAmwKSBsV94fBL//db8H/5nPeENAtmdKl3bpJgCHoyvHLVPKlEg6UH
         83TmpYbiSPxd9zZ46cUONHS33nke1ksRgDapXGRmPsBLs0J6Fv9jrU0KrkEfHSPTBUv5
         ElCfqoQ3y6aHPtG38kF8n7csAm0GVGBl/IVfM5AjeSaWHU1RA7eLb5VpyKIK6CQ5xZHO
         6bKR4MsEtpYT55svVFaozv5HUNKzHlhZRToAIg5YO1hCISBmi0kDpZrc/NhK7Klx0Cw6
         dLpg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUO9aAQja2Jn4ATtGX3pZ7hzSR3ug8x5uQt4YoLahRm1eRmAWlLNuFqkMX3+wVr/jVGnRaJWg==@lfdr.de
X-Gm-Message-State: AOJu0YzZtKuJvFJVCscCMgAV/oZHkiayXdTeAaX/eVmHYBcyA2/V77J2
	odxIVuxqlgi78Z7jGmnAg04v6eJplRFNeWvbUzcgNI317/ecois5OJbj
X-Received: by 2002:a05:600d:644f:10b0:47b:da85:b9ef with SMTP id 5b1f17b1804b1-4801e2fef40mr112804115e9.16.1768817381025;
        Mon, 19 Jan 2026 02:09:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HP7wutNJosXwGI4Cla9fNQWpblfMcqFF8rzjw9jGJFzA=="
Received: by 2002:a05:600c:3510:b0:47a:74d9:db with SMTP id
 5b1f17b1804b1-47fb730a4a5ls23950365e9.1.-pod-prod-02-eu; Mon, 19 Jan 2026
 02:09:38 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXodiLv2wMPAn+bSySAlC7CedQh1l5cp9HfbJS9uXvcYVwWDQ1CEFWPte9xQpznLOkiUcNyh4SJpDE=@googlegroups.com
X-Received: by 2002:a05:600c:458c:b0:47d:6856:9bd9 with SMTP id 5b1f17b1804b1-4801e3342bamr97623485e9.23.1768817378394;
        Mon, 19 Jan 2026 02:09:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768817378; cv=none;
        d=google.com; s=arc-20240605;
        b=Ymwv+fsO8Nr4JtNvPStENHbwr6o2r0FTpbydmpANJFHSQ47+8p9fJICX7dgjp2k/Pq
         U/XpQsDnvjGqZf2DwZFlujTqLDzPXb8Kj2JP+KPBC1ZsP5JYdc3whOAdzokKvETycUO0
         kGv6PR5UQ5xN+lkiNNPojlKWBunZnc/3zUwtRsWdD6MP45UixBNRAwCQGZgek8IKgyK8
         OqQBJI/+YP1+Txves0NnCbS3fBLuZQEjBXCLwmMruZrZpczddW4Uo2pdOGFbwFvXJZrW
         N8aAPNrJ9IYrr3uWC2ertn6N0+1866uYbA2kfZH7kbEoNnHhajt7UT6DgJSxdITNnMQX
         jEtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=RR3eb3DfGsCtOFcgHqGdbhM1TC4Knm+6+G2KfNqmCNA=;
        fh=KDJM2J+CluSNuZFMRpSGdSzTe0G9RbhFzt5xcVD9hkE=;
        b=HS6oj9xGWHCd2p7BpZtxThd3vjnV0uGNSKEfBOJPMpU1qco4tieTlr2F41oOjcH6v7
         SyKtFnuHJ9A76EqYwB2hpslREh51MYJdddcwhMTEbVPmBDohqMuVi7jqeLSuo72BEi9c
         HoLBKt4UTv/eLNM138aAuDxJ+dHyhyYjElRjODgd2bWcjHqBYqemj0nkx0ycz2NmhhCl
         izQuyYRdSVLwGEUQfw/bbaOY1DXsf6rtnr1kS7cSTuq739MGkTBF0es4LaTytdQ3Xv7z
         xhQccpSfNsCk+2IwUg/CzU515791TSQBe2FE9Pi/envqcZbmYcqbRZCvVWlQsoHlAqN1
         lKiw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ScKxdrxs;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ScKxdrxs;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-480272cba44si606405e9.1.2026.01.19.02.09.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Jan 2026 02:09:38 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id BAD5C33717;
	Mon, 19 Jan 2026 10:09:37 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 8A61F3EA63;
	Mon, 19 Jan 2026 10:09:37 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id juptIeECbmnrewAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 19 Jan 2026 10:09:37 +0000
Message-ID: <e4831aab-40e6-48ec-a4b9-1967bd0d6a4c@suse.cz>
Date: Mon, 19 Jan 2026 11:09:37 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 07/21] slab: make percpu sheaves compatible with
 kmalloc_nolock()/kfree_nolock()
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
 <20260116-sheaves-for-all-v3-7-5595cb000772@suse.cz>
 <aW2zmf4dXL5C_Iu2@hyeyoo>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <aW2zmf4dXL5C_Iu2@hyeyoo>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [-4.51 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	ARC_NA(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	MIME_TRACE(0.00)[0:+];
	SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FREEMAIL_CC(0.00)[suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	DNSWL_BLOCKED(0.00)[2a07:de40:b281:104:10:150:64:97:from,2a07:de40:b281:106:10:150:64:167:received];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	MID_RHS_MATCH_FROM(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,imap1.dmz-prg2.suse.org:rdns,suse.cz:mid,suse.cz:dkim,suse.cz:email]
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Rspamd-Queue-Id: BAD5C33717
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=ScKxdrxs;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=ScKxdrxs;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 1/19/26 05:31, Harry Yoo wrote:
> On Fri, Jan 16, 2026 at 03:40:27PM +0100, Vlastimil Babka wrote:
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
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> ---
> 
> Looks good to me,
> Reviewed-by: Harry Yoo <harry.yoo@oracle.com>

Thanks.

> 
> with a nit below.
> 
>>  mm/slub.c | 79 ++++++++++++++++++++++++++++++++++++++++++++-------------------
>>  1 file changed, 56 insertions(+), 23 deletions(-)
>> 
>> diff --git a/mm/slub.c b/mm/slub.c
>> index 706cb6398f05..b385247c219f 100644
>> --- a/mm/slub.c
>> +++ b/mm/slub.c
>> @@ -6703,7 +6735,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
>>  
>>  	if (likely(!IS_ENABLED(CONFIG_NUMA) || slab_nid(slab) == numa_mem_id())
>>  	    && likely(!slab_test_pfmemalloc(slab))) {
>> -		if (likely(free_to_pcs(s, object)))
>> +		if (likely(free_to_pcs(s, object, true)))
>>  			return;
>>  	}
>>  
>> @@ -6964,7 +6996,8 @@ void kfree_nolock(const void *object)
>>  	 * since kasan quarantine takes locks and not supported from NMI.
>>  	 */
>>  	kasan_slab_free(s, x, false, false, /* skip quarantine */true);
>> -	do_slab_free(s, slab, x, x, 0, _RET_IP_);
>> +	if (!free_to_pcs(s, x, false))
>> +		do_slab_free(s, slab, x, x, 0, _RET_IP_);
>>  }
> 
> nit: Maybe it's not that common but should we bypass sheaves if
> it's from remote NUMA node just like slab_free()?

Right, will do.

>>  EXPORT_SYMBOL_GPL(kfree_nolock);
>>  
>> @@ -7516,7 +7549,7 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
>>  		size--;
>>  	}
>>  
>> -	i = alloc_from_pcs_bulk(s, size, p);
>> +	i = alloc_from_pcs_bulk(s, flags, size, p);
>>  
>>  	if (i < size) { >  		/*
>> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e4831aab-40e6-48ec-a4b9-1967bd0d6a4c%40suse.cz.
