Return-Path: <kasan-dev+bncBDXYDPH3S4OBBGGYRDEAMGQE2MNLPOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A37DC1B80B
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 16:00:42 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-475c422fd70sf57467345e9.2
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 08:00:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761750041; cv=pass;
        d=google.com; s=arc-20240605;
        b=etaqcgVsWtjD30m+iZXZPPaRdU1tsuPuow+NYmUSLKx+glaCljD3zDaR4nyamI0XFj
         hrsORZYAeBAOwCa/iiFA9KXJIrno4ADtACjvbYDK32nTChbAscvHbWKcEaZi209Jl6r6
         o/KqV1HQLRjvH9ZpQnw1wDUz+TuHiwQ20lW8vNyVvCx3f8niCxt744TxX+V7on0Z0AoN
         wmJIqaCDFvtQuywIeH61wWtZpDCXtJdNNctE6LkdNwj5c8/2/YDWWwTkeK+/Ng3DTf8u
         gOagKxjvacVP0R0PJcyJgf+1VTsS+97tDx/9C0rW8ODFxQFXeWwDMji4WkP7uHwvpp9D
         P0Jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=iuD7SnXHonORzzfzfLjhY0/JIprMUzQUOCzESwxbdQ8=;
        fh=vKlrfULXpy6j7ruex/qABG2WMtbAa6oynMjp9BYuKDY=;
        b=cPP0JnAVzseCE9h6yv3Kir5VotRuwWmYtDUHC1cIISa0b0yF0xjqeQtousiRImOnz0
         Q6AZPvay5c6g4iYSfW+MgFdIjl8utWSonzeq9I/dDOHObd3M2Gitv6PODJDmkeKNTBwr
         2Td+MlXJrMfdhOJwzDczGtfKrW9JjBJH/QQhyRnpqpnvN+WOC9oalgV2OwE6eGNOWhEK
         HfZUk+xNuE0AGMHHBFZawTegKuz1YqqQoTjPJwCcNUH5fS9oCAllh/2tVpVUsQudKkOf
         m+GG8rdm6CF0hFlx4mQP5w8ir1FGdtif3d//M2kycSKupJ7jO0mAeJHEYnRw78Gh5Tdu
         XaNA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="yBeuD/9Y";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="yBeuD/9Y";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761750041; x=1762354841; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=iuD7SnXHonORzzfzfLjhY0/JIprMUzQUOCzESwxbdQ8=;
        b=AkHGjU1ksYFiEd9i4S5jhjyKtTgnXK/yIG466un3vX+C3TCet1t2RR02d5rQtkMAIA
         Wc8ZM0Pk7Pl3FJ84NYLqc+82WGrsL232jI1o/r77OHG0h7BRdy4+fsd90y+tPX4nKyzY
         N7ZvbpN7abzYsw+v5NKwEahA5Mrh3R77gldEJJV3mpeocNifSnSXar74lyKrsXj5U2fd
         7H6qhDF//44ytD13ql2UoAT4bsSKLwOhMzLdbEBA6Ymw6cxFkk4os7Nnh4eo3V0iKTji
         ljS7X8Kq/OUo2ysDXMSizoqMgb2VSadlBcK+NsRJau6FZR/vOh5PZmoHjIMMCGP5Opfb
         Q2zA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761750041; x=1762354841;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=iuD7SnXHonORzzfzfLjhY0/JIprMUzQUOCzESwxbdQ8=;
        b=HCCVEoiFOzGGnc1Y1agcccY49zWAp/FUPk93ciE6iEAUXvGGbZuU77NzJwIID67alI
         g1JhY94Y3DJCt9XobAqKmsC/gerbXglCOVhUE4B1tkmYwvC9tGfmMQ49++Vxmz2EceXO
         NQ64zaenpq3pguyXrtuKw6uyfBRBXPFYu44qHLX9hM29AWIea9gzJYfB5hJo9Vqd34bz
         xBZEVEKsNboM8An1iISzl2aVdWl7kSBKfwadrcKOpZD0LxnntPV3bbKf3IThbOnxad0h
         AZAbaEZi9Ey0/OK0W2jjhDJJhf6R1y66W3K6URbYYquYl+SsMJFSQMpfocMmfnWyUwI4
         ZbQw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWgXIfplSMExw7g6cZvm6ihOOugV3xygd0289PCec0ySynDVjlQL6PnHe2hwTFn7ooevLqZtA==@lfdr.de
X-Gm-Message-State: AOJu0Yw72bSRiQ7c7y0Qi+S9Rem1eDlnonUvL8Y9AXsW2J7iNkDqxFmp
	V+SZCQDgfgn/K/3fTluZ11NFQ4xexM5ykC9N0TPXo3pHiQ/PW1QTqKX6
X-Google-Smtp-Source: AGHT+IGrdZ06q4XhH3oqxPe2sz9QW9Zou7hM+Ys4q+GjsJVxVFdjTJD2KJ7RaH5oLVtofh7jDsbE9Q==
X-Received: by 2002:a05:600c:530e:b0:45d:d8d6:7fcc with SMTP id 5b1f17b1804b1-4771e1dcc81mr29785065e9.27.1761750040999;
        Wed, 29 Oct 2025 08:00:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZjPky4E49HezvIUo/q20ZATRaHhmm6mpnQ2ubUg6XUhQ=="
Received: by 2002:a7b:cb58:0:b0:475:d8e6:dea7 with SMTP id 5b1f17b1804b1-475d8e6e100ls27907985e9.1.-pod-prod-09-eu;
 Wed, 29 Oct 2025 08:00:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUdq+rN7LIeWCKqzwYPwPxsQ5ULmzTbt30g9Mxw+9UpVaeIRnt46Hf9T26YrAHRyZ+Rxb2YN1mMtpk=@googlegroups.com
X-Received: by 2002:a05:600d:8306:b0:477:25b9:3917 with SMTP id 5b1f17b1804b1-47725b93aa2mr1776995e9.39.1761750037985;
        Wed, 29 Oct 2025 08:00:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761750037; cv=none;
        d=google.com; s=arc-20240605;
        b=AU6HqpQL9C7J/CIuZfHdSvFMudfaG9bPFqzUfPmGlj6ONtKPUzanLnjiVuQ/yd1s6I
         ycSHkFLzTbteYefns+vc1LGuH4mUpr6VqFnP8iYU+B9Xcq8KhP1p3BGFtWESfbbeFaYH
         29tXre9OlamFfdOlhA4X0sbCVFLodmMygpwwou716AlFC56MZYGCQ/pPCevZ6kgsi1gR
         aW7DnQjf3f3uy5xbs57A7FLr3wYxj0fG6vdou5bfyDdHztNvsSveZQoPlgv1FJhSZU8V
         ocDeay2go8z6FJ7QCFRAn9cO8DYPO/7VWPhFAIuqLbWjuNzv4PGInUerMQmrdfM72jSE
         Dckw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=/UPS7wTW//mEiHwtYoijDeEHmtxYAPJacr3wZrmWnhE=;
        fh=o5F+zdD+BrF1g389dqaHWhI8yyYLrSzZl2Fw5mCrJ38=;
        b=T8gVBz42w6wBePQkvUEzthhq+KszA2YMrBDRO2vRV9dElmvJIJWfhr1daMaSz2n2cF
         5GnJtcPo8WWGXhcwXVesX4pKTqYl2/rKrMBCAkSwPj1jLuJwk80Va53HH6lZuYh2Nhn5
         uhZZ2IFR73efDAgCIK+o/fEL7nluVfMR8E5zhn9aCQL4C2EMSnKVaGF3i6z3LZ4zdk2p
         ahYAv7e/ZNTvrQKvq0yDA4ybzPrvT9cBtRRyv4mX9bLzrOC9wxfjUkwa2W8qcORbnXjl
         FjXmFbhgOgpj0DTiRXnjYhwbV2tZSPCYZcy000CXlMFqb9JSJkXEcTjZoSd7HiO14Hp7
         ASlg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="yBeuD/9Y";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="yBeuD/9Y";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4771e1a4bc3si222805e9.2.2025.10.29.08.00.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 08:00:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 4A0E920DA0;
	Wed, 29 Oct 2025 15:00:37 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 2BAAC1349D;
	Wed, 29 Oct 2025 15:00:37 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id JPhEChUsAmlgVAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 29 Oct 2025 15:00:37 +0000
Message-ID: <51cfb267-f4f4-42b2-b0ea-d29d62bb1151@suse.cz>
Date: Wed, 29 Oct 2025 16:00:36 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 02/19] slab: handle pfmemalloc slabs properly with
 sheaves
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
References: <20251024142137.739555-1-clm@meta.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <20251024142137.739555-1-clm@meta.com>
Content-Type: text/plain; charset="UTF-8"
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
X-Spam-Flag: NO
X-Spam-Score: -4.30
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="yBeuD/9Y";
       dkim=neutral (no key) header.i=@suse.cz;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="yBeuD/9Y";
       dkim=neutral (no key) header.i=@suse.cz;       spf=pass (google.com:
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

On 10/24/25 16:21, Chris Mason wrote:
> On Thu, 23 Oct 2025 15:52:24 +0200 Vlastimil Babka <vbabka@suse.cz> wrote:
>> @@ -5497,7 +5528,7 @@ int kmem_cache_refill_sheaf(struct kmem_cache *s, gfp_t gfp,
>>
>>  	if (likely(sheaf->capacity >= size)) {
>>  		if (likely(sheaf->capacity == s->sheaf_capacity))
>> -			return refill_sheaf(s, sheaf, gfp);
>> +			return __prefill_sheaf_pfmemalloc(s, sheaf, gfp);
>>
>>  		if (!__kmem_cache_alloc_bulk(s, gfp, sheaf->capacity - sheaf->size,
>>  					     &sheaf->objects[sheaf->size])) {
>                                              ^^^
> 
> In kmem_cache_refill_sheaf(), does the oversize sheaf path (when
> sheaf->capacity != s->sheaf_capacity) need __GFP_NOMEMALLOC too?
> 
> The commit message says "When refilling sheaves, use __GFP_NOMEMALLOC
> to override any pfmemalloc context", and the normal capacity path now
> calls __prefill_sheaf_pfmemalloc() which adds __GFP_NOMEMALLOC.
> 
> But this oversize path still calls __kmem_cache_alloc_bulk() with the
> raw gfp flags. If the calling context is pfmemalloc-enabled (e.g.,
> during swap or network operations), could pfmemalloc objects be
> allocated into the sheaf? Those objects would then be returned via

Yes.

> kmem_cache_alloc_from_sheaf() to potentially non-pfmemalloc callers.

The assumption is the caller will use the prefilled sheaf for its purposes
and not pass it to other callers. The reason for caring about pfmemalloc and
setting sheaf->pfmemalloc is only to recognize them when the prefilled sheaf
is returned - so that it's flushed+freed and not attached as pcs->spare -
that would then be available to other non-pfmemalloc callers.

But we always flush oversize sheaves when those are returned, so it's not
necessary to also track pfmemalloc for them. I'll add a comment about it.

Thanks,
Vlastimil

> Similar issue exists in kmem_cache_prefill_sheaf() for the oversize
> path at the function's start, though that code wasn't modified by this
> patch.
> 
>>  			return -ENOMEM;
>>  		}
>>  		sheaf->size = sheaf->capacity;
> 
> [ ... ]
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/51cfb267-f4f4-42b2-b0ea-d29d62bb1151%40suse.cz.
