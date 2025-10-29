Return-Path: <kasan-dev+bncBDXYDPH3S4OBB2PPRDEAMGQEQ4DJ7SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id B033FC1BCB5
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 16:51:06 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-63c55116bdfsf6044375a12.3
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 08:51:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761753066; cv=pass;
        d=google.com; s=arc-20240605;
        b=EtgtML6aIWYanbIVXqhzh16MiusUeHFyP8Mrq+5j5kx1yMa6zRsF4k4h/+NJvGlL7E
         RY1NvEmV8W9UrrUe2D74b14sZNYG+H844ZKJ87+vL0F4L1o6Jjchq2gLkMAkhcpt+2iu
         J2E/Nkm0PoDlZXPL06AC9kTKBsCIFOq9N5czFnGWzgciBLr1pIc9SvP6AYkjGsfnbNt0
         dBAuYJvjwhUMf5Xbuo0HqSWcaWeuzgZCvxgQ1+sdAAXAnawVoHtT+rufU+CaGo4LZA1E
         jhzzI2+MdBp2ZWDzyIlswgSRp0aFlJyNCCAWE2+ihBiA4Svu8zf3hCZlBPImkWAF3/XX
         95Uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=l8ip14j1xhelKcdBEr9ZXwoEnkJdnH5WALybD+dPjy4=;
        fh=VpsDjjC1dfnE2B5BXDOcVRru66kvOh66myzrnbIUlgY=;
        b=IPmnNPwaUfnGihHihksGXRQSjc9XW0KKQeS7YTz7SgLomNXPEKN+tjo8nvYp+/96nr
         XJU/pE4ry7umGJXs6/jFD7iR4sUej+5486ddBmMyopS+0nPR5ByGMX8zjP91YxY92Uiu
         Z/qCg6HEHap83virMTRKSjXoH+R9aLI1pgSbjArB5lvGnOZktnOK0jTROvnve+f/I1c8
         dfw6lljTJ7Kd6KM6xRPmZuqy/vZ6fOTjtYr7/5Q1zwegtniaHB5BMDlaJV7IDqnoghL9
         yBLcTaSdUMMm7fHenXKW3I9gd5fk356dmgQuL+UHm8hNSBOtUC68ibdCjiicNSJMmoQZ
         owew==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=1Uxy6L1d;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=1Uxy6L1d;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761753066; x=1762357866; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=l8ip14j1xhelKcdBEr9ZXwoEnkJdnH5WALybD+dPjy4=;
        b=bZYp+ZNX5uZJaW+fGBTJaEO5zOYqfNtKI08fiUocO59/ZQjmCJ5MUBrEdbZF3vX/N8
         535VCQybK4QvOehHR49DslAjVnwkQCPBibueNyifE/URvqRSpz2zWNAzxk6yfeG0ALFW
         Uv8+02VADv5J0PMd2szyVM2FZvt3DVE8OX9clKhO9RVbG1Z2kp/TY/wPih+wgiObQ/Cc
         2wXhIQNPJfM4ehZGUFcqzLQYdhLIrRU5efqXwidFVKtP++Wpsf5eVXnGG7YY4c2BSoCv
         dc5eTunP2M5W5Ja42OtrUCd0UZEUBOyAXmViKg/y0LFPTF0Wo0zxucgru6VaXW0NrxQV
         pPQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761753066; x=1762357866;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=l8ip14j1xhelKcdBEr9ZXwoEnkJdnH5WALybD+dPjy4=;
        b=Empt+Zbz3SUd8VtSNVtdLmV1tdv4Ck2WKN3Nnz635AHwZQxPaQNECc/lOS02+gcXWb
         TAokxvyB1txOqDi/pXCcewNDLNzedk1xiorIlp17+KlOFFgSZ0pb7B2xFLoWm3QUyeIl
         EUkiBA4u8j3n9ECvuN2atMZ7D9syrXP+cr3upj7vRKlQEtM6bmhtoCEmRdZjSufGElfA
         YcOi/ZFUXU2G/YiUEATrEdsTeREAUgwXGquTzb17VFUbuvM8sgvIx/59lz6aT3zUwQtT
         fjT3riPh3fc9kfqlCQVQX2q5roZPCrXUY17rE5vf3QwC0DYr27bnWaHXT55Bp2fuZBGt
         ZDiQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXf6csOK4h0fq3WU98yI1r8mBB9I/sK1chb1b1VeaYPvq8DyBQf0FSfJ+DyWCmnGjGrBVTHDA==@lfdr.de
X-Gm-Message-State: AOJu0YxDdaQ6xL4gfw0qzU3Wj65mhKa/pft1/VdOsgw+zPpffgSCZrxm
	PiPVL0NRyNJ3UAxQ0Ejf0W+bv3DrC8IVCroX0/+arh3gCZOewAGbAOBX
X-Google-Smtp-Source: AGHT+IFUh41vRk8W08CZcBBHTIpW6PgWzQs1V64Tak4JiKmBA3ehd0h+O4q33d5l0YQBf/t8e0UNcQ==
X-Received: by 2002:a05:6402:51cd:b0:63e:9e1:42d5 with SMTP id 4fb4d7f45d1cf-64044252bbamr2593421a12.22.1761753066118;
        Wed, 29 Oct 2025 08:51:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aheybfjal7ENyROuJryPhQc+EZDHpWTn1SxV+l9HwJbQ=="
Received: by 2002:a05:6402:a149:b0:63c:37de:a667 with SMTP id
 4fb4d7f45d1cf-63e3e5edb90ls5075110a12.0.-pod-prod-07-eu; Wed, 29 Oct 2025
 08:51:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWFqK9LnoIOCvM6BhRQd+c4W/SsWWK7uU8HoKw54GKYmvRp+2ZB+EysGdXCAu/RIIw3d9f9u6AquBM=@googlegroups.com
X-Received: by 2002:a17:906:f5a9:b0:b50:697e:ba3 with SMTP id a640c23a62f3a-b703d5a7686mr342596666b.63.1761753063449;
        Wed, 29 Oct 2025 08:51:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761753063; cv=none;
        d=google.com; s=arc-20240605;
        b=dS0hsl6Up6dCpxude5rEavVp17EXD12KsrzY/iQoFXCluxsjIM6LFkQ9V7UM5+9bL5
         7npf16I0owcQuLsSBbmgZygZtUoTVXSiBB4CYTl4soDAr12dlgDhXKE1W8UO4YuHKd6Z
         KrksDVDy+aVWfXVHPuvZtftO5HgVgcQxeOYrsTZjoXpniBS0YkvbjaDd63ODd39c2NET
         i44JwryCoyq7KcclVyb1Dr0yswS4kyj5fMArtfjQWPoIekUm4jB9WdX8lbaLRHwbL61K
         Gv5VBvaQdDvQTbdXxQ0j1C5Mwml9BqsZ9Kr8gRjVswKJIqITTq1a7Rvvcx4yPzFcVYes
         KSbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=38XVem9V9R+8KoeP3WL2xrsbd2vq05h7o4o1fLwBkic=;
        fh=o5F+zdD+BrF1g389dqaHWhI8yyYLrSzZl2Fw5mCrJ38=;
        b=RwiZo5SgChyxwLLryLiB5Xrc/RtGpJmuhRAzxvo7+7dV7Loovof60uFXLoJ7rE/CSH
         BMs0h6yeBZgB5AVkE/bYEDXD2JjaY0hUS52Dh/+UGXIz0BWL1psi0xKdb8Dw1FZKptxd
         bnizWstqMGP/moWur5m+UsxHmNiKLBEbLMsbqGbfDpN+UDldaJyOR7Id9ScJ+MsiWvkg
         rqri8ImMofgXFQqdYaSMLMYdWWDBzfxKwiCVua7xMTQ+kzduNHmrJon3767edMgjy93L
         LCu3+/8T2NNLL/OyvMYjAHTwzjKxylCm2rARdcsoS5MgQw+4zU9fDy5uR7SB/E3gblZ/
         I5Dw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=1Uxy6L1d;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=1Uxy6L1d;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b6d8728c76asi22363966b.1.2025.10.29.08.51.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 08:51:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 00D5D33E4C;
	Wed, 29 Oct 2025 15:51:03 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id D34461349D;
	Wed, 29 Oct 2025 15:51:02 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id hcnzMuY3AmkcBwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 29 Oct 2025 15:51:02 +0000
Message-ID: <48e0bc5b-ccee-4fce-8a89-a32f79228bb6@suse.cz>
Date: Wed, 29 Oct 2025 16:51:02 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 06/19] slab: introduce percpu sheaves bootstrap
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
References: <20251024152913.1115220-1-clm@meta.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <20251024152913.1115220-1-clm@meta.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,suse.cz:email,suse.cz:mid]
X-Spam-Flag: NO
X-Spam-Score: -4.30
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=1Uxy6L1d;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=1Uxy6L1d;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
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

On 10/24/25 17:29, Chris Mason wrote:
> On Thu, 23 Oct 2025 15:52:28 +0200 Vlastimil Babka <vbabka@suse.cz> wrote:
> 
>> Until now, kmem_cache->cpu_sheaves was !NULL only for caches with
>> sheaves enabled. Since we want to enable them for almost all caches,
>> it's suboptimal to test the pointer in the fast paths, so instead
>> allocate it for all caches in do_kmem_cache_create(). Instead of testing
>> the cpu_sheaves pointer to recognize caches (yet) without sheaves, test
>> kmem_cache->sheaf_capacity for being 0, where needed.
>> 
>> However, for the fast paths sake we also assume that the main sheaf
>> always exists (pcs->main is !NULL), and during bootstrap we cannot
>> allocate sheaves yet.
>> 
>> Solve this by introducing a single static bootstrap_sheaf that's
>> assigned as pcs->main during bootstrap. It has a size of 0, so during
>> allocations, the fast path will find it's empty. Since the size of 0
>> matches sheaf_capacity of 0, the freeing fast paths will find it's
>> "full". In the slow path handlers, we check sheaf_capacity to recognize
>> that the cache doesn't (yet) have real sheaves, and fall back. Thus
>> sharing the single bootstrap sheaf like this for multiple caches and
>> cpus is safe.
>>
> 
> Hi Vlastimil,
> 
> We're trying out the AI patch review automation on the BPF commits and it had
> some questions about a few of these.  Since the goal is to actually test the
> automation, I'm putting them in unedited, but I did try and make sure they
> were valid before sending.
> 
>> diff --git a/mm/slub.c b/mm/slub.c
>> index a6e58d3708f4..ecb10ed5acfe 100644
>> --- a/mm/slub.c
>> +++ b/mm/slub.c
> 
> [ ... ]
> 
>> @@ -7733,8 +7782,7 @@ static void free_kmem_cache_nodes(struct kmem_cache *s)
>>  void __kmem_cache_release(struct kmem_cache *s)
>>  {
>>  	cache_random_seq_destroy(s);
>> -	if (s->cpu_sheaves)
>> -		pcs_destroy(s);
>> +	pcs_destroy(s);
> 
> Can pcs_destroy() handle a NULL cpu_sheaves pointer? Looking at the
> error path in do_kmem_cache_create():

Good catch! I will leave the condition in __kmem_cache_release().
Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/48e0bc5b-ccee-4fce-8a89-a32f79228bb6%40suse.cz.
