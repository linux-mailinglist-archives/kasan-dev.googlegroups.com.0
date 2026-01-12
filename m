Return-Path: <kasan-dev+bncBDXYDPH3S4OBBU5CSTFQMGQEZNGF7AY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B96DD1399D
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 16:20:53 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-38317963123sf20756981fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 07:20:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768231253; cv=pass;
        d=google.com; s=arc-20240605;
        b=aDvOPP60OP4yHkQbUgfOQfVO5pkk6PJdOwpb+nY4VP2biNgCnTdM5wlCobr65BHORi
         hW1R8ezWIFWfiOtujEFB3CmU8KTQCQFVEZW1CT77blZ2nmOZHnFRgZnEoFXbmj7b0Qw7
         zbH0aQ+GvShXmTrM1KDAXHJQ86Fawt5odyj6WmsFBASPQlV9dfPa0DNGTwckCiGXA7yI
         vhorYUEdavc7Yr5IyjcFXoUbP8rpx7mtId7wNa1IWAEdr0C8A/NV2hyPCaJ7eN4mo426
         ILLehYp+FUF/8c5/eR1SFXKmerCMCTJbBlIFMdaqE33QaSsojWilZDJbW1ETPwT1h2rb
         fTDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=v2qd1oqdcDRehrcIO04Jk2uBQnx66JDaCM1K49EollI=;
        fh=WF+/4IWb0FutgTBtTO/U3Xj4CZZ2rsK/BFjP/cDt09I=;
        b=eDv2iLOKogJpacGmhN3L623ZVePJ3xz5x0jgcLXmhgAoIrzHf8C7c7D+oiEKNDZVye
         oB59wc+5D9Ere786RoOT7Ld76Ach+tUpCCWVdevH7Bse6pkc/cj1JiCMzbyt95os2XRl
         YJ/l2+tE12o/C+J6Lt7kjLII8Ox6WlqoHaVZE8OCrg6GJrg8559kT91S3LGEAZjeqqRp
         /gZLUqj4u7epmRz0/rJfbqI1bmffWt8tEgqJxFuhLkfwQZP69E1+xIbU5Pqxa8hOpPdE
         PyLF5dqo71APOwQ/HUhipxIMtp1yTsiyXPGvtSSQwxNWa2+nR2miOaEKrpoVAyR0Zs/E
         alrg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ANFGIGqM;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=mlOykGbL;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768231253; x=1768836053; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=v2qd1oqdcDRehrcIO04Jk2uBQnx66JDaCM1K49EollI=;
        b=ClVbKtYkjvyw3zbdmBgMz6Siu4E3AXLK3c1hp8elrrbSsJ1+u09y/Pf+EsHvzgKOuC
         cxZSsuMNbHqXgZ5reHI5n6vg9EtZAOoqn7/2tnLJJjN67KY76WLrMhB2tJ/M/u0Dq1hk
         5X3fq2xWWOoirvQQVbz9UA85F8MsIFUf5jSrDfA5Djj2pITL4L7Kfe1Jmedj+TUXS00q
         rGfMNCPKtbwrZQzBKjfRFb2DIfOI5BJYYvxDrTkUBQ8qAV+BoiQMaTXTq1k6C36yEnLO
         6RuqkMWlHlYGIpNhDbPvGVcYEEpwUyuBMG3OkcdNgbQCKk5PgWvriYEmdPTAxlvEwIcE
         0FiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768231253; x=1768836053;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=v2qd1oqdcDRehrcIO04Jk2uBQnx66JDaCM1K49EollI=;
        b=jZeWpO4CpNt8pKwMrIMPyPvQ93pqWcPa9EUP/LtR0Yl8OyaArbewLZs5YPOfdbx9Ha
         o+8hKAQtD5zhqsaUTaIpgfacpROnEzzAPb44qEVVImXv7yx1mErE9LQF1EgBhjxBrBN8
         CVT/+hfsJ6Cb3VZcebykK4MmKGGI3VrX+bBjR5O+bPgEg5F0X1iCT6yzlaq7ngi6cpTc
         mGUMnSiEF1chzjOpEZLeFvxS5gdjIoT5jRbNNEY/rWTvuauwaxppXECmvyiJdg08iP+C
         Vm6pseWp1f3M9S+BupaEYmuT2RHVh5JeE3dcYNAcsDBxK7M5JaTVyQtntB4h3PehLJwf
         HmPw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU4sknchMFbmb4UWIXrIEeGxAlvEbpSr7sWx+0uiFLdFl8JaY8q92RdEOZiEKFwwwjr1jGYvw==@lfdr.de
X-Gm-Message-State: AOJu0Yz7M5tjRMNw+KH8fckMjuuo5nxGxpevvrCn8+PjqWbIR9xkPcQC
	oQMx66DH7xe/DEIhkIsjmTWI2blRCuL5ORKf6+S7Jww0Nju3xJncZ+5r
X-Google-Smtp-Source: AGHT+IF7/Nht6Qqqaf5BGMfv6srGlc5RoO6aVh7YcEVXe4JNT5JQlbG6C0biz/Iwr3st9dk1hsjY3Q==
X-Received: by 2002:a05:651c:41ca:b0:37f:aa44:2cd6 with SMTP id 38308e7fff4ca-382ff6e8831mr53852331fa.28.1768231252605;
        Mon, 12 Jan 2026 07:20:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+H+pSYFUGELaNu9597gqfOM3nHks568xCH1AwkbM9j5mQ=="
Received: by 2002:a2e:a288:0:b0:363:22ce:bcfc with SMTP id 38308e7fff4ca-382e931bcfbls3670371fa.2.-pod-prod-03-eu;
 Mon, 12 Jan 2026 07:20:50 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXvPf4EUVsSE0Ynkt1M4P7zQ5YA6R7SPVcKZBA32ag3rXXD7L/FOWCm0IeX3Ao1AUaSBp3GKFmrhu4=@googlegroups.com
X-Received: by 2002:a2e:a593:0:b0:37a:5990:2ba8 with SMTP id 38308e7fff4ca-382ff6e5dc1mr50857051fa.23.1768231249737;
        Mon, 12 Jan 2026 07:20:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768231249; cv=none;
        d=google.com; s=arc-20240605;
        b=NJtkNKVUcc7d8jTLi3qTZngGFq7+VX8qEPX3H0LtM/qfCnN55wHv3rACQelusKXatE
         cjyxFWgzqkouQHJjoc49fvP59VmGoyXENyiVYMYJ7F1dKV7PTcC9Vzo4ytn3k+hNqe5/
         0E6USDhCA7bli3NpaJb21xDzt4wGe1u3+YxxEZqS+4emcJSknNCyekp0BYvqjva/wOjT
         tfwBn8Ya1H2u8U6W6OA8zOziY69Cx32lDnkrh8zdfnxM6HYHqZzEmJWIhyMRVvocHSPl
         eECggIt3NvYFgtuv/Bju4oYMH3yi/soMXvJCragzxyoSwHfWZ07fBFxrTnfAW2IxZt8c
         E6/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=n25xYend9nOvPHOgzYEdjuhjORh5tzR0W8gWZOljgv4=;
        fh=hsHBnuEFqOuHSK1NJ3mYJ9Sw4UDQd+nM7Ij3ICXe4YQ=;
        b=PMwH8z0GB1FMTjKxOrtFOlK672ALv4AjwUolWwit8WhsFa8Yy0aMU49CG0vZhIw0Oi
         MOTRqOGbe0nqKjJh2CP9v3M3K8Fx5ZYdVFR5u2dVS6nkP4Q6ccqZs0cgw9qPBr3UkNpM
         Bluv8jTZqOxgZjXC4XtgGI7PErlHm9n6PmqI7ORJtggJYNSt/6v4W/VC+2rj8BX9ErzZ
         Of3PjbOv7XGKXyDE1EDaVhOlsJuC4aJJqXgAdTS5/ayqGkpnB/mzEtCR+bWITZBMnZrj
         mqVCC0zV2r8994d/+eAzJBTUVt1808RrQ9MdYn/5JOUuvy+JUQMLhNFzrSueOZHq0Pv0
         SLHw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ANFGIGqM;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=mlOykGbL;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-382fc3b94f2si2774891fa.7.2026.01.12.07.20.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 07:20:49 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 7348A33686;
	Mon, 12 Jan 2026 15:20:48 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 50A303EA63;
	Mon, 12 Jan 2026 15:20:48 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id ueREE1ARZWndGgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 12 Jan 2026 15:20:48 +0000
Message-ID: <7a0be5a1-17f5-4bba-9d42-a53fbb84abe8@suse.cz>
Date: Mon, 12 Jan 2026 16:20:48 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 00/20] slab: replace cpu (partial) slabs with sheaves
Content-Language: en-US
To: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>
Cc: Hao Li <hao.li@linux.dev>, Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com,
 kernel test robot <oliver.sang@intel.com>, stable@vger.kernel.org
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -4.51
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
	RCPT_COUNT_TWELVE(0.00)[19];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	MIME_TRACE(0.00)[0:+];
	SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,intel.com];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:dkim,suse.cz:mid,suse.cz:email,msgid.link:url,imap1.dmz-prg2.suse.org:rdns,imap1.dmz-prg2.suse.org:helo]
X-Spam-Level: 
X-Rspamd-Action: no action
X-Rspamd-Queue-Id: 7348A33686
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=ANFGIGqM;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=mlOykGbL;       dkim=neutral (no key)
 header.i=@suse.cz header.s=susede2_ed25519;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 1/12/26 16:16, Vlastimil Babka wrote:
> Percpu sheaves caching was introduced as opt-in but the goal was to
> eventually move all caches to them. This is the next step, enabling
> sheaves for all caches (except the two bootstrap ones) and then removing
> the per cpu (partial) slabs and lots of associated code.
> 
> Besides (hopefully) improved performance, this removes the rather
> complicated code related to the lockless fastpaths (using
> this_cpu_try_cmpxchg128/64) and its complications with PREEMPT_RT or
> kmalloc_nolock().
> 
> The lockless slab freelist+counters update operation using
> try_cmpxchg128/64 remains and is crucial for freeing remote NUMA objects
> without repeating the "alien" array flushing of SLUB, and to allow
> flushing objects from sheaves to slabs mostly without the node
> list_lock.
> 
> This v2 is the first non-RFC. I would consider exposing the series to
> linux-next at this point.

Well if only I didn't forget to remove the RFC prefix before sending...

> Git branch for the v2:
>   https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=sheaves-for-all-v2
> 
> Based on:
>   https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/slab.git/log/?h=slab/for-7.0/sheaves
>   - includes a sheaves optimization that seemed minor but there was lkp
>     test robot result with significant improvements:
>     https://lore.kernel.org/all/202512291555.56ce2e53-lkp@intel.com/
>     (could be an uncommon corner case workload though)
> 
> Significant (but not critical) remaining TODOs:
> - Integration of rcu sheaves handling with kfree_rcu batching.
>   - Currently the kfree_rcu batching is almost completely bypassed. I'm
>     thinking it could be adjusted to handle rcu sheaves in addition to
>     individual objects, to get the best of both.
> - Performance evaluation. Petr Tesarik has been doing that on the RFC
>   with some promising results (thanks!) and also found a memory leak.
> 
> Note that as many things, this caching scheme change is a tradeoff, as
> summarized by Christoph:
> 
>   https://lore.kernel.org/all/f7c33974-e520-387e-9e2f-1e523bfe1545@gentwo.org/
> 
> - Objects allocated from sheaves should have better temporal locality
>   (likely recently freed, thus cache hot) but worse spatial locality
>   (likely from many different slabs, increasing memory usage and
>   possibly TLB pressure on kernel's direct map).
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
> Changes in v2:
> - Rebased to v6.19-rc1+slab.git slab/for-7.0/sheaves
>   - Some of the preliminary patches from the RFC went in there.
> - Incorporate feedback/reports from many people (thanks!), including:
>   - Make caches with sheaves mergeable.
>   - Fix a major memory leak.
> - Cleanup of stat items.
> - Link to v1: https://patch.msgid.link/20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz
> 
> ---
> Vlastimil Babka (20):
>       mm/slab: add rcu_barrier() to kvfree_rcu_barrier_on_cache()
>       mm/slab: move and refactor __kmem_cache_alias()
>       mm/slab: make caches with sheaves mergeable
>       slab: add sheaves to most caches
>       slab: introduce percpu sheaves bootstrap
>       slab: make percpu sheaves compatible with kmalloc_nolock()/kfree_nolock()
>       slab: handle kmalloc sheaves bootstrap
>       slab: add optimized sheaf refill from partial list
>       slab: remove cpu (partial) slabs usage from allocation paths
>       slab: remove SLUB_CPU_PARTIAL
>       slab: remove the do_slab_free() fastpath
>       slab: remove defer_deactivate_slab()
>       slab: simplify kmalloc_nolock()
>       slab: remove struct kmem_cache_cpu
>       slab: remove unused PREEMPT_RT specific macros
>       slab: refill sheaves from all nodes
>       slab: update overview comments
>       slab: remove frozen slab checks from __slab_free()
>       mm/slub: remove DEACTIVATE_TO_* stat items
>       mm/slub: cleanup and repurpose some stat items
> 
>  include/linux/slab.h |    6 -
>  mm/Kconfig           |   11 -
>  mm/internal.h        |    1 +
>  mm/page_alloc.c      |    5 +
>  mm/slab.h            |   53 +-
>  mm/slab_common.c     |   56 +-
>  mm/slub.c            | 2591 +++++++++++++++++---------------------------------
>  7 files changed, 950 insertions(+), 1773 deletions(-)
> ---
> base-commit: aff9fb2fffa1175bd5ae3b4630f3d4ae53af450b
> change-id: 20251002-sheaves-for-all-86ac13dc47a5
> 
> Best regards,

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7a0be5a1-17f5-4bba-9d42-a53fbb84abe8%40suse.cz.
