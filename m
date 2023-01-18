Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBFODT2PAMGQERHNDQKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 39A5367151C
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Jan 2023 08:36:55 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id b24-20020a0565120b9800b004d593e1d644sf219085lfv.8
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Jan 2023 23:36:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674027414; cv=pass;
        d=google.com; s=arc-20160816;
        b=LHMeN42ZUdtvC/PY//+J3XizbZgmCpbMmtxEIEbDNz6294fBlTC8lmqrdSEoncAldb
         vjruxmJQPcgjIXgUUcszl6XMJuqwO37YE5VjqcwZCi4vMpVSlEG4aQriJ65fsHDrxjqz
         R8VBirpJxXQXP/IW6IgszFZv+MpV5wNwmPe+/kLe/slmndPxAs5Bb/PF3MJdq38FsQjm
         YjTuDQGuu4Kj7AACqOTBM7NcX2qIBQQHknd5logXUuisW5xveBL2LL4wMfi05cACatBK
         w2YlwURXDdlSiX4GgxzsGqq+Zt+wzl0uUNhY9/+CfCq2hB1aOivaDMywq9dnoNtgy1fA
         TJFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=uXYI1trH4JdZ3AdRMJijYY7mcj9PI3t7JlYBmtlVsPA=;
        b=TR8WJOUZu/DZBMw3ZuMDBRDBjwyxqGu9bfkJniWUEdpiJzBKNXyOXt/XKquXtsxnV4
         PVjeUJ5o3JwaEaj5J193REs6Wmgx8kjCxY31AKljAKVL++D22dUz119jU4cHjNyqycPM
         1/MHdnYzbYpZtkEFbP+zX7wETaO0rit0v/95Hp21VgEaIp9FX3m4DBB9Ngq3pozdQ2MO
         PXSvA19iqoQFCxfYZNi4kwZEoh6HaOCCTq0IgQBqC3JlKCbj/nDFv90m9rEDdZrEK6CV
         F1eU1okebdOr37RUPW3A5T0KeRp+VhHMFK5sYmc+17lsJdCnF34JE2/TI8jfiXtyMl6r
         N6cg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="ZfMfMP/8";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=uXYI1trH4JdZ3AdRMJijYY7mcj9PI3t7JlYBmtlVsPA=;
        b=lLAzK3bS80KmkBwXRA0ugqdSLMlgBltQA5GoWmGvXA/s+Roy3k+akqt6DWApc8SPpZ
         3DvczbYSc4Z3JKK/deSh0cOZUedGeP0vsNV7gNXQSXSGHY2zL5VpYrh8VcbYPNtRsjSf
         aJlXod8IiU4n11N/26gmer5w6OFQioOQ9SlFkY9HXpOP+MtjTSzmOgzr71fCzDLQbJNb
         kBAUEs3rjoARlC0RrHN12oIp4+EB2VmnIZgQdDJDyyvv9FHlNhzzcFVla9BiW6bI1plt
         XSsaLT7KmQ8noNc5yu3DHMpFhjd5YdncdoRFd0m3Ienm8ebYMmHjcegrQKerVX61ESAc
         4kBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uXYI1trH4JdZ3AdRMJijYY7mcj9PI3t7JlYBmtlVsPA=;
        b=ucGKFflDj0TgDhZvHGlU+Dovf7j3VBCTsOwMrjWVcaGpknWz7/H2m5qBsXl0ilrrch
         AOHZEG8yAKiBmNl2rGq0itTpIUhfMdIB8Mbecg8KvUjrFVfwbzZ7WgQXYMbc8Av3iuJQ
         E4NpMSJ6LnVN7GlPjq5giBkR2XAxAjbbUolVs0/JYOaky1V8wXvIk3AH/JSdLtcedS/9
         i/GbO7AZRAmQOZF7PvDezpzxLW4XMj99lFu5p6czt7zrohRaLtbpebsfc9V+FpAkg8XI
         IWcQVI/fr8fgrVsf0sehHwTTKORTE2bywv/csMGoYgtM9gJ3BWwO9CFWn8ld9B9kaXpl
         OQBA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kozpdEC7hpxtSETIphIw0PX6+p3iHGPve5G//VbCIekaOo1k/pF
	wo/n59ZegNXANmXKDJpGNW4=
X-Google-Smtp-Source: AMrXdXt8xMBQDLAc42etcaZWJKfXdQjtOAPI6/G9u+FevVHVzG0UYh1o7DYMOy42qIuP30rcPT03Xg==
X-Received: by 2002:a05:6512:1322:b0:4b6:f2a8:884e with SMTP id x34-20020a056512132200b004b6f2a8884emr608239lfu.191.1674027414335;
        Tue, 17 Jan 2023 23:36:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a554:0:b0:27f:b767:aaf6 with SMTP id e20-20020a2ea554000000b0027fb767aaf6ls2568228ljn.3.-pod-prod-gmail;
 Tue, 17 Jan 2023 23:36:52 -0800 (PST)
X-Received: by 2002:a2e:9097:0:b0:27f:d351:5f05 with SMTP id l23-20020a2e9097000000b0027fd3515f05mr1697133ljg.49.1674027412559;
        Tue, 17 Jan 2023 23:36:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674027412; cv=none;
        d=google.com; s=arc-20160816;
        b=NXQBWVR+yi/CE7l6ht8mbG5be2lkj5ILX/Sbcoo49tWjQFV/P7R0xhClHgUQwctg6H
         zMwSWdso/tWLFVpyPtFCWph0XJHpOW4Bo9H7CP1rJCfes5qGVPBbmLsGFK0euWFUK8xR
         FSTnT6Aed5CvhFmg7HIV2ViGccJy40oyc0zXgLyeqKNy+CYRNx75pF2FW0AkfexgXArV
         fVsM0fdD62XMp4+e/1gcXIzwezIdfvaKkhQLAQvRLjOUOksfr3VC+zn2mtpkhT77Y93z
         TX79ioYLgcyaAllvoA8VrvW46U7rqP4KHHIxw1FAPJ8TglZwSEX4CNqurLBGnPPMuIS0
         E+IQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=MYuQWqLPhNPLil6KLFw9XlwkP5BswaDfjZz2ueIxD6Q=;
        b=Fd5LJia48obBlm6DkMp11sNBGhV5ZYMaY5AhnhOi5RenRb7ovL6QPBHBDaHoj5ccv8
         Fam+PoGAXcRPg/UKCpVz0uff9xRIxj9O0dS3HmA/CtSHqGsqT1ETIlsUoGdbG+eEn+5G
         5hcjs6DMdR2wANUrW2oJ4gmhUdT9wBnVqX5qu0n0HjO+j3A+cNycstrNWJSmQDFiugDo
         QFenALjqf9mRgPDImGlpAneaLg0T+9x6Sp90MIh4Va6xErEM96jUr/c+Ax+xp0oGhaWd
         WMd2fK0O8VHRznHqhvjuzRktgt/PEutx3KvF6kASmq0sBRc8y8XKbSfvZjRs6WfOYQRy
         T18w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="ZfMfMP/8";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id z18-20020a2eb532000000b002865233e8b5si597295ljm.5.2023.01.17.23.36.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 Jan 2023 23:36:52 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id B5ECA20EAD;
	Wed, 18 Jan 2023 07:36:51 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 70B5E139D2;
	Wed, 18 Jan 2023 07:36:51 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id FujMGpOhx2MqfQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Wed, 18 Jan 2023 07:36:51 +0000
Message-ID: <bfe4ff8f-0244-739d-3dfa-60101c8bf6b8@suse.cz>
Date: Wed, 18 Jan 2023 08:36:51 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.1
Subject: Re: [PATCH RFC] mm+net: allow to set kmem_cache create flag for
 SLAB_NEVER_MERGE
To: Jesper Dangaard Brouer <brouer@redhat.com>, netdev@vger.kernel.org,
 linux-mm@kvack.org
Cc: Christoph Lameter <cl@linux.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Mel Gorman <mgorman@techsingularity.net>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>, penberg@kernel.org,
 Jakub Kicinski <kuba@kernel.org>, "David S. Miller" <davem@davemloft.net>,
 edumazet@google.com, pabeni@redhat.com, David Rientjes
 <rientjes@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 kasan-dev <kasan-dev@googlegroups.com>
References: <167396280045.539803.7540459812377220500.stgit@firesoul>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <167396280045.539803.7540459812377220500.stgit@firesoul>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="ZfMfMP/8";
       dkim=neutral (no key) header.i=@suse.cz;       spf=softfail
 (google.com: domain of transitioning vbabka@suse.cz does not designate
 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 1/17/23 14:40, Jesper Dangaard Brouer wrote:
> Allow API users of kmem_cache_create to specify that they don't want
> any slab merge or aliasing (with similar sized objects). Use this in
> network stack and kfence_test.
> 
> The SKB (sk_buff) kmem_cache slab is critical for network performance.
> Network stack uses kmem_cache_{alloc,free}_bulk APIs to gain
> performance by amortising the alloc/free cost.
> 
> For the bulk API to perform efficiently the slub fragmentation need to
> be low. Especially for the SLUB allocator, the efficiency of bulk free
> API depend on objects belonging to the same slab (page).

Incidentally, would you know if anyone still uses SLAB instead of SLUB
because it would perform better for networking? IIRC in the past discussions
networking was one of the reasons for SLAB to stay. We are looking again
into the possibility of removing it, so it would be good to know if there
are benchmarks where SLUB does worse so it can be looked into.

> When running different network performance microbenchmarks, I started
> to notice that performance was reduced (slightly) when machines had
> longer uptimes. I believe the cause was 'skbuff_head_cache' got
> aliased/merged into the general slub for 256 bytes sized objects (with
> my kernel config, without CONFIG_HARDENED_USERCOPY).

So did things improve with SLAB_NEVER_MERGE?

> For SKB kmem_cache network stack have reasons for not merging, but it
> varies depending on kernel config (e.g. CONFIG_HARDENED_USERCOPY).
> We want to explicitly set SLAB_NEVER_MERGE for this kmem_cache.
> 
> Signed-off-by: Jesper Dangaard Brouer <brouer@redhat.com>
> ---
>  include/linux/slab.h    |    2 ++
>  mm/kfence/kfence_test.c |    7 +++----
>  mm/slab.h               |    5 +++--
>  mm/slab_common.c        |    8 ++++----
>  net/core/skbuff.c       |   13 ++++++++++++-
>  5 files changed, 24 insertions(+), 11 deletions(-)
> 
> diff --git a/include/linux/slab.h b/include/linux/slab.h
> index 45af70315a94..83a89ba7c4be 100644
> --- a/include/linux/slab.h
> +++ b/include/linux/slab.h
> @@ -138,6 +138,8 @@
>  #define SLAB_SKIP_KFENCE	0
>  #endif
>  
> +#define SLAB_NEVER_MERGE	((slab_flags_t __force)0x40000000U)

I think there should be an explanation what this does and when to consider
it. We should discourage blind use / cargo cult / copy paste from elsewhere
resulting in excessive proliferation of the flag.

- very specialized internal things like kfence? ok
- prevent a bad user of another cache corrupt my cache due to merging? no,
use slub_debug to find and fix the root cause
- performance concerns? only after proper evaluation, not prematurely

> +
>  /* The following flags affect the page allocator grouping pages by mobility */
>  /* Objects are reclaimable */
>  #ifndef CONFIG_SLUB_TINY
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index b5d66a69200d..9e83e344ee3c 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -191,11 +191,10 @@ static size_t setup_test_cache(struct kunit *test, size_t size, slab_flags_t fla
>  	kunit_info(test, "%s: size=%zu, ctor=%ps\n", __func__, size, ctor);
>  
>  	/*
> -	 * Use SLAB_NOLEAKTRACE to prevent merging with existing caches. Any
> -	 * other flag in SLAB_NEVER_MERGE also works. Use SLAB_ACCOUNT to
> -	 * allocate via memcg, if enabled.
> +	 * Use SLAB_NEVER_MERGE to prevent merging with existing caches.
> +	 * Use SLAB_ACCOUNT to allocate via memcg, if enabled.
>  	 */
> -	flags |= SLAB_NOLEAKTRACE | SLAB_ACCOUNT;
> +	flags |= SLAB_NEVER_MERGE | SLAB_ACCOUNT;
>  	test_cache = kmem_cache_create("test", size, 1, flags, ctor);
>  	KUNIT_ASSERT_TRUE_MSG(test, test_cache, "could not create cache");
>  
> diff --git a/mm/slab.h b/mm/slab.h
> index 7cc432969945..be1383176d3e 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -341,11 +341,11 @@ static inline slab_flags_t kmem_cache_flags(unsigned int object_size,
>  #if defined(CONFIG_SLAB)
>  #define SLAB_CACHE_FLAGS (SLAB_MEM_SPREAD | SLAB_NOLEAKTRACE | \
>  			  SLAB_RECLAIM_ACCOUNT | SLAB_TEMPORARY | \
> -			  SLAB_ACCOUNT)
> +			  SLAB_ACCOUNT | SLAB_NEVER_MERGE)
>  #elif defined(CONFIG_SLUB)
>  #define SLAB_CACHE_FLAGS (SLAB_NOLEAKTRACE | SLAB_RECLAIM_ACCOUNT | \
>  			  SLAB_TEMPORARY | SLAB_ACCOUNT | \
> -			  SLAB_NO_USER_FLAGS | SLAB_KMALLOC)
> +			  SLAB_NO_USER_FLAGS | SLAB_KMALLOC | SLAB_NEVER_MERGE)
>  #else
>  #define SLAB_CACHE_FLAGS (SLAB_NOLEAKTRACE)
>  #endif
> @@ -366,6 +366,7 @@ static inline slab_flags_t kmem_cache_flags(unsigned int object_size,
>  			      SLAB_TEMPORARY | \
>  			      SLAB_ACCOUNT | \
>  			      SLAB_KMALLOC | \
> +			      SLAB_NEVER_MERGE | \
>  			      SLAB_NO_USER_FLAGS)
>  
>  bool __kmem_cache_empty(struct kmem_cache *);
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 1cba98acc486..269f67c5fee6 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -45,9 +45,9 @@ static DECLARE_WORK(slab_caches_to_rcu_destroy_work,
>  /*
>   * Set of flags that will prevent slab merging
>   */
> -#define SLAB_NEVER_MERGE (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER | \
> +#define SLAB_NEVER_MERGE_FLAGS (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER |\
>  		SLAB_TRACE | SLAB_TYPESAFE_BY_RCU | SLAB_NOLEAKTRACE | \
> -		SLAB_FAILSLAB | kasan_never_merge())
> +		SLAB_FAILSLAB | SLAB_NEVER_MERGE | kasan_never_merge())
>  
>  #define SLAB_MERGE_SAME (SLAB_RECLAIM_ACCOUNT | SLAB_CACHE_DMA | \
>  			 SLAB_CACHE_DMA32 | SLAB_ACCOUNT)
> @@ -137,7 +137,7 @@ static unsigned int calculate_alignment(slab_flags_t flags,
>   */
>  int slab_unmergeable(struct kmem_cache *s)
>  {
> -	if (slab_nomerge || (s->flags & SLAB_NEVER_MERGE))
> +	if (slab_nomerge || (s->flags & SLAB_NEVER_MERGE_FLAGS))
>  		return 1;
>  
>  	if (s->ctor)
> @@ -173,7 +173,7 @@ struct kmem_cache *find_mergeable(unsigned int size, unsigned int align,
>  	size = ALIGN(size, align);
>  	flags = kmem_cache_flags(size, flags, name);
>  
> -	if (flags & SLAB_NEVER_MERGE)
> +	if (flags & SLAB_NEVER_MERGE_FLAGS)
>  		return NULL;
>  
>  	list_for_each_entry_reverse(s, &slab_caches, list) {
> diff --git a/net/core/skbuff.c b/net/core/skbuff.c
> index 79c9e795a964..799b9914457b 100644
> --- a/net/core/skbuff.c
> +++ b/net/core/skbuff.c
> @@ -4629,12 +4629,23 @@ static void skb_extensions_init(void)
>  static void skb_extensions_init(void) {}
>  #endif
>  
> +/* The SKB kmem_cache slab is critical for network performance.  Never
> + * merge/alias the slab with similar sized objects.  This avoids fragmentation
> + * that hurts performance of kmem_cache_{alloc,free}_bulk APIs.
> + */
> +#ifndef CONFIG_SLUB_TINY
> +#define FLAG_SKB_NEVER_MERGE	SLAB_NEVER_MERGE
> +#else /* CONFIG_SLUB_TINY - simple loop in kmem_cache_alloc_bulk */
> +#define FLAG_SKB_NEVER_MERGE	0
> +#endif
> +
>  void __init skb_init(void)
>  {
>  	skbuff_head_cache = kmem_cache_create_usercopy("skbuff_head_cache",
>  					      sizeof(struct sk_buff),
>  					      0,
> -					      SLAB_HWCACHE_ALIGN|SLAB_PANIC,
> +					      SLAB_HWCACHE_ALIGN|SLAB_PANIC|
> +						FLAG_SKB_NEVER_MERGE,
>  					      offsetof(struct sk_buff, cb),
>  					      sizeof_field(struct sk_buff, cb),
>  					      NULL);
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bfe4ff8f-0244-739d-3dfa-60101c8bf6b8%40suse.cz.
