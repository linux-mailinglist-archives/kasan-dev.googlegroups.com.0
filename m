Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHOVQ6KQMGQEY5VRE3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 269F1544C50
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 14:42:07 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id h23-20020a2e3a17000000b00255788e9a7fsf3884810lja.10
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 05:42:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654778526; cv=pass;
        d=google.com; s=arc-20160816;
        b=G5o1aFu1gl2ijYaI0hPMdwHrU6AeAM5g322Geb1SzofQaXj2Q+aiDRPmse4GvwQqYL
         dIXUpIkOizfnR/vgIQR0pwVJzKH2OP1vAtYdjayM4fJOCxWu5DzvjB/SnD6Z3+MG5uy4
         MozEB41rXMYMU6yYSk5zb89SmmkV2fF/w1lnnk3X+I4BD5lt0O6F9PEVv78OVCkR8niD
         Wu7wOkzO/0bTh7z35IMPz1JKBRuHqyvlWc16MgevhW7dXWSMdqIWEjdFnq93JDI5edVB
         24q2obxbBEJqAwjRKIA2OwY1WJBn2okf9nia96x/YBH5pl2NO0naqTofAuTJz0pNMtVa
         QOfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=mJwApblniXlr8I/YGfEDBExsxvzPrJjVkP/2RF9MJ34=;
        b=YqF2T6ZNLjvmzmRuaoiSSfxE0nf64meCPr6i0QII8w5uBYEyURrz4JU2CKLT/3GSoQ
         rsAXGxT0EZPOT9sFuAe4+huahmz+AiTKQglV5n3hctaSQusihfXA008Oghgdg5P4Ko3R
         yDG0V7kmqUbvAabyk69H1VrFf0kAd5klh84DoLb0O26Z1kw6Wwr/bhNhmgvo2rxINQeD
         JWTZdoWCdYj3olgTh94fuPtl5yFnpY6fHjzxJw1WQTN+2n8/WhmDfFUJLyDBUfIAngJN
         ZMLADX1pRH+e+PeZ5xyQpjQC1U1S2P2K8rgiBBitx5CIyQvHfAclEo7LNkr7+wMkqTnZ
         IIyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gtgWlr41;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=mJwApblniXlr8I/YGfEDBExsxvzPrJjVkP/2RF9MJ34=;
        b=mYRR+1315dS3RZOxuozOhgQkWVJjUC+gOnevfdBYbofP9UUjpY2/H/q+WOV4yy/ieF
         2n/u5wZ4ZpiwRsPX86qT9XmB+OWXUjvHcY5PTA6O6inuGiD6f4F+BcnujuPiMzFOqsy0
         vfXoS0UbhAGjIJMD6HA0mTqz4PMk0jBjoNU3mvdrAQGdM/Qz2ANwe/d5BnZVqkTEPB/Y
         MQqHMz/kUbobp0FwJslSZ4u//CPBM72tKnz7LCSB9li8Zv2ho7tP60+zV9lb7kKtYC1c
         PXvubqJo+jqkhZ/pNf2Ezts4plFZtakDaSjOdD5kTpdSskwzzkhvkd4lI/ARZzIK8O36
         EsBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mJwApblniXlr8I/YGfEDBExsxvzPrJjVkP/2RF9MJ34=;
        b=XVBkH5j2foHSYmqe4Y8ybKSDWQoVah1Z4Xq5SuTb3LdQ19egw/OBuWhUqsh3U+6Meq
         QfqyVHdyxO3R7gdzDi/AyzK0MO2b3ZnmXu4/8Evks1l52P605en9hHXG3ik6EZ1d3f4M
         Ol3NToxqrip5iDkkBcb3Q6tRhE/Yo5QxizctcU+suDDUSGkkrAE/wXukiqkXj6gsh27i
         o+l3DX02X8gER20PA6ZIWP6y7Qr4Ve9QRs/qzw+rR0Hzga2Wv5VJv+4wJkBv9OrhlgfT
         C2jXroy9h/SnJRZrIBbfIE0PmMSuq2RNEQ6QOXMUZ09U08nX6cmFLeu0oMxjARbpzw0v
         7ggA==
X-Gm-Message-State: AOAM531zpJfl0/LB46LZGq6d82KahLpljoeqU8K8wigzwK2rAzALTRV+
	VIaFRG0aEoDitsgbujI+JVM=
X-Google-Smtp-Source: ABdhPJzRNEIXhvlmnYujsOONMc0Fx62uwKyx424pMWXihrkKCPttTG/EZq65s/iIKXJ+tqStSCFlYA==
X-Received: by 2002:a05:6512:3d23:b0:478:fa1e:70fe with SMTP id d35-20020a0565123d2300b00478fa1e70femr24936728lfv.530.1654778526128;
        Thu, 09 Jun 2022 05:42:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7003:0:b0:255:95cf:cecf with SMTP id l3-20020a2e7003000000b0025595cfcecfls839719ljc.11.gmail;
 Thu, 09 Jun 2022 05:42:04 -0700 (PDT)
X-Received: by 2002:a2e:7813:0:b0:255:8e6e:1988 with SMTP id t19-20020a2e7813000000b002558e6e1988mr13675064ljc.107.1654778524665;
        Thu, 09 Jun 2022 05:42:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654778524; cv=none;
        d=google.com; s=arc-20160816;
        b=KXVFpXFTfG25MiEgzoV+wgQlQf93M8vz2YIzrupAhxtCHigxQd6JSkUn/BLRuYiqDp
         yEwPXZcZIXeOdqVydma/R4jv+ZNL0X+qguqWf49UoMMROr9xto7DEf8oTUY9fCDx4cjC
         m9dM61p50OfHcvOitGDAdG/lzisTOcBVHOFwunAP2LLfVyq49jxjt/qmWdO2U6Nh0rfY
         Rny5k1Qb/TUM6OKskYdS0TGqqjujIQ1X21w9GrykIRlOG+HIPgee/oBj88UvkNiKdcCk
         Pp3BNZjNvacbUwj8O+LIH80xorcx1d9RPjWL5KE4/z5zcKdOwgAc6mubed/dcuQAFqDZ
         FJyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=arApoAXBepq4URi/Em9A+yWgPjBE5I/lG8/rZgaEm2s=;
        b=YYW5u6Go+Aj9jucJ5S1Ef1C+o4sY7MuBaA+PYV6cPWl8Xr6cRM0evBPvGNpG1fzrbw
         JrpUTj/vQE3eGxlihhthQ/MEndwnhCD36YwoH9IgxeTzEA5p2fK2vysl615YybirlF6u
         ruTzWaoaLbNSei3E5RhVQNH6ANcfPzRQ1dPLNODXZpNX6T1se8oo17aZrOjsw/cejo6E
         WnSrVppwa6jgvB0/NGhCBriWu6QQSHphDDSO5VcS2Bo6LwPlKvmwrLJdMdXGlD6lug1f
         ZH4HvBXnhRCEcz8dy/MWiECqhnJufW5HYEAA2pOCTydxOkrEEWL4GWe0nLOZaj4cc0qP
         9sqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gtgWlr41;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id b14-20020a0565120b8e00b004785b6eac92si1150124lfv.7.2022.06.09.05.42.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 05:42:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id q15so24199435wrc.11
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 05:42:04 -0700 (PDT)
X-Received: by 2002:adf:dd0a:0:b0:213:ba65:73fa with SMTP id a10-20020adfdd0a000000b00213ba6573famr33219503wrm.521.1654778524190;
        Thu, 09 Jun 2022 05:42:04 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:dcf:e5ba:10a5:1ea5])
        by smtp.gmail.com with ESMTPSA id j37-20020a05600c1c2500b0039c235fb6a5sm28367506wms.8.2022.06.09.05.42.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Jun 2022 05:42:03 -0700 (PDT)
Date: Thu, 9 Jun 2022 14:41:56 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Jason A. Donenfeld" <Jason@zx2c4.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: linux-mm@kvack.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, John Ogness <john.ogness@linutronix.de>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Geert Uytterhoeven <geert@linux-m68k.org>,
	Geert Uytterhoeven <geert+renesas@glider.be>
Subject: Re: [PATCH v2] mm/kfence: select random number before taking raw lock
Message-ID: <YqHqlC9gvYl2vAiE@elver.google.com>
References: <CAHmME9rkQDnsTu-8whevtBa_J6aOKT=gQO7kBAxwWrBgKgcyUQ@mail.gmail.com>
 <20220609123319.17576-1-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220609123319.17576-1-Jason@zx2c4.com>
User-Agent: Mutt/2.1.4 (2021-12-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=gtgWlr41;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, Jun 09, 2022 at 02:33PM +0200, Jason A. Donenfeld wrote:
> The RNG uses vanilla spinlocks, not raw spinlocks, so kfence should pick
> its random numbers before taking its raw spinlocks. This also has the
> nice effect of doing less work inside the lock. It should fix a splat
> that Geert saw with CONFIG_PROVE_RAW_LOCK_NESTING:
> 
>      dump_backtrace.part.0+0x98/0xc0
>      show_stack+0x14/0x28
>      dump_stack_lvl+0xac/0xec
>      dump_stack+0x14/0x2c
>      __lock_acquire+0x388/0x10a0
>      lock_acquire+0x190/0x2c0
>      _raw_spin_lock_irqsave+0x6c/0x94
>      crng_make_state+0x148/0x1e4
>      _get_random_bytes.part.0+0x4c/0xe8
>      get_random_u32+0x4c/0x140
>      __kfence_alloc+0x460/0x5c4
>      kmem_cache_alloc_trace+0x194/0x1dc
>      __kthread_create_on_node+0x5c/0x1a8
>      kthread_create_on_node+0x58/0x7c
>      printk_start_kthread.part.0+0x34/0xa8
>      printk_activate_kthreads+0x4c/0x54
>      do_one_initcall+0xec/0x278
>      kernel_init_freeable+0x11c/0x214
>      kernel_init+0x24/0x124
>      ret_from_fork+0x10/0x20
> 
> Cc: John Ogness <john.ogness@linutronix.de>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Reported-by: Geert Uytterhoeven <geert@linux-m68k.org>
> Tested-by: Geert Uytterhoeven <geert+renesas@glider.be>
> Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>

Reviewed-by: Marco Elver <elver@google.com>

Thank you.

> ---
> Changes v1->v2:
> - Make the bools const to help compiler elide branch when possible,
>   suggested by Marco.
> 
>  mm/kfence/core.c | 7 +++++--
>  1 file changed, 5 insertions(+), 2 deletions(-)
> 
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 4e7cd4c8e687..4b5e5a3d3a63 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -360,6 +360,9 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
>  	unsigned long flags;
>  	struct slab *slab;
>  	void *addr;
> +	const bool random_right_allocate = prandom_u32_max(2);
> +	const bool random_fault = CONFIG_KFENCE_STRESS_TEST_FAULTS &&
> +				  !prandom_u32_max(CONFIG_KFENCE_STRESS_TEST_FAULTS);
>  
>  	/* Try to obtain a free object. */
>  	raw_spin_lock_irqsave(&kfence_freelist_lock, flags);
> @@ -404,7 +407,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
>  	 * is that the out-of-bounds accesses detected are deterministic for
>  	 * such allocations.
>  	 */
> -	if (prandom_u32_max(2)) {
> +	if (random_right_allocate) {
>  		/* Allocate on the "right" side, re-calculate address. */
>  		meta->addr += PAGE_SIZE - size;
>  		meta->addr = ALIGN_DOWN(meta->addr, cache->align);
> @@ -444,7 +447,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
>  	if (cache->ctor)
>  		cache->ctor(addr);
>  
> -	if (CONFIG_KFENCE_STRESS_TEST_FAULTS && !prandom_u32_max(CONFIG_KFENCE_STRESS_TEST_FAULTS))
> +	if (random_fault)
>  		kfence_protect(meta->addr); /* Random "faults" by protecting the object. */
>  
>  	atomic_long_inc(&counters[KFENCE_COUNTER_ALLOCATED]);
> -- 
> 2.35.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YqHqlC9gvYl2vAiE%40elver.google.com.
