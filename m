Return-Path: <kasan-dev+bncBCKJJ7XLVUBBB2WUSSJQMGQEQPBKH2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 52B6550D139
	for <lists+kasan-dev@lfdr.de>; Sun, 24 Apr 2022 12:46:03 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id k2-20020a0566022a4200b00654c0f121a9sf9334706iov.1
        for <lists+kasan-dev@lfdr.de>; Sun, 24 Apr 2022 03:46:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650797162; cv=pass;
        d=google.com; s=arc-20160816;
        b=CkUFQk1AfAfHuxpwMqhG50jDd0+qal6XN1u6AtevSbCXsJw4tBWaZTpq9M0QeAN/KD
         R8ym3sztOLJXcqog8qPq4iJxzsDpdng2jxFn1g6WsV905uSswKmzW1ykHsHmyy4e9Pag
         /t3vaZW6bqRwPLppy9YSD4K3bYIrXl+m6X6oxnwY6ZyrR9DD8FNt4ue0ELDW55NOudKT
         B9ydheZGbd1jgkPT0H8s4dqHkXVXVkR+nYNraBsAuUp6GSEecPFzJQTi/vlihMaFmG/1
         WeejHaaP5a1kxvWv0+OH0EAO2m/xxx8jKyD7/pugU/j9F3y5RIBM87Oj3ozDxLGIshCv
         nkDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=rb4EnH6KV3ikdDMO73DhVaV4LA8flGsd+QezWhYu8Qg=;
        b=zGDKqkTlfV1JPEuzSth2GtsVGftIomDjSv0tsF4rNlI+szsg8KP4o6uh7qdnbqPPpC
         3ODFoF0ZLE1SzsurhVQCE2OC27FCPwJFF/hCNNikq0daaXop2RRGWLmnDtREWcnO5J8p
         ngHkzosQPKSCPQuBscD3GJ/7PsS6hYZCGSlgINY7AtwSQQ6SYd1c+I0z1oqeoFwj+F1N
         GTVkDkUTvsLpQMZ9+0x85YS7vHgroFUZGd1ukcGt4uplvmgaLcD7qQg4dutwbRrIWh5j
         QKXvv0uD9D2cf4dkkJ6p0S3LpWAXqghK0jGyZ8GyxmGlWO7l5MExc0j0MBCxLi71LlKf
         04HA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=JnZyENfI;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rb4EnH6KV3ikdDMO73DhVaV4LA8flGsd+QezWhYu8Qg=;
        b=HLGh1Wfl4IaupTuxI87L8kdc2JozG1okLponheZnGUTDgIir2+Ec5YyTBxhzP61lza
         DJFKXb5iTX0vxLhE4ea40PpJhp20VvWEw3p+6BqsanrIJdPLyJjRcVILDBpC6FSAc/5o
         En0kkzBKYLRgLYN6/AjkEIUPZ2ifhbgRPK2p/roowZ6RkKUYcVitMeQ4VLp0aewe29N+
         rUz9M9vRTOAXXMuwkgpA+K5iXkQbab69+Gw6nC2f3rYYd9czENBGhFz6RZKZ+Y0Uescx
         GzswNv4fUa/2s6iGKEkUR0hYuo5cld+Vr4MvsX6m6HSNQwMrawNzr26ox7njv+01+6bZ
         BeyA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rb4EnH6KV3ikdDMO73DhVaV4LA8flGsd+QezWhYu8Qg=;
        b=X2Ocd8cSbFNVIZzQ4DboT4gtRtei9lCnVxWdyF83NFNBSv6wAognyZErk5ZQMz5ZcR
         Di6TmN+YyQGCQ2hc1+CMIureMtWJc/3+fqooR31l15ePg44DIVsZtTStfrUV4whJXo3b
         Peg1TnDdqn32vVo2xpt01/teRvvUx3bXKpqGD06DFYO6TPg2Ely6kw8F8KIvHAsqh9M3
         XHmnLrODDgCRbtfo9Hsl0ttUZBh5ctGrAchldil1vdaL/5H00WDEC9POge7F7DG6EZfR
         pzDHELSVHdLsdbitB57XpNYRu+j2kIS8AJO9lPIdBqjrwtD0K1qbn4ttEvFS8kZ65tEF
         mkuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rb4EnH6KV3ikdDMO73DhVaV4LA8flGsd+QezWhYu8Qg=;
        b=tj+xg5vS3YTG1Lrx5j4VhJDiV0v0dV5LfFJH9tt6Q6NK1+JXnHxmh7IKlBmEgTuOXm
         n6FYWK3h54JA58kJnLHlxmV4arQAipHz4SCNLCwCYLeIdGwXIjKXYMl8oPkj85LP3vml
         imJSRn3CIitegNyguLgCprzkxb/A/ln3zjDGN9LCDPGojvI0Xy98jy7MwZ1sgrWHkBwt
         ZyMBBAz+pv4TVGBNxADbXwoP5FVQFoS1+JWidSQBvA0K0moJu3HTgyIX+xNxASon2s5z
         cssjlHlnJCZYaw7J+f+/4V9jBluPxtF1l6AR4SUo0J5JZGVBjk+LT+OV8gK0gdhglo4a
         aiOQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530sJ982Iw3BwYYXUFtoYx4n9uTrSv4uxR0ow0v8PLTt/n7w1Xx/
	I3VAO+2gMavg1yDBmyKlUy4=
X-Google-Smtp-Source: ABdhPJxwK9T1nXcAepTXiU3bfB/dPqWnODxjyZI6Qy8K5tOP4gUx/3BvqohVWlAsE9KizvrbMtdEKw==
X-Received: by 2002:a02:6d1b:0:b0:32a:c918:e0b2 with SMTP id m27-20020a026d1b000000b0032ac918e0b2mr2938353jac.286.1650797162088;
        Sun, 24 Apr 2022 03:46:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1d0b:b0:2cc:2007:baba with SMTP id
 i11-20020a056e021d0b00b002cc2007babals2430963ila.6.gmail; Sun, 24 Apr 2022
 03:46:01 -0700 (PDT)
X-Received: by 2002:a92:d212:0:b0:2cb:7635:9940 with SMTP id y18-20020a92d212000000b002cb76359940mr4856861ily.132.1650797161476;
        Sun, 24 Apr 2022 03:46:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650797161; cv=none;
        d=google.com; s=arc-20160816;
        b=eoIRIyPwqfyiJHG5kxg6dGBM6xvzABoClwyoUqvX01Q/fcfPBZ0LtwM5ROn0twWZQa
         P8H8kzcNhGYux+pY6j55WJyJMU/0NGiGtUAXWaMV0XVrneQm2L1gGtP+4ThMLdQKbExw
         zkyIr3Ec1fI75OHVLv7ot3iqpClD7xaJXCKC7/srv2XDZbPiH7Ex7oHXY4YmmlrwF0PZ
         u5WP+lWXVvk3Mrr/ExD0lrpjIVh+CE5yXuCczBGj6iyn2qMNnJK4LAAg/UfPp69/PcIN
         H1abfnbmEUvPUBIwhelNpuaJGU3LqSXS5l6YD1EQH3L6ZC1N23wJ2sXmduJStDr3XvXF
         Ltjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=csRs3fmQd457QlO7dqPrYTB82Qqq+2T7nWfwhT2jUys=;
        b=Wg1Cxi5LB80tUiT03fiz22wK0E0aV/TbPmreT54YdpuLv02G7GH/kS5VcJiF8YX4Ha
         vVQRIcknA203BXvejL8G48sh2qHwvBp+GsyfZdnZ6wjSjxzRCJOrcKqVbO6mD2ntWW1f
         zSyT6qj1ehPKB8b0/jcEbuEnPTLvgd05OrQxxlD61Sjq+D+vjFqjSMHAO/kC2mKU7XU3
         Y8UvPVuRJULf+VSE/OGX5PkDp08eyLcxRfl81lo33UFaT4IV63v76mRtQV1JYKXRKn+A
         i3cDGvkin9i/S2YTLNXOPzaGLozR6Uhm9jdfl4BcuIfiU1OY4b/lCrNQQkrmQEHj5+1c
         oxig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=JnZyENfI;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x629.google.com (mail-pl1-x629.google.com. [2607:f8b0:4864:20::629])
        by gmr-mx.google.com with ESMTPS id s11-20020a5d928b000000b0064cedb07afcsi1213691iom.3.2022.04.24.03.46.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 24 Apr 2022 03:46:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::629 as permitted sender) client-ip=2607:f8b0:4864:20::629;
Received: by mail-pl1-x629.google.com with SMTP id u7so5430444plg.13
        for <kasan-dev@googlegroups.com>; Sun, 24 Apr 2022 03:46:01 -0700 (PDT)
X-Received: by 2002:a17:90b:2690:b0:1d9:73e3:af18 with SMTP id pl16-20020a17090b269000b001d973e3af18mr55696pjb.213.1650797160848;
        Sun, 24 Apr 2022 03:46:00 -0700 (PDT)
Received: from hyeyoo ([114.29.24.243])
        by smtp.gmail.com with ESMTPSA id z7-20020a056a00240700b004e1cde37bc1sm8305307pfh.84.2022.04.24.03.45.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 24 Apr 2022 03:45:58 -0700 (PDT)
Date: Sun, 24 Apr 2022 19:45:50 +0900
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	vbabka@suse.cz, penberg@kernel.org, roman.gushchin@linux.dev,
	iamjoonsoo.kim@lge.com, rientjes@google.com,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Eric Biederman <ebiederm@xmission.com>,
	Kees Cook <keescook@chromium.org>
Subject: Re: [PATCH v3] mm: make minimum slab alignment a runtime property
Message-ID: <YmUqXi5+53wDifKS@hyeyoo>
References: <20220422201830.288018-1-pcc@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220422201830.288018-1-pcc@google.com>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=JnZyENfI;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::629
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Apr 22, 2022 at 01:18:30PM -0700, Peter Collingbourne wrote:
> When CONFIG_KASAN_HW_TAGS is enabled we currently increase the minimum
> slab alignment to 16. This happens even if MTE is not supported in
> hardware or disabled via kasan=off, which creates an unnecessary
> memory overhead in those cases. Eliminate this overhead by making
> the minimum slab alignment a runtime property and only aligning to
> 16 if KASAN is enabled at runtime.
> 
> On a DragonBoard 845c (non-MTE hardware) with a kernel built with
> CONFIG_KASAN_HW_TAGS, waiting for quiescence after a full Android
> boot I see the following Slab measurements in /proc/meminfo (median
> of 3 reboots):
> 
> Before: 169020 kB
> After:  167304 kB
> 
> Link: https://linux-review.googlesource.com/id/I752e725179b43b144153f4b6f584ceb646473ead
> Signed-off-by: Peter Collingbourne <pcc@google.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
> ---
> v3:
> - go back to ARCH_SLAB_MINALIGN
> - revert changes to fs/binfmt_flat.c
> - update arch_slab_minalign() comment to say that it must be a power of two
> 
> v2:
> - use max instead of max_t in flat_stack_align()
> 
>  arch/arm64/include/asm/cache.h | 17 ++++++++++++-----
>  include/linux/slab.h           | 12 ++++++++++++
>  mm/slab.c                      |  7 +++----
>  mm/slab_common.c               |  3 +--
>  mm/slob.c                      |  6 +++---
>  5 files changed, 31 insertions(+), 14 deletions(-)
> 
> diff --git a/arch/arm64/include/asm/cache.h b/arch/arm64/include/asm/cache.h
> index a074459f8f2f..22b22dc1b1b5 100644
> --- a/arch/arm64/include/asm/cache.h
> +++ b/arch/arm64/include/asm/cache.h
> @@ -6,6 +6,7 @@
>  #define __ASM_CACHE_H
>  
>  #include <asm/cputype.h>
> +#include <asm/mte-def.h>
>  
>  #define CTR_L1IP_SHIFT		14
>  #define CTR_L1IP_MASK		3
> @@ -49,16 +50,22 @@
>   */
>  #define ARCH_DMA_MINALIGN	(128)
>  
> +#ifndef __ASSEMBLY__
> +
> +#include <linux/bitops.h>
> +#include <linux/kasan-enabled.h>
> +
>  #ifdef CONFIG_KASAN_SW_TAGS
>  #define ARCH_SLAB_MINALIGN	(1ULL << KASAN_SHADOW_SCALE_SHIFT)
>  #elif defined(CONFIG_KASAN_HW_TAGS)
> -#define ARCH_SLAB_MINALIGN	MTE_GRANULE_SIZE
> +static inline size_t arch_slab_minalign(void)
> +{
> +	return kasan_hw_tags_enabled() ? MTE_GRANULE_SIZE :
> +					 __alignof__(unsigned long long);
> +}
> +#define arch_slab_minalign() arch_slab_minalign()
>  #endif
>  
> -#ifndef __ASSEMBLY__
> -
> -#include <linux/bitops.h>
> -
>  #define ICACHEF_ALIASING	0
>  #define ICACHEF_VPIPT		1
>  extern unsigned long __icache_flags;
> diff --git a/include/linux/slab.h b/include/linux/slab.h
> index 373b3ef99f4e..2c7190db4cc0 100644
> --- a/include/linux/slab.h
> +++ b/include/linux/slab.h
> @@ -209,6 +209,18 @@ void kmem_dump_obj(void *object);
>  #define ARCH_SLAB_MINALIGN __alignof__(unsigned long long)
>  #endif
>  
> +/*
> + * Arches can define this function if they want to decide the minimum slab
> + * alignment at runtime. The value returned by the function must be a power
> + * of two and >= ARCH_SLAB_MINALIGN.
> + */
> +#ifndef arch_slab_minalign
> +static inline size_t arch_slab_minalign(void)
> +{
> +	return ARCH_SLAB_MINALIGN;
> +}
> +#endif
> +
>  /*
>   * kmalloc and friends return ARCH_KMALLOC_MINALIGN aligned
>   * pointers. kmem_cache_alloc and friends return ARCH_SLAB_MINALIGN
> diff --git a/mm/slab.c b/mm/slab.c
> index 0edb474edef1..97b756976c8b 100644
> --- a/mm/slab.c
> +++ b/mm/slab.c
> @@ -3009,10 +3009,9 @@ static void *cache_alloc_debugcheck_after(struct kmem_cache *cachep,
>  	objp += obj_offset(cachep);
>  	if (cachep->ctor && cachep->flags & SLAB_POISON)
>  		cachep->ctor(objp);
> -	if (ARCH_SLAB_MINALIGN &&
> -	    ((unsigned long)objp & (ARCH_SLAB_MINALIGN-1))) {
> -		pr_err("0x%px: not aligned to ARCH_SLAB_MINALIGN=%d\n",
> -		       objp, (int)ARCH_SLAB_MINALIGN);
> +	if ((unsigned long)objp & (arch_slab_minalign() - 1)) {
> +		pr_err("0x%px: not aligned to arch_slab_minalign()=%d\n", objp,
> +		       (int)arch_slab_minalign());
>  	}
>  	return objp;
>  }
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 2b3206a2c3b5..33cc49810a54 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -154,8 +154,7 @@ static unsigned int calculate_alignment(slab_flags_t flags,
>  		align = max(align, ralign);
>  	}
>  
> -	if (align < ARCH_SLAB_MINALIGN)
> -		align = ARCH_SLAB_MINALIGN;
> +	align = max_t(size_t, align, arch_slab_minalign());
>  
>  	return ALIGN(align, sizeof(void *));
>  }
> diff --git a/mm/slob.c b/mm/slob.c
> index 40ea6e2d4ccd..3bd2669bd690 100644
> --- a/mm/slob.c
> +++ b/mm/slob.c
> @@ -478,7 +478,7 @@ static __always_inline void *
>  __do_kmalloc_node(size_t size, gfp_t gfp, int node, unsigned long caller)
>  {
>  	unsigned int *m;
> -	int minalign = max_t(size_t, ARCH_KMALLOC_MINALIGN, ARCH_SLAB_MINALIGN);
> +	int minalign = max_t(size_t, ARCH_KMALLOC_MINALIGN, arch_slab_minalign());
>  	void *ret;
>  
>  	gfp &= gfp_allowed_mask;
> @@ -555,7 +555,7 @@ void kfree(const void *block)
>  
>  	sp = virt_to_folio(block);
>  	if (folio_test_slab(sp)) {
> -		int align = max_t(size_t, ARCH_KMALLOC_MINALIGN, ARCH_SLAB_MINALIGN);
> +		int align = max_t(size_t, ARCH_KMALLOC_MINALIGN, arch_slab_minalign());
>  		unsigned int *m = (unsigned int *)(block - align);
>  		slob_free(m, *m + align);
>  	} else {
> @@ -584,7 +584,7 @@ size_t __ksize(const void *block)
>  	if (unlikely(!folio_test_slab(folio)))
>  		return folio_size(folio);
>  
> -	align = max_t(size_t, ARCH_KMALLOC_MINALIGN, ARCH_SLAB_MINALIGN);
> +	align = max_t(size_t, ARCH_KMALLOC_MINALIGN, arch_slab_minalign());
>  	m = (unsigned int *)(block - align);
>  	return SLOB_UNITS(*m) * SLOB_UNIT;
>  }
> -- 
> 2.36.0.rc2.479.g8af0fa9b8e-goog
> 

Looks good to me.
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

And work properly on my arm64 machine (no MTE support)
Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

Thanks!

-- 
Thanks,
Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YmUqXi5%2B53wDifKS%40hyeyoo.
