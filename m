Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBUU4QWJQMGQE4GA364A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B13A509FAC
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 14:30:12 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id q5-20020a0566022f0500b00654a56b1dfbsf3187675iow.8
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 05:30:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650544211; cv=pass;
        d=google.com; s=arc-20160816;
        b=yy60wsSVGPP5Dgd0Ea18Z6o0zOwH/Y2tA2vElCKRehl2dwq1GkYdA9JzaI6ZkiOKQc
         Nb3WfXnIgAN37TLMHHp21Te98X86tj9UqD+9H48SHkCn71n4GVC83TjilsVVOExDmOZP
         Fp24pBLXWOvAFtGYdgzDZqZe1PQT7I0ukeThp1CTtVt7raQ6YG7J+dHkDkTyMqQSpQvy
         v61L662JrxIp0axnKvS84dGaI7CxTW8VHGZH2R1RypQhyPseicOlLGV9cvQbxG3rgZF0
         ZTncNs/A4YgSJXKsQL35HtH8imEI6pnNZ1HVq4tFwNHQn3FeKp4bhTpG7q5ANEbdv8MJ
         j0PQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=KXYdRFfjkMe+QlH+FsUyUQIPmP5MzyTGWGTei/7D9JM=;
        b=k/ymWgY01Uv2IgEURELd76G7Aj/ZKy/8fuRdCOaem0sXv8XSTqLs2aQH8eNr1m8MwI
         ELL7NbLGKmv7tdCBbhqP6saxUOvfh8JhD4e4Ldf/4kTKRtwm0qwXDYp4NEk4aS8I7NvD
         TOo4gLe4oUbcmAA5D84YHX6gkKgXamfhAmr+aARFGcaB4HbpYq3t6AftqppyzQEMjLJ5
         CIjmSz8X7KBUWrVEeLJK3Le8ODU+Vo23valT9WvTxYfxoYFY9PdbiNLxbZHpT9dTEsXy
         p0qUdIy2slz3Vw44vofvrmbgOJijrtUL3LU+5hYMAPVA4HxKWWppK1EpXSmuz90AlBkb
         qh6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=omd3y+6m;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KXYdRFfjkMe+QlH+FsUyUQIPmP5MzyTGWGTei/7D9JM=;
        b=Lpxxy5O/gFrnv2hY/tPAUAb0G3aGDp4NV2bemwZBwmE0eECUBmC3GRzthtn5YvQFbL
         d81Nhx9V8cYqyXpkxle8TY1mM21gtT/85UTMHqbpFMNPcqIAmNFA8ohAzYOSYuKC4hrA
         wa3OBUo8XCOYwtuRME+n6Mbtt02l7hjSWBAxYRig5bk/7a+woiQlQh1ji4x/bWchHNmh
         C8rYyg1J5B+sIecGRzFwg6pUhW4vznlLLMnWAivK023kY/Gu7T7LrHUXijmwCQvCgMpG
         Lzdb3TUR5ABwFQJurD1gGr9FR6Tp2v5vAYW0yFqaX/A7DM+2EEN0CSlDGreIoic/B6kT
         Z9PA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KXYdRFfjkMe+QlH+FsUyUQIPmP5MzyTGWGTei/7D9JM=;
        b=kvIWlcx45WjVR6Op2Fc0tEj3iJtHJaemT/8nE02zN4mNf+MBlbNe1ZAl8cub1ExVjO
         r5EgTzgEoz0sOOtKLT2bWdEFlnPG4idiPPqIdeWUmJwXNkv65Lv/Ki8pdD3zVnum6XCl
         xTDq+IieTN1JukiG/m+aM1xzndueSb+t/jGy+YF31JOX1zYCDKO7jBbDallz89aI/VG1
         cq9q+as2HniCukRGWMtpXJouxpWVuTo6FDMMjfuEfjjtc9iaklVkIqG9G7J4l9T+Zi4N
         JJ9b7B5DGOv+u1Sr+Vg/A52aqtRBZq9xmL74PNC9ALUKWhUwCbadmacrwJSTwoWHg3S4
         Q8sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KXYdRFfjkMe+QlH+FsUyUQIPmP5MzyTGWGTei/7D9JM=;
        b=EKrYtK7QhMyXeSfNJBClJZh4QpsJmmu+TnEn0g3m1KWdg56zszNWvZS7m2j3S5rjMq
         xervDuyno8NHJQdlhlg5t6cdSpvHJlnsKZtf+N934lEG+fxroDMcGtnCIfcCprtc8LQl
         qrr3cWyVaJgPCrJOnwJ6dLumnLTLUPR0a3QugsE5xOpcLYBUq0tc8QQRMI+qwEoy4B8C
         KXM0y0Pgn7YxiFmInDyIqBoP8AG9b8XKP2YZQTg66wQ7TfKGJ8KLUgFRG/oYZppCMCCC
         QHZQ5LEDp83BGPO0miOzNibJA9/hPV8c1u3Y072iUSsDcCEtffFQ1jqMHAAIyRmKTF4I
         9b3Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533xNln1e0PAnCzY843Xgveo2U2WOmvBeADfWjqA/SxG1T0n2nh0
	DjfawQG4pf3sOnF2wJj5mVg=
X-Google-Smtp-Source: ABdhPJyU13mvIRWMyO/g468oM6GSIcv+UdTMkyVIPcfAQ7se2Gm6PQz6/w5EaTeFo/GU4CgWj5is5A==
X-Received: by 2002:a05:6602:2d0d:b0:654:b31f:2585 with SMTP id c13-20020a0566022d0d00b00654b31f2585mr6451856iow.104.1650544210995;
        Thu, 21 Apr 2022 05:30:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:ca4a:0:b0:2cc:2449:1fe2 with SMTP id q10-20020a92ca4a000000b002cc24491fe2ls703085ilo.0.gmail;
 Thu, 21 Apr 2022 05:30:09 -0700 (PDT)
X-Received: by 2002:a05:6e02:194e:b0:2cc:4e4c:fc9a with SMTP id x14-20020a056e02194e00b002cc4e4cfc9amr5062764ilu.178.1650544209723;
        Thu, 21 Apr 2022 05:30:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650544209; cv=none;
        d=google.com; s=arc-20160816;
        b=bbtXA3y+yPxF/gobKwE+u2Ta3/7ab3hUi+9MwD3LmV8k3LRICq0w+Ujz4QrKCUoyr8
         kXkoh/aHKdTIhVE53yAYqekBdMTi5HtxtC4LqGEToONRWmkdKyUAKfKRx1UfJDzaV4Mb
         iS+lxFa3efsmAnXl5tDW5jzkMIR/pxfA1xMoIc3plndnXAS8Vd+NkaxW2VNQ/Y6WVFdX
         T7y259+GWeZZAdpuqkEVWjXsOA4lG6RxSIO4KTbYSWcHIlD7BUn0TEJtyc+R2WN1CzVn
         cMQ1hsZ49alnOi1hiP9kxSmod0Z5SXc6JLjGVv8yBCTXgyP8BGw4VPJwDEgE/4B93Z19
         z3bw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=OT2aW10PJgZ40KFWgNO7vzgAZM1fsO2q4Q/P9UtJWtw=;
        b=y8Lfbo9uVLvZeLvRpT0EI/l2eYe/Kgs3jYNNVEI9lU0+A5PE6tkMRZklD4V69vk6KJ
         BsT86Zo/Tv6ctAdRqzC9+4UejEa4Gkommv2ZbeJghd/7YMmD7ISJrSkNPK6GuioGK71S
         kDzjKTUDQiwgeXmmDvsljDJrbdyqFl2kGnSGd+p2ZqzE/rDWimUdQR2zQMd0AStYgRjy
         cb4FIzTtFkbY2lmqAUGg1W1CYO3MuJHoIMg5u9xtELMyLkR9cd9lStB8fhUvxYV6KI19
         ic3fbjFlRAmVO34tTWm34yBjj/PYww2pGPRT/LFv5DhdF02CGiiTUqk/dEJNco1Em86e
         p7ow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=omd3y+6m;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x52f.google.com (mail-pg1-x52f.google.com. [2607:f8b0:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id f15-20020a056e020b4f00b002ca3e929b6csi374086ilu.2.2022.04.21.05.30.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Apr 2022 05:30:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) client-ip=2607:f8b0:4864:20::52f;
Received: by mail-pg1-x52f.google.com with SMTP id g3so3894291pgg.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Apr 2022 05:30:09 -0700 (PDT)
X-Received: by 2002:a63:2b0b:0:b0:39d:890a:ab68 with SMTP id r11-20020a632b0b000000b0039d890aab68mr23558186pgr.247.1650544208210;
        Thu, 21 Apr 2022 05:30:08 -0700 (PDT)
Received: from hyeyoo ([114.29.24.243])
        by smtp.gmail.com with ESMTPSA id w4-20020a056a0014c400b004fb0c7b3813sm24338190pfu.134.2022.04.21.05.30.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Apr 2022 05:30:06 -0700 (PDT)
Date: Thu, 21 Apr 2022 21:29:57 +0900
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, vbabka@suse.cz, penberg@kernel.org,
	cl@linux.org, roman.gushchin@linux.dev, iamjoonsoo.kim@lge.com,
	rientjes@google.com, Catalin Marinas <catalin.marinas@arm.com>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Eric Biederman <ebiederm@xmission.com>,
	Kees Cook <keescook@chromium.org>
Subject: Re: [PATCH] mm: make minimum slab alignment a runtime property
Message-ID: <YmFORWyMAVacycu5@hyeyoo>
References: <20220421031738.3168157-1-pcc@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220421031738.3168157-1-pcc@google.com>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=omd3y+6m;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::52f
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

On Wed, Apr 20, 2022 at 08:17:38PM -0700, Peter Collingbourne wrote:
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
> ---
>  arch/arc/include/asm/cache.h        |  4 ++--
>  arch/arm/include/asm/cache.h        |  2 +-
>  arch/arm64/include/asm/cache.h      | 19 +++++++++++++------
>  arch/microblaze/include/asm/page.h  |  2 +-
>  arch/riscv/include/asm/cache.h      |  2 +-
>  arch/sparc/include/asm/cache.h      |  2 +-
>  arch/xtensa/include/asm/processor.h |  2 +-
>  fs/binfmt_flat.c                    |  9 ++++++---
>  include/crypto/hash.h               |  2 +-
>  include/linux/slab.h                | 22 +++++++++++++++++-----
>  mm/slab.c                           |  7 +++----
>  mm/slab_common.c                    |  3 +--
>  mm/slob.c                           |  6 +++---
>  13 files changed, 51 insertions(+), 31 deletions(-)

[+Cc slab people, Catalin and affected subsystems' folks]

just FYI, There is similar discussion about kmalloc caches' alignment.
https://lore.kernel.org/linux-mm/20220405135758.774016-1-catalin.marinas@arm.com/

It seems this is another demand for runtime resolution of slab
alignment, But slightly different from kmalloc as there is no requirement
for DMA alignment.

> 
> diff --git a/arch/arc/include/asm/cache.h b/arch/arc/include/asm/cache.h
> index f0f1fc5d62b6..b6a7763fd5d6 100644
> --- a/arch/arc/include/asm/cache.h
> +++ b/arch/arc/include/asm/cache.h
> @@ -55,11 +55,11 @@
>   * Make sure slab-allocated buffers are 64-bit aligned when atomic64_t uses
>   * ARCv2 64-bit atomics (LLOCKD/SCONDD). This guarantess runtime 64-bit
>   * alignment for any atomic64_t embedded in buffer.
> - * Default ARCH_SLAB_MINALIGN is __alignof__(long long) which has a relaxed
> + * Default ARCH_SLAB_MIN_MINALIGN is __alignof__(long long) which has a relaxed
>   * value of 4 (and not 8) in ARC ABI.
>   */
>  #if defined(CONFIG_ARC_HAS_LL64) && defined(CONFIG_ARC_HAS_LLSC)
> -#define ARCH_SLAB_MINALIGN	8
> +#define ARCH_SLAB_MIN_MINALIGN	8
>  #endif
> 

Why isn't it just ARCH_SLAB_MINALIGN?

>  extern int ioc_enable;
> diff --git a/arch/arm/include/asm/cache.h b/arch/arm/include/asm/cache.h
> index e3ea34558ada..3e1018bb9805 100644
> --- a/arch/arm/include/asm/cache.h
> +++ b/arch/arm/include/asm/cache.h
> @@ -21,7 +21,7 @@
>   * With EABI on ARMv5 and above we must have 64-bit aligned slab pointers.
>   */
>  #if defined(CONFIG_AEABI) && (__LINUX_ARM_ARCH__ >= 5)
> -#define ARCH_SLAB_MINALIGN 8
> +#define ARCH_SLAB_MIN_MINALIGN 8
>  #endif
>  
>  #define __read_mostly __section(".data..read_mostly")
> diff --git a/arch/arm64/include/asm/cache.h b/arch/arm64/include/asm/cache.h
> index a074459f8f2f..38f171591c3f 100644
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
> @@ -49,15 +50,21 @@
>   */
>  #define ARCH_DMA_MINALIGN	(128)
>  
> -#ifdef CONFIG_KASAN_SW_TAGS
> -#define ARCH_SLAB_MINALIGN	(1ULL << KASAN_SHADOW_SCALE_SHIFT)
> -#elif defined(CONFIG_KASAN_HW_TAGS)
> -#define ARCH_SLAB_MINALIGN	MTE_GRANULE_SIZE
> -#endif
> -
>  #ifndef __ASSEMBLY__
>  
>  #include <linux/bitops.h>
> +#include <linux/kasan-enabled.h>
> +
> +#ifdef CONFIG_KASAN_SW_TAGS
> +#define ARCH_SLAB_MIN_MINALIGN	(1ULL << KASAN_SHADOW_SCALE_SHIFT)
> +#elif defined(CONFIG_KASAN_HW_TAGS)
> +static inline size_t arch_slab_minalign(void)
> +{
> +	return kasan_hw_tags_enabled() ? MTE_GRANULE_SIZE :
> +					 __alignof__(unsigned long long);
> +}
> +#define arch_slab_minalign() arch_slab_minalign()
> +#endif
>

kasan_hw_tags_enabled() is also false when kasan is just not initialized yet.
What about writing a new helper something like kasan_is_disabled()
instead?

>  #define ICACHEF_ALIASING	0
>  #define ICACHEF_VPIPT		1
> diff --git a/arch/microblaze/include/asm/page.h b/arch/microblaze/include/asm/page.h
> index 4b8b2fa78fc5..ccdbc1da3c3e 100644
> --- a/arch/microblaze/include/asm/page.h
> +++ b/arch/microblaze/include/asm/page.h
> @@ -33,7 +33,7 @@
>  /* MS be sure that SLAB allocates aligned objects */
>  #define ARCH_DMA_MINALIGN	L1_CACHE_BYTES
>  
> -#define ARCH_SLAB_MINALIGN	L1_CACHE_BYTES
> +#define ARCH_SLAB_MIN_MINALIGN	L1_CACHE_BYTES
>  
>  /*
>   * PAGE_OFFSET -- the first address of the first page of memory. With MMU
> diff --git a/arch/riscv/include/asm/cache.h b/arch/riscv/include/asm/cache.h
> index 9b58b104559e..7beb3b5d27c7 100644
> --- a/arch/riscv/include/asm/cache.h
> +++ b/arch/riscv/include/asm/cache.h
> @@ -16,7 +16,7 @@
>   * the flat loader aligns it accordingly.
>   */
>  #ifndef CONFIG_MMU
> -#define ARCH_SLAB_MINALIGN	16
> +#define ARCH_SLAB_MIN_MINALIGN	16
>  #endif
>  
>  #endif /* _ASM_RISCV_CACHE_H */
> diff --git a/arch/sparc/include/asm/cache.h b/arch/sparc/include/asm/cache.h
> index e62fd0e72606..9d8cb4687b7e 100644
> --- a/arch/sparc/include/asm/cache.h
> +++ b/arch/sparc/include/asm/cache.h
> @@ -8,7 +8,7 @@
>  #ifndef _SPARC_CACHE_H
>  #define _SPARC_CACHE_H
>  
> -#define ARCH_SLAB_MINALIGN	__alignof__(unsigned long long)
> +#define ARCH_SLAB_MIN_MINALIGN	__alignof__(unsigned long long)
>  
>  #define L1_CACHE_SHIFT 5
>  #define L1_CACHE_BYTES 32
> diff --git a/arch/xtensa/include/asm/processor.h b/arch/xtensa/include/asm/processor.h
> index 4489a27d527a..e3ea278e3fcf 100644
> --- a/arch/xtensa/include/asm/processor.h
> +++ b/arch/xtensa/include/asm/processor.h
> @@ -18,7 +18,7 @@
>  #include <asm/types.h>
>  #include <asm/regs.h>
>  
> -#define ARCH_SLAB_MINALIGN XTENSA_STACK_ALIGNMENT
> +#define ARCH_SLAB_MIN_MINALIGN XTENSA_STACK_ALIGNMENT
>  
>  /*
>   * User space process size: 1 GB.
> diff --git a/fs/binfmt_flat.c b/fs/binfmt_flat.c
> index 626898150011..8ff1bf7d1e87 100644
> --- a/fs/binfmt_flat.c
> +++ b/fs/binfmt_flat.c
> @@ -64,7 +64,10 @@
>   * Here we can be a bit looser than the data sections since this
>   * needs to only meet arch ABI requirements.
>   */
> -#define FLAT_STACK_ALIGN	max_t(unsigned long, sizeof(void *), ARCH_SLAB_MINALIGN)
> +static size_t flat_stack_align(void)
> +{
> +	return max_t(unsigned long, sizeof(void *), arch_slab_minalign());
> +}
>  
>  #define RELOC_FAILED 0xff00ff01		/* Relocation incorrect somewhere */
>  #define UNLOADED_LIB 0x7ff000ff		/* Placeholder for unused library */
> @@ -148,7 +151,7 @@ static int create_flat_tables(struct linux_binprm *bprm, unsigned long arg_start
>  		sp -= 2; /* argvp + envp */
>  	sp -= 1;  /* &argc */
>  
> -	current->mm->start_stack = (unsigned long)sp & -FLAT_STACK_ALIGN;
> +	current->mm->start_stack = (unsigned long)sp & -flat_stack_align();
>  	sp = (unsigned long __user *)current->mm->start_stack;
>  
>  	if (put_user(bprm->argc, sp++))
> @@ -966,7 +969,7 @@ static int load_flat_binary(struct linux_binprm *bprm)
>  #endif
>  	stack_len += (bprm->argc + 1) * sizeof(char *);   /* the argv array */
>  	stack_len += (bprm->envc + 1) * sizeof(char *);   /* the envp array */
> -	stack_len = ALIGN(stack_len, FLAT_STACK_ALIGN);
> +	stack_len = ALIGN(stack_len, flat_stack_align());
>  
>  	res = load_flat_file(bprm, &libinfo, 0, &stack_len);
>  	if (res < 0)
> diff --git a/include/crypto/hash.h b/include/crypto/hash.h
> index f140e4643949..442c290f458c 100644
> --- a/include/crypto/hash.h
> +++ b/include/crypto/hash.h
> @@ -149,7 +149,7 @@ struct ahash_alg {
>  
>  struct shash_desc {
>  	struct crypto_shash *tfm;
> -	void *__ctx[] __aligned(ARCH_SLAB_MINALIGN);
> +	void *__ctx[] __aligned(ARCH_SLAB_MIN_MINALIGN);
>  };
>  
>  #define HASH_MAX_DIGESTSIZE	 64
> diff --git a/include/linux/slab.h b/include/linux/slab.h
> index 373b3ef99f4e..80e517593372 100644
> --- a/include/linux/slab.h
> +++ b/include/linux/slab.h
> @@ -201,21 +201,33 @@ void kmem_dump_obj(void *object);
>  #endif
>  
>  /*
> - * Setting ARCH_SLAB_MINALIGN in arch headers allows a different alignment.
> + * Setting ARCH_SLAB_MIN_MINALIGN in arch headers allows a different alignment.
>   * Intended for arches that get misalignment faults even for 64 bit integer
>   * aligned buffers.
>   */
> -#ifndef ARCH_SLAB_MINALIGN
> -#define ARCH_SLAB_MINALIGN __alignof__(unsigned long long)
> +#ifndef ARCH_SLAB_MIN_MINALIGN
> +#define ARCH_SLAB_MIN_MINALIGN __alignof__(unsigned long long)
> +#endif
> +
> +/*
> + * Arches can define this function if they want to decide the minimum slab
> + * alignment at runtime. The value returned by the function must be
> + * >= ARCH_SLAB_MIN_MINALIGN.
> + */

Not only the value should be bigger than or equal to ARCH_SLAB_MIN_MINALIGN,
it should be compatible with ARCH_SLAB_MIN_MINALIGN.

> +#ifndef arch_slab_minalign
> +static inline size_t arch_slab_minalign(void)
> +{
> +	return ARCH_SLAB_MIN_MINALIGN;
> +}
>  #endif
>  
>  /*
>   * kmalloc and friends return ARCH_KMALLOC_MINALIGN aligned
> - * pointers. kmem_cache_alloc and friends return ARCH_SLAB_MINALIGN
> + * pointers. kmem_cache_alloc and friends return ARCH_SLAB_MIN_MINALIGN
>   * aligned pointers.
>   */
>  #define __assume_kmalloc_alignment __assume_aligned(ARCH_KMALLOC_MINALIGN)
> -#define __assume_slab_alignment __assume_aligned(ARCH_SLAB_MINALIGN)
> +#define __assume_slab_alignment __assume_aligned(ARCH_SLAB_MIN_MINALIGN)
>  #define __assume_page_alignment __assume_aligned(PAGE_SIZE)
>  
>  /*
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
> 2.36.0.rc0.470.gd361397f0d-goog
> 
> 

-- 
Thanks,
Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YmFORWyMAVacycu5%40hyeyoo.
