Return-Path: <kasan-dev+bncBC7OBJGL2MHBBC75U2QAMGQE5Z7QANQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 185146B2253
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Mar 2023 12:10:05 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id k23-20020a5e8917000000b0074cbfb58b5bsf674898ioj.14
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Mar 2023 03:10:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678360203; cv=pass;
        d=google.com; s=arc-20160816;
        b=A0GvAjhZ3FagB/sSnlQJsTo2Z4z3uZxIjxJ0K16siFk4EBgB7gX588GuM6SqUOsKSV
         lPFGP9V3rtE0vX3+e6SI9C0SHfWNBdT1VXPyLCgYbuWY4T8DsS9CMy/bP1DpZFJF9q3l
         d6XK4BcB3QspulRYV+T7bCQvnNGkgEVcZiehVVqqwhHeCY5I3aK+lAkFAVG04nhH4Af2
         TFrDiFKfweaC1bxwyxwUAQfnb4N7rZXgwYiwTcS065S62srAZpK/WV/xreeE6s62Ulbc
         r/Jsc2o5TLGeUPJdzaN88Fug2FN7fWlloUw/zFbopsLin04E1NJRoifx2RpqGnMyNGY7
         SEgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vIjMhxflq082yMW+OnlplDTv8LsZ2oLGnNgtMbjweUs=;
        b=Gem38u9TIIq9/nN5gbgW+W5FDXd+1PSGV1x+4VifWNjXjMKG0bO+X7T/b+3HSVCBzG
         XzDr8iVFD2soiMUCOlWZoeqf5t6h83JGgGS/1AmWZr015i1xFhcXpsD6OavCfIA8/yOV
         EtgoMcNSps9apL3uXu24/9bTGXHPCNd9BYOKpOIyxx+/ogBYvPLThrvr0UCeFbYcqkGH
         /CC1oNF3ZQ2KnedjGZCu3WjLnBSk62ISYUBzLJq9gd4sKdvaIpm7dj1MT0tiGxg2ZLWl
         885c781vGBAtPFlkkuFlYRUZGkDvNXrEXJTR9Dg5s62tiT5dQYY5cC0JbDbSYIqxziJM
         ilbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Tbn0PJXv;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678360203;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vIjMhxflq082yMW+OnlplDTv8LsZ2oLGnNgtMbjweUs=;
        b=QZKgjh4g9oPkf8ZE/rU3qo+b0vZJNiuAcjpWUQMrR/bv1yFc1EhGFirCIpFzrCsbrk
         uaoYhpp80COMzuTAhkGfwS7Gr/FdRPvtxAg6ym21e27APijiJZeJg9owfa3g/mXI92Li
         6ubWm1TlW56ZwL3S/yflXolj0pdKwB8POf8Z2KrhS9YoRjTD5VcT0/h1oYoVrSiV0wQj
         OWETdfoMr771k/tMO/bCD/X6RPfCTM1LQ7L7JmFDnVquqOdLKgR7uVoHRQdk2KMGE0rN
         fTh669YxLumYYfBoiGBCDfWCh+DcJBUsPAYjrq3Idg70Un4i6ZGSDFrEBeca9D6OeZjE
         j4Kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678360203;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=vIjMhxflq082yMW+OnlplDTv8LsZ2oLGnNgtMbjweUs=;
        b=Z4dz/6i13DqhACRXeubFzRmg8V3AeCvC3mlsJaQaj7RkAcN+jJzpj0oKt3wPWDjpwK
         q9Ti+fI0xeO3DssegdLwsxtOathnMBrC1fxfOzVW5SY0jKZole4PoOClMYd6hx2hmuXT
         IEzfKH26xENoFGloAsT8EJkhylne7sxeTi3h17tC1ar5krz4vkWRN09u8tBoF/OH6Eeh
         KkZGTthCJ8Ee7EMwg7QmK/4LVX86Ntdny9CUxnM80nCNaY+PSn31Zek2vlouMdKrj75D
         zyEa/edVgHFI3V4dxdT+qDQdGna5EGZRy31qcQQkFGCsW+0r8L2vMv9g48jp89Wx6IY+
         s7Dw==
X-Gm-Message-State: AO0yUKWXut01QT+AXz7SkduQJBEwNrSMCLw2darS7tINYFVUfIVUvYlC
	o9P0Q85StHId/qtVwwBM/vA=
X-Google-Smtp-Source: AK7set+zsyFs9fUHWgYyHww7ytww8Na3uXB4K6drWXN6NfuWUb4ahm3afm+j4aK39sgMr/rijSezcg==
X-Received: by 2002:a5d:97d1:0:b0:745:6c2f:61dd with SMTP id k17-20020a5d97d1000000b007456c2f61ddmr9971247ios.2.1678360203654;
        Thu, 09 Mar 2023 03:10:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d305:0:b0:317:96aa:2fb8 with SMTP id x5-20020a92d305000000b0031796aa2fb8ls369539ila.11.-pod-prod-gmail;
 Thu, 09 Mar 2023 03:10:03 -0800 (PST)
X-Received: by 2002:a05:6e02:1b87:b0:315:7004:3e6c with SMTP id h7-20020a056e021b8700b0031570043e6cmr17145487ili.23.1678360202969;
        Thu, 09 Mar 2023 03:10:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678360202; cv=none;
        d=google.com; s=arc-20160816;
        b=nhSshSUH11nFdv77r3skQIuqKaMcdpeX9cusap1ikjHoZ7xniGohpvsLXko0imaGPi
         VPdUHljYm4aCiow8f1DssDRA4Y/cSmqkENNXlQHrW4AiaOXVFAVL/VU2NWOukSY+yCcx
         4Dx+XloxZrJlIhLzlGBLsqjMv3QOW6I2yWeQ7eYUKdJXjgHgCoy8GFbgs6H4KPOBPTha
         SnkEy3I7mvhT61pHYKaJPbDssvISgp8UCNdy91vx3HLbLxHKVhi2liP7gdpuWYFKloH6
         zJ7xT1UIZ2LBYnv5riyloTf1LYuZvB617oVjtIx+Q2UhQeEiTnIaczXU0a/1oCNct6NU
         pF/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sHADsOZhE0a7TvE3AcZTPLBcjUVYE5zGjZn3DjfnMYk=;
        b=taipWkn8rGqx8SWXeTH+32Uqwd/CUycLEX6h8RG6yfc474Be843B4D/LJXw0BxjzLj
         akmdBdbacqvBfKAYINNJbIcqwBplWkNuhjQ7FmwafEBYsPzVDAQQVZhb8MffnXx+R9mM
         tP00rS6qL+Wotj34jiNZtweY1DjD8iNuDWCHI8bytTGFpgRy/q/nPsZa2Rl1Ntv3ZqTK
         Z5FkTXcdKE8DEVYbAZpigDwoavkuoerie+Db0TAwuC21ECpU9pEImsTLMUuiabmtDY5l
         1ocweXUVHu6M/CcVxa219S9VhWcjrZG5WHipxoSRp6sI5hM/9uVLiST6YaIUDZ1uS3cP
         X7IQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Tbn0PJXv;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe36.google.com (mail-vs1-xe36.google.com. [2607:f8b0:4864:20::e36])
        by gmr-mx.google.com with ESMTPS id a6-20020a92c546000000b00316f4a326adsi839051ilj.4.2023.03.09.03.10.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Mar 2023 03:10:02 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e36 as permitted sender) client-ip=2607:f8b0:4864:20::e36;
Received: by mail-vs1-xe36.google.com with SMTP id d20so1225951vsf.11
        for <kasan-dev@googlegroups.com>; Thu, 09 Mar 2023 03:10:02 -0800 (PST)
X-Received: by 2002:a67:ce0a:0:b0:416:e50f:8215 with SMTP id
 s10-20020a67ce0a000000b00416e50f8215mr14235184vsl.4.1678360202503; Thu, 09
 Mar 2023 03:10:02 -0800 (PST)
MIME-Version: 1.0
References: <1678349122-19279-1-git-send-email-quic_zhenhuah@quicinc.com>
 <CANpmjNOah6gSB_mRvhsK_9DpBtiYinRd5z34PU+tOFgSqXB8Sw@mail.gmail.com> <706340ef-1745-c1e4-be4d-358d5db4c05e@quicinc.com>
In-Reply-To: <706340ef-1745-c1e4-be4d-358d5db4c05e@quicinc.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Mar 2023 12:09:22 +0100
Message-ID: <CANpmjNP64OSJgnYyfrijJMdkBNhsvVM9hmwLXOkKJAxoZJV=tg@mail.gmail.com>
Subject: Re: [PATCH] mm,kfence: decouple kfence from page granularity mapping judgement
To: Zhenhua Huang <quic_zhenhuah@quicinc.com>
Cc: catalin.marinas@arm.com, will@kernel.org, glider@google.com, 
	dvyukov@google.com, akpm@linux-foundation.org, robin.murphy@arm.com, 
	mark.rutland@arm.com, jianyong.wu@arm.com, james.morse@arm.com, 
	linux-arm-kernel@lists.infradead.org, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, quic_pkondeti@quicinc.com, quic_guptap@quicinc.com, 
	quic_tingweiz@quicinc.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Tbn0PJXv;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e36 as
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

On Thu, 9 Mar 2023 at 12:04, Zhenhua Huang <quic_zhenhuah@quicinc.com> wrote:
>
> Thanks Marco.
>
> On 2023/3/9 18:33, Marco Elver wrote:
> > On Thu, 9 Mar 2023 at 09:05, Zhenhua Huang <quic_zhenhuah@quicinc.com> wrote:
> >>
> >> Kfence only needs its pool to be mapped as page granularity, previous
> >> judgement was a bit over protected. Decouple it from judgement and do
> >> page granularity mapping for kfence pool only [1].
> >>
> >> To implement this, also relocate the kfence pool allocation before the
> >> linear mapping setting up, kfence_alloc_pool is to allocate phys addr,
> >> __kfence_pool is to be set after linear mapping set up.
> >>
> >> LINK: [1] https://lore.kernel.org/linux-arm-kernel/1675750519-1064-1-git-send-email-quic_zhenhuah@quicinc.com/T/
> >> Suggested-by: Mark Rutland <mark.rutland@arm.com>
> >> Signed-off-by: Zhenhua Huang <quic_zhenhuah@quicinc.com>
> >> ---
> >>   arch/arm64/mm/mmu.c      | 24 ++++++++++++++++++++++++
> >>   arch/arm64/mm/pageattr.c |  5 ++---
> >>   include/linux/kfence.h   | 10 ++++++++--
> >>   init/main.c              |  1 -
> >>   mm/kfence/core.c         | 18 ++++++++++++++----
> >>   5 files changed, 48 insertions(+), 10 deletions(-)
> >>
> >> diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
> >> index 6f9d889..bd79691 100644
> >> --- a/arch/arm64/mm/mmu.c
> >> +++ b/arch/arm64/mm/mmu.c
> >> @@ -24,6 +24,7 @@
> >>   #include <linux/mm.h>
> >>   #include <linux/vmalloc.h>
> >>   #include <linux/set_memory.h>
> >> +#include <linux/kfence.h>
> >>
> >>   #include <asm/barrier.h>
> >>   #include <asm/cputype.h>
> >> @@ -532,6 +533,9 @@ static void __init map_mem(pgd_t *pgdp)
> >>          phys_addr_t kernel_end = __pa_symbol(__init_begin);
> >>          phys_addr_t start, end;
> >>          int flags = NO_EXEC_MAPPINGS;
> >> +#ifdef CONFIG_KFENCE
> >> +       phys_addr_t kfence_pool = 0;
> >> +#endif
> >>          u64 i;
> >>
> >>          /*
> >> @@ -564,6 +568,12 @@ static void __init map_mem(pgd_t *pgdp)
> >>          }
> >>   #endif
> >>
> >> +#ifdef CONFIG_KFENCE
> >> +       kfence_pool = kfence_alloc_pool();
> >> +       if (kfence_pool)
> >> +               memblock_mark_nomap(kfence_pool, KFENCE_POOL_SIZE);
> >> +#endif
> >> +
> >>          /* map all the memory banks */
> >>          for_each_mem_range(i, &start, &end) {
> >>                  if (start >= end)
> >> @@ -608,6 +618,20 @@ static void __init map_mem(pgd_t *pgdp)
> >>                  }
> >>          }
> >>   #endif
> >> +
> >> +       /* Kfence pool needs page-level mapping */
> >> +#ifdef CONFIG_KFENCE
> >> +       if (kfence_pool) {
> >> +               __map_memblock(pgdp, kfence_pool,
> >> +                       kfence_pool + KFENCE_POOL_SIZE,
> >> +                       pgprot_tagged(PAGE_KERNEL),
> >> +                       NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
> >> +               memblock_clear_nomap(kfence_pool, KFENCE_POOL_SIZE);
> >> +               /* kfence_pool really mapped now */
> >> +               kfence_set_pool(kfence_pool);
> >> +       }
> >> +#endif
> >> +
> >>   }
> >>
> >>   void mark_rodata_ro(void)
> >> diff --git a/arch/arm64/mm/pageattr.c b/arch/arm64/mm/pageattr.c
> >> index 79dd201..61156d0 100644
> >> --- a/arch/arm64/mm/pageattr.c
> >> +++ b/arch/arm64/mm/pageattr.c
> >> @@ -22,12 +22,11 @@ bool rodata_full __ro_after_init = IS_ENABLED(CONFIG_RODATA_FULL_DEFAULT_ENABLED
> >>   bool can_set_direct_map(void)
> >>   {
> >>          /*
> >> -        * rodata_full, DEBUG_PAGEALLOC and KFENCE require linear map to be
> >> +        * rodata_full and DEBUG_PAGEALLOC require linear map to be
> >>           * mapped at page granularity, so that it is possible to
> >>           * protect/unprotect single pages.
> >>           */
> >> -       return (rodata_enabled && rodata_full) || debug_pagealloc_enabled() ||
> >> -               IS_ENABLED(CONFIG_KFENCE);
> >> +       return (rodata_enabled && rodata_full) || debug_pagealloc_enabled();
> >>   }
> >>
> >>   static int change_page_range(pte_t *ptep, unsigned long addr, void *data)
> >> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> >> index 726857a..0252e74 100644
> >> --- a/include/linux/kfence.h
> >> +++ b/include/linux/kfence.h
> >> @@ -61,7 +61,12 @@ static __always_inline bool is_kfence_address(const void *addr)
> >>   /**
> >>    * kfence_alloc_pool() - allocate the KFENCE pool via memblock
> >>    */
> >> -void __init kfence_alloc_pool(void);
> >> +phys_addr_t __init kfence_alloc_pool(void);
> >> +
> >> +/**
> >> + * kfence_set_pool() - KFENCE pool mapped and can be used
> >> + */
> >> +void __init kfence_set_pool(phys_addr_t addr);
> >>
> >>   /**
> >>    * kfence_init() - perform KFENCE initialization at boot time
> >> @@ -223,7 +228,8 @@ bool __kfence_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *sla
> >>   #else /* CONFIG_KFENCE */
> >>
> >>   static inline bool is_kfence_address(const void *addr) { return false; }
> >> -static inline void kfence_alloc_pool(void) { }
> >> +static inline phys_addr_t kfence_alloc_pool(void) { return (phys_addr_t)NULL; }
> >> +static inline void kfence_set_pool(phys_addr_t addr) { }
> >>   static inline void kfence_init(void) { }
> >>   static inline void kfence_shutdown_cache(struct kmem_cache *s) { }
> >>   static inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags) { return NULL; }
> >> diff --git a/init/main.c b/init/main.c
> >> index 4425d17..9aaf217 100644
> >> --- a/init/main.c
> >> +++ b/init/main.c
> >> @@ -839,7 +839,6 @@ static void __init mm_init(void)
> >>           */
> >>          page_ext_init_flatmem();
> >>          init_mem_debugging_and_hardening();
> >> -       kfence_alloc_pool();
> >
> > This breaks other architectures.
>
> Nice catch. Thanks!
>
> >
> >>          report_meminit();
> >>          kmsan_init_shadow();
> >>          stack_depot_early_init();
> >> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> >> index 5349c37..dd5cdd5 100644
> >> --- a/mm/kfence/core.c
> >> +++ b/mm/kfence/core.c
> >> @@ -809,15 +809,25 @@ static void toggle_allocation_gate(struct work_struct *work)
> >>
> >>   /* === Public interface ===================================================== */
> >>
> >> -void __init kfence_alloc_pool(void)
> >> +phys_addr_t __init kfence_alloc_pool(void)
> >>   {
> >
> > You could just return here:
> >
> >    if (__kfence_pool)
> >      return; /* Initialized earlier by arch init code. */
>
> Yeah.
>
> >
> > ... and see my comments below.
> >
> >> +       phys_addr_t kfence_pool;
> >>          if (!kfence_sample_interval)
> >> -               return;
> >> +               return 0;
> >>
> >> -       __kfence_pool = memblock_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
> >> +       kfence_pool = memblock_phys_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
> >>
> >> -       if (!__kfence_pool)
> >> +       if (!kfence_pool) {
> >>                  pr_err("failed to allocate pool\n");
> >> +               return 0;
> >> +       }
> >> +
> >> +       return kfence_pool;
> >> +}
> >> +
> >> +void __init kfence_set_pool(phys_addr_t addr)
> >> +{
> >> +       __kfence_pool = phys_to_virt(addr);
> >>   }
> >
> > I would suggest leaving kfence_alloc_pool() to return nothing (with
> > the addition above), and just set __kfence_pool as before.
> > __kfence_pool itself is exported by include/linux/kfence.h, so if you
> > call kfence_alloc_pool() in arm64 earlier, you can access
> > __kfence_pool to get the allocated pool.
>
> Shall we add one new function like arm64_kfence_alloc_pool() ? The
> reason is linear mapping at that time not set up and we must alloc phys
> addr based on memblock. We can't use common kfence_alloc_pool()..

Ah right - well, you can initialize __kfence_pool however you like
within arm64 init code. Just teaching kfence_alloc_pool() to do
nothing if it's already initialized should be enough. Within
arch/arm64/mm/mmu.c it might be nice to factor out some bits into a
helper like arm64_kfence_alloc_pool(), but would just stick to
whatever is simplest.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP64OSJgnYyfrijJMdkBNhsvVM9hmwLXOkKJAxoZJV%3Dtg%40mail.gmail.com.
