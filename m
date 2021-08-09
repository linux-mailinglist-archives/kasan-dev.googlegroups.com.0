Return-Path: <kasan-dev+bncBDW2JDUY5AORBRXEYWEAMGQE7JH4JEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 868B93E4C09
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Aug 2021 20:21:58 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id a18-20020a05600c2252b02902531dcdc68fsf16158wmm.6
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Aug 2021 11:21:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628533318; cv=pass;
        d=google.com; s=arc-20160816;
        b=eBQXQiv95DJg2TLYNk+3DAO5rrM1rzf2DPw5utBmi2UlbSWjpFBfu+c5dpX7ZcFZke
         5Z6IoLIBqzEXBCxlHGLcZxfZ4aKoys6zDudC5T+WgO5F9xo0fRoUq75H3tV1QHb85TIw
         6MRW3bppTHz6o3NJjb6Kj3vOKxg+lGHV/RAoWfcubJ5pdrrpFyqqd30qwm4JlVAR0uhm
         fZzlFMhMJi/uDItRsyK9OKrb42Btfe52fCxc73426I5GonH9Kh44N13jw5RlbjZSTKml
         BRBOCChUEtMzHr2FndGMAdysQEJc0OUefwAf3oBbYbGtVu2BVrwsZTJ4l0c2oi+QQIYS
         cQLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=Lf+F85GD25u+gBUYeUP2ATPu0PzA7OQPouwTCxPLa5Y=;
        b=Wfhv1r8F7n+2HpPtK1Q7iU7JRkSi9b+mSlibnvmHUu2Wvy+2Je8MzYLDs+ot6mxoCa
         xRUUbI4jTXATOjeX7E5vSlfsvHSb3b0+Y2/DDwu/jTUSS2JNbt+C40rQiPIAd+fU4tvp
         7sOijH+V+BSrRMD4AqE42x2le3dEvC3DK5hug7KLcGoNizRoF7wZk8b90RZCvmYKlo/1
         A1zKwpUczC7nhEg4vUgbFkzf+LPJ1OEr3FwdSm4JZGJMN0EZqAlY0u0jApIcPpWAal8Z
         et8UpKSaWDiq/JIUXFmai5YSg0A7V6SWMFhkRDNv5iThSwFeCV1w4cw1b1ogKfpQTweK
         mDOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="e2p4CwB/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Lf+F85GD25u+gBUYeUP2ATPu0PzA7OQPouwTCxPLa5Y=;
        b=RlRXwwVRoLT41oa+EyyBf2GeFMsX/+VzceBwATtlnGmRRVXx36cNlnSsxyEiQW4805
         47LJmIlOvJxufGZOXqVcySslBeXxfkmgp/bMBTf2ALDRhuyqvMjy1B8e+296LS5/VcEW
         Imr/qJ0CPxZ0pm7LDdGQUk1V8gIToOiXw5Tm5m89MmxUXIP9KHD4Ph9XLJ35nhWygoqN
         EPuaitDi+mG7dbgXDTvHzCP7A44u91gQqPs6VK2Oogash8LNeQyarYLcPfS/7eIpA2gB
         e4yCrjSnIPJzyaPRrT2T7nOZskcNjReJ/6BLO+uRWHpkUstci8P3sUTutI3RWIDFmqoK
         VunA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Lf+F85GD25u+gBUYeUP2ATPu0PzA7OQPouwTCxPLa5Y=;
        b=TcgZO59JKi1M79wPLnW+KqhThR9xl09HG86jAPaIqpucaWcLl/AlZl4iUtwfoVfKm3
         oWre6yKJjTq7RJ6jM3PbRDFQk7DSlCNSBnmpythXBT9JfsvRmNPJLjU4HwqC8htQVkp+
         KHZ6BC8SbFQ/5Dxp+a0MN7Q55pwdDw/Di4NTknhqI5kAi5NEgYlMINNvMnk6QCf/v4ck
         S02rNcRtvEFCCm+goC4OcebjMQEtk7kpbUptH5W0YcmIJ2+KzYw82WCpTdKNnGageEit
         EUdN++5a8+YOkKmSe2gyyiGVHoA8b23gZ836ue2vDQCDaCN42bCPe9ih0p/jqLu58f9H
         kCiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Lf+F85GD25u+gBUYeUP2ATPu0PzA7OQPouwTCxPLa5Y=;
        b=a3NvYlPGwfO1/9wTmjCzt94fyiuMsCGo3Mu5JqnU6zZtX7L6q/4B6KRGDiDOp5OgIB
         F2iXV4zVjLmsClSjyVSZ1y3V5xl2CTwXt2FBrZd14IFAM3ecx8mZa4vRxiKg14YduntS
         ggCnPYoQrWJoiPuUHZ0aLyUQ4LNV8N48q5ossaEdJY9QoVklc8sgRwZKDySmcOlk0tw0
         KIvh1609zb0Hj/osFBXKrQCke16v2LLONvjqktfWlhzPGHVt/oNTk17zPbiZ1McO4mzU
         xoQTh8ZBkHA/NNUohxZD7VSDfaeEScfj39zbPnynQQUpo5GdPo6SSdTyge0DH0KJngmi
         iE+Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531+HjMExP58RfgLq3AAfUajRXHUDxtfX/uJ1rKZjffb3vGqzG47
	dNFPisNNWV7xGI+rQIA2Ip0=
X-Google-Smtp-Source: ABdhPJxFmYaOST9qa8P4ar6UZ1IzlBwl9Wl/mz5gN8gaHvrbvX/XA7t9vOeuUcCLK2j0SDk0eIV8Tw==
X-Received: by 2002:a5d:49c1:: with SMTP id t1mr26681591wrs.141.1628533318349;
        Mon, 09 Aug 2021 11:21:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e5c5:: with SMTP id a5ls5552295wrn.0.gmail; Mon, 09 Aug
 2021 11:21:57 -0700 (PDT)
X-Received: by 2002:a5d:424d:: with SMTP id s13mr26509687wrr.356.1628533317495;
        Mon, 09 Aug 2021 11:21:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628533317; cv=none;
        d=google.com; s=arc-20160816;
        b=HQtbhbDEH9gznYLtAoGPlXP56/EtV64ht8UksAB6R0WLmUlxVvB3wQeHxUeiNaSIxB
         hSKP1D9hpzE4SUdkSHBbwa/hoK3I/2Udx3lbrNHLcda9rO4uz/BPhtur5dD1tXLx+nzY
         2HXnvstzDFxOnQR1CFdHB1PHUQC/9/UD7KOo55B8CRhgtEjdPYsK8losnvdWrJjCj6VH
         vZagZjLlbexhF6+zgAR/D/Mftda1YruucGB7CEQI1BNBse/rsWQy50KigxW72asCVcIt
         SVz4lBG0o6QD8WsRp5fQ0KlhiAnWYF+WkHi7ers2jb24rCkye+a43dFDe3UO4wjSEyhy
         2h1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ftVuG4BqRClWmA3Iio5cpbFgJTgza3Lrv72uDZY9cX8=;
        b=DCdTYpkrKp8K++rYqeCfDfM0h1icQZKcPHjY8NPhwNdd9adtsB2MehPxNQXvJ8dfaI
         Frlq/D12qot7oXBKJ+0YZS+ChG1ky79N1Q4xPv0sZktM42EPBLJGPNlwe5D7g+ciyCy4
         L3y8yyeHHoBTd9rj87+jvLjca3Q5fNiUuUP7Fdcn4Cg698Ic4VE8YtMwHb3RvCX1nlJ+
         iiHzaE+yYC5WItfKYYE9/wCd6McXGVsOo0LGR+qs5KH2uI3cyWwRfpUEp2XtNySeVDVn
         /76PCCJa0zRPoBUilV4OwaIDxM02U8NkR+V1EivYHt51Ts/9NKCFMJ6ghiV9G03G1Ex/
         QlkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="e2p4CwB/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x530.google.com (mail-ed1-x530.google.com. [2a00:1450:4864:20::530])
        by gmr-mx.google.com with ESMTPS id u2si990000wro.0.2021.08.09.11.21.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Aug 2021 11:21:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::530 as permitted sender) client-ip=2a00:1450:4864:20::530;
Received: by mail-ed1-x530.google.com with SMTP id f13so25969437edq.13
        for <kasan-dev@googlegroups.com>; Mon, 09 Aug 2021 11:21:57 -0700 (PDT)
X-Received: by 2002:a05:6402:430b:: with SMTP id m11mr31667971edc.55.1628533317269;
 Mon, 09 Aug 2021 11:21:57 -0700 (PDT)
MIME-Version: 1.0
References: <20210809093750.131091-1-wangkefeng.wang@huawei.com> <20210809093750.131091-4-wangkefeng.wang@huawei.com>
In-Reply-To: <20210809093750.131091-4-wangkefeng.wang@huawei.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 9 Aug 2021 20:21:46 +0200
Message-ID: <CA+fCnZcL7tv=HsXJjXMayjASeAriy6N0HJwCoH7iPZZ6hqZGQw@mail.gmail.com>
Subject: Re: [PATCH v3 3/3] kasan: arm64: Fix pcpu_page_first_chunk crash with KASAN_VMALLOC
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: Will Deacon <will@kernel.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="e2p4CwB/";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::530
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Mon, Aug 9, 2021 at 11:32 AM Kefeng Wang <wangkefeng.wang@huawei.com> wrote:
>
> With KASAN_VMALLOC and NEED_PER_CPU_PAGE_FIRST_CHUNK, it crashs,
>
> Unable to handle kernel paging request at virtual address ffff7000028f2000
> ...
> swapper pgtable: 64k pages, 48-bit VAs, pgdp=0000000042440000
> [ffff7000028f2000] pgd=000000063e7c0003, p4d=000000063e7c0003, pud=000000063e7c0003, pmd=000000063e7b0003, pte=0000000000000000
> Internal error: Oops: 96000007 [#1] PREEMPT SMP
> Modules linked in:
> CPU: 0 PID: 0 Comm: swapper Not tainted 5.13.0-rc4-00003-gc6e6e28f3f30-dirty #62
> Hardware name: linux,dummy-virt (DT)
> pstate: 200000c5 (nzCv daIF -PAN -UAO -TCO BTYPE=--)
> pc : kasan_check_range+0x90/0x1a0
> lr : memcpy+0x88/0xf4
> sp : ffff80001378fe20
> ...
> Call trace:
>  kasan_check_range+0x90/0x1a0
>  pcpu_page_first_chunk+0x3f0/0x568
>  setup_per_cpu_areas+0xb8/0x184
>  start_kernel+0x8c/0x328
>
> The vm area used in vm_area_register_early() has no kasan shadow memory,
> Let's add a new kasan_populate_early_vm_area_shadow() function to populate
> the vm area shadow memory to fix the issue.
>
> Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
> ---
>  arch/arm64/mm/kasan_init.c | 16 ++++++++++++++++
>  include/linux/kasan.h      |  6 ++++++
>  mm/kasan/init.c            |  5 +++++
>  mm/vmalloc.c               |  1 +
>  4 files changed, 28 insertions(+)
>
> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> index 61b52a92b8b6..5b996ca4d996 100644
> --- a/arch/arm64/mm/kasan_init.c
> +++ b/arch/arm64/mm/kasan_init.c
> @@ -287,6 +287,22 @@ static void __init kasan_init_depth(void)
>         init_task.kasan_depth = 0;
>  }
>
> +#ifdef CONFIG_KASAN_VMALLOC
> +void __init kasan_populate_early_vm_area_shadow(void *start, unsigned long size)
> +{
> +       unsigned long shadow_start, shadow_end;
> +
> +       if (!is_vmalloc_or_module_addr(start))
> +               return;
> +
> +       shadow_start = (unsigned long)kasan_mem_to_shadow(start);
> +       shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
> +       shadow_end = (unsigned long)kasan_mem_to_shadow(start + size);
> +       shadow_end = ALIGN(shadow_end, PAGE_SIZE);
> +       kasan_map_populate(shadow_start, shadow_end, NUMA_NO_NODE);
> +}
> +#endif
> +
>  void __init kasan_init(void)
>  {
>         kasan_init_shadow();
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index dd874a1ee862..3f8c26d9ef82 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -133,6 +133,8 @@ struct kasan_cache {
>         bool is_kmalloc;
>  };
>
> +void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
> +
>  slab_flags_t __kasan_never_merge(void);
>  static __always_inline slab_flags_t kasan_never_merge(void)
>  {
> @@ -303,6 +305,10 @@ void kasan_restore_multi_shot(bool enabled);
>
>  #else /* CONFIG_KASAN */
>
> +static inline void kasan_populate_early_vm_area_shadow(void *start,
> +                                                      unsigned long size)
> +{ }
> +
>  static inline slab_flags_t kasan_never_merge(void)
>  {
>         return 0;
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index cc64ed6858c6..d39577d088a1 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -279,6 +279,11 @@ int __ref kasan_populate_early_shadow(const void *shadow_start,
>         return 0;
>  }
>
> +void __init __weak kasan_populate_early_vm_area_shadow(void *start,
> +                                                      unsigned long size)
> +{
> +}
> +
>  static void kasan_free_pte(pte_t *pte_start, pmd_t *pmd)
>  {
>         pte_t *pte;
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index 1e8fe08725b8..66a7e1ea2561 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -2253,6 +2253,7 @@ void __init vm_area_register_early(struct vm_struct *vm, size_t align)
>         vm->addr = (void *)addr;
>
>         vm_area_add_early(vm);
> +       kasan_populate_early_vm_area_shadow(vm->addr, vm->size);
>  }
>
>  static void vmap_init_free_space(void)
> --
> 2.26.2
>

Acked-by: Andrey Konovalov <andreyknvl@gmail.com>

for KASAN parts.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcL7tv%3DHsXJjXMayjASeAriy6N0HJwCoH7iPZZ6hqZGQw%40mail.gmail.com.
