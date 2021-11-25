Return-Path: <kasan-dev+bncBDW2JDUY5AORBPPJ72GAMGQESQQFIHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BC6B45DE4B
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Nov 2021 17:07:26 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id gf10-20020a056214250a00b003c08951ea03sf7074446qvb.17
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Nov 2021 08:07:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637856445; cv=pass;
        d=google.com; s=arc-20160816;
        b=kvxmrvxWo4EnbBncIZXevdO3YhYljQKO8MLQr8qtYwidK5E/mULm7qMaHvwz3bP4tL
         nyV0nKD9TveXiVoKxHVACTBMqgK4KJzDp60GyMSJh/xXuUC6GCsY7AzJ2IWVtYapNX+f
         gWbz/BTVJBu/TKFFbmcVuQR5Vt/wW5XuzjTZiUww+A9wOf6OdYsJPDrV4zHZcLpxIbBo
         yQJcEhgY5Hk4uCfLrZDYsUuu2EN1i3Bfgap3hdXu1k9SBikC1D4oA79/Ot02XR00uthF
         b3RuvtjjF+GiXyUSxmqJvoZGGuEkdLBVltimNlJufZUXskdZIf77zWqeAtAXAF9XOKKG
         LG2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=O5rMdaSZnlKUtMqpBrI8ofcmGFxyHUkYmCFvRsNKqfw=;
        b=hxCFiTlFuDZeswqyh51H8Y5rTQ9gq5wDCoqlDwEQRohUjai51TKeaA4bc5U4YWFw34
         fhlXzzxV/ZejPzxwkopKGKMx84ninhJT7mZEvvGTnghcJQyZOJ6RQnR3yo0Pf7ztcsF1
         9ZKSsFD0F7/ZFkQHanedH7ffcYPdWEdWa1ihXidpZ24qmLORxBKGwLg6S+LULUgBvsHK
         Wax7RetRl4dwUx0WzI0UVkbzH+a/g1XT926I92jvWLaS1tYvSUIHoTEFy/p4c1EMceFB
         A7XjQf7pHkndsMJORZEuIjlZ/C5geH8qeqeJgj0Hq+2edIeJpmERQs+2B03W11mOi2pl
         FmNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=jRJnFJtn;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d32 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O5rMdaSZnlKUtMqpBrI8ofcmGFxyHUkYmCFvRsNKqfw=;
        b=YbLcmzk6ExIyxbB9csBO/5y3lhnUsUfnB2LPvbx8k5b62J0yhVZbTf2GqqSWecPv1b
         zUJR2CHDxurcfblv/ArtY51dwJyhfl3jV/zN78QirJIXQBzH1g1p64CjFXo1VvlKf/Xb
         quPZhybFvvbF1JC0gqs+lh03nAzZMD8E4ihcY+2OzQUUaS2J2jVC9jkQKEdbtYkOPQ83
         PS0wvoz/Bfy1/B50jB9rMzAZy+aUDkltkcVvZt11uxQTNTzSqJGI66hb4tLZHZ1xPfsq
         zURt8y8G0IWYwdnc/pKL1ci3YSxN3kynvKapRAKqxNWcLBu1AeNQCr6dnrInmyCJaLhw
         AOUw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O5rMdaSZnlKUtMqpBrI8ofcmGFxyHUkYmCFvRsNKqfw=;
        b=moZ9Y4AtfAPsPhyymRQUBZoc9g44T5kLtq6o649T8WuslpLhGe/rxzIsDlv4eTKz1z
         PkAhEahH6mMSUm0RgXTlSb/eXSisRnM8sUYATrdms4EWwKNOPlkH19ouDdyBeTrzVNHn
         nGlDRO3biO0TLZmzNuk2wzfUmoK/lnYhakDaM5HUkYAdVn+gdR23UpFgfALAdpc6Me6E
         /zby2RgH6LDZP114ynzjxpb053bYqQWjfWC/5ucK0lEWwkKBjDkxbbXUAoyChlv4PN+l
         N5VBqQFIy+LqecJRqXx2zyEb4CJPtssg7cauTbwBAlQHMaZXfS/XLBhtDeLnMev+tFuB
         tKwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O5rMdaSZnlKUtMqpBrI8ofcmGFxyHUkYmCFvRsNKqfw=;
        b=kZvfhIHH9qemXX/6sXm1ljnAgJzzH014jVI2BIq4BnipQ4MTSXGDdw+spVwm//8Csy
         471+4bi5iMUO411thiLQAfQDMROt89f92jffWU62QfVaZt+VkGVADtDBh+/Xdgy6WjbK
         aBEDi4dX+2BAHvMaZ8ZEwBVjGcduf2Jhm58AbhxJCAmYAGjG7A5ssZ04pEPbjmik54LT
         l9eALQJZXrygVyqEpGZH5IgXY24ckUgs5sScriMxUdQL9KTC3V25AoN2B1L+GcO8xxhZ
         2WaqRZ9Ekk9nzBlXTgnbjObLrGvaoXxYXkxml5DgCYVnaC6lkycOIquLME/g8dwaXIXe
         udEA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ZwFir0d8zhQa3UPWBz+CSn5O6bOsG1kmCgmwpkq5iQLrpECOd
	CJWHa1mojmcmoEGFkFws3Dk=
X-Google-Smtp-Source: ABdhPJzCGtVA4wWUcbD+2XiGInLPo50R7raHzKAGA8xrCdQm3rS4Mtxv4exv69ImNMiCQRAi1Mfl+Q==
X-Received: by 2002:a05:6214:c47:: with SMTP id r7mr19048110qvj.51.1637856445125;
        Thu, 25 Nov 2021 08:07:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5fd4:: with SMTP id k20ls1929998qta.8.gmail; Thu, 25 Nov
 2021 08:07:24 -0800 (PST)
X-Received: by 2002:a05:622a:610:: with SMTP id z16mr19108533qta.184.1637856444734;
        Thu, 25 Nov 2021 08:07:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637856444; cv=none;
        d=google.com; s=arc-20160816;
        b=bw9H+7UBnQ4bCVdMcBvqXD1nvSzMQ2XOi4ywIrwWYJOyeU2UjKtjaPgYt5ak6ZJfg6
         nxEV/oKLgejP6iEwWKat0tCvm9L5bzpcy7k9HAAk/zDxOQmeoS6TmHATUxZHY8DGT1c/
         /ozX1ztlbKli1md2h+EGIdfqO+ksHcCsN9dk46p7YZISomyZyL/yzXOSWzsgiR8fsbZt
         bgArnmsRmROOdcC6KtrdRzhSnnPFjQO0nS36/5OnIYM0j8ZxC474707PXWYeJ/QQKjUY
         OKsxLcDqiVp4Wdx3jlodGuSAHEBO7TSRP5NemUyko6gyUin5uAp3wzlF4WJOIFG45HMx
         iegA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ShBwsoBhPdOA1WTiDFm7VC0m3oxnPMz059B7sCZmM1Y=;
        b=0F1TR+1u5SaCOU260rNWP1hcYX295EjGl76PDwVJhliNRZOtyZwICA4AUm7HeUjMjK
         9SaiEnESsqamanvL6utNpvdmFRjkmUMzVIbZ7HcwC+8VxyNQKk+Quk5EF/HlQdbO+X2d
         Nn60yy+QMUjMhwLWJ4ls3lf+MgVbHEsY1i1I9syGk18F9Ey2sOcyjR0mYi/j2+JB0q2w
         yccwU8p5WgiA+oOY+PuBc98b3mBYqBAovMCDQ4W2j25OhaSDyrYB01bmgwUfI9fczbba
         OCeRjq2eMbPwOYzwVpdDaPLFhGKAt2VMreDfVYh87A4CQ1x8NPEDbb+yHILlFy9XQDn0
         9kdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=jRJnFJtn;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d32 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd32.google.com (mail-io1-xd32.google.com. [2607:f8b0:4864:20::d32])
        by gmr-mx.google.com with ESMTPS id s4si598095qtc.4.2021.11.25.08.07.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Nov 2021 08:07:24 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d32 as permitted sender) client-ip=2607:f8b0:4864:20::d32;
Received: by mail-io1-xd32.google.com with SMTP id x10so8093487ioj.9
        for <kasan-dev@googlegroups.com>; Thu, 25 Nov 2021 08:07:24 -0800 (PST)
X-Received: by 2002:a02:7053:: with SMTP id f80mr29604175jac.28.1637856443318;
 Thu, 25 Nov 2021 08:07:23 -0800 (PST)
MIME-Version: 1.0
References: <20211125080307.27225-1-wangkefeng.wang@huawei.com>
In-Reply-To: <20211125080307.27225-1-wangkefeng.wang@huawei.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 25 Nov 2021 17:07:12 +0100
Message-ID: <CA+fCnZcnwJHUQq34VuRxpdoY6_XbJCDJ-jopksS5Eia4PijPzw@mail.gmail.com>
Subject: Re: [PATCH v4] mm: Defer kmemleak object creation of module_alloc()
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, LKML <linux-kernel@vger.kernel.org>, 
	linux-s390@vger.kernel.org, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Heiko Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>, 
	Christian Borntraeger <borntraeger@linux.ibm.com>, Alexander Gordeev <agordeev@linux.ibm.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Alexander Potapenko <glider@google.com>, 
	Yongqiang Liu <liuyongqiang13@huawei.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=jRJnFJtn;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d32
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

On Thu, Nov 25, 2021 at 8:52 AM 'Kefeng Wang' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Yongqiang reports a kmemleak panic when module insmod/rmmod
> with KASAN enabled(without KASAN_VMALLOC) on x86[1].
>
> When the module area allocates memory, it's kmemleak_object
> is created successfully, but the KASAN shadow memory of module
> allocation is not ready, so when kmemleak scan the module's
> pointer, it will panic due to no shadow memory with KASAN check.
>
> module_alloc
>   __vmalloc_node_range
>     kmemleak_vmalloc
>                                 kmemleak_scan
>                                   update_checksum
>   kasan_module_alloc
>     kmemleak_ignore
>
> Note, there is no problem if KASAN_VMALLOC enabled, the modules
> area entire shadow memory is preallocated. Thus, the bug only
> exits on ARCH which supports dynamic allocation of module area
> per module load, for now, only x86/arm64/s390 are involved.
>
>
> Add a VM_DEFER_KMEMLEAK flags, defer vmalloc'ed object register
> of kmemleak in module_alloc() to fix this issue.
>
> [1] https://lore.kernel.org/all/6d41e2b9-4692-5ec4-b1cd-cbe29ae89739@huawei.com/
>
> Fixes: 793213a82de4 ("s390/kasan: dynamic shadow mem allocation for modules")
> Fixes: 39d114ddc682 ("arm64: add KASAN support")
> Fixes: bebf56a1b176 ("kasan: enable instrumentation of global variables")
> Reported-by: Yongqiang Liu <liuyongqiang13@huawei.com>
> Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
> ---
> V4:
> - add fix tag
> - fix missing change about VM_DELAY_KMEMLEAK
> v3:
> - update changelog to add more explanation
> - use DEFER instead of DELAY sugguested by Catalin.
> v2:
> - fix type error on changelog and kasan_module_alloc()
>
>  arch/arm64/kernel/module.c | 4 ++--
>  arch/s390/kernel/module.c  | 5 +++--
>  arch/x86/kernel/module.c   | 7 ++++---
>  include/linux/kasan.h      | 4 ++--
>  include/linux/vmalloc.h    | 7 +++++++
>  mm/kasan/shadow.c          | 9 +++++++--
>  mm/vmalloc.c               | 3 ++-
>  7 files changed, 27 insertions(+), 12 deletions(-)
>
> diff --git a/arch/arm64/kernel/module.c b/arch/arm64/kernel/module.c
> index b5ec010c481f..309a27553c87 100644
> --- a/arch/arm64/kernel/module.c
> +++ b/arch/arm64/kernel/module.c
> @@ -36,7 +36,7 @@ void *module_alloc(unsigned long size)
>                 module_alloc_end = MODULES_END;
>
>         p = __vmalloc_node_range(size, MODULE_ALIGN, module_alloc_base,
> -                               module_alloc_end, gfp_mask, PAGE_KERNEL, 0,
> +                               module_alloc_end, gfp_mask, PAGE_KERNEL, VM_DEFER_KMEMLEAK,
>                                 NUMA_NO_NODE, __builtin_return_address(0));
>
>         if (!p && IS_ENABLED(CONFIG_ARM64_MODULE_PLTS) &&
> @@ -58,7 +58,7 @@ void *module_alloc(unsigned long size)
>                                 PAGE_KERNEL, 0, NUMA_NO_NODE,
>                                 __builtin_return_address(0));
>
> -       if (p && (kasan_module_alloc(p, size) < 0)) {
> +       if (p && (kasan_module_alloc(p, size, gfp_mask) < 0)) {
>                 vfree(p);
>                 return NULL;
>         }
> diff --git a/arch/s390/kernel/module.c b/arch/s390/kernel/module.c
> index b01ba460b7ca..d52d85367bf7 100644
> --- a/arch/s390/kernel/module.c
> +++ b/arch/s390/kernel/module.c
> @@ -37,14 +37,15 @@
>
>  void *module_alloc(unsigned long size)
>  {
> +       gfp_t gfp_mask = GFP_KERNEL;
>         void *p;
>
>         if (PAGE_ALIGN(size) > MODULES_LEN)
>                 return NULL;
>         p = __vmalloc_node_range(size, MODULE_ALIGN, MODULES_VADDR, MODULES_END,
> -                                GFP_KERNEL, PAGE_KERNEL_EXEC, 0, NUMA_NO_NODE,
> +                                gfp_mask, PAGE_KERNEL_EXEC, VM_DEFER_KMEMLEAK, NUMA_NO_NODE,
>                                  __builtin_return_address(0));
> -       if (p && (kasan_module_alloc(p, size) < 0)) {
> +       if (p && (kasan_module_alloc(p, size, gfp_mask) < 0)) {
>                 vfree(p);
>                 return NULL;
>         }
> diff --git a/arch/x86/kernel/module.c b/arch/x86/kernel/module.c
> index 169fb6f4cd2e..95fa745e310a 100644
> --- a/arch/x86/kernel/module.c
> +++ b/arch/x86/kernel/module.c
> @@ -67,6 +67,7 @@ static unsigned long int get_module_load_offset(void)
>
>  void *module_alloc(unsigned long size)
>  {
> +       gfp_t gfp_mask = GFP_KERNEL;
>         void *p;
>
>         if (PAGE_ALIGN(size) > MODULES_LEN)
> @@ -74,10 +75,10 @@ void *module_alloc(unsigned long size)
>
>         p = __vmalloc_node_range(size, MODULE_ALIGN,
>                                     MODULES_VADDR + get_module_load_offset(),
> -                                   MODULES_END, GFP_KERNEL,
> -                                   PAGE_KERNEL, 0, NUMA_NO_NODE,
> +                                   MODULES_END, gfp_mask,
> +                                   PAGE_KERNEL, VM_DEFER_KMEMLEAK, NUMA_NO_NODE,
>                                     __builtin_return_address(0));
> -       if (p && (kasan_module_alloc(p, size) < 0)) {
> +       if (p && (kasan_module_alloc(p, size, gfp_mask) < 0)) {
>                 vfree(p);
>                 return NULL;
>         }
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index d8783b682669..89c99e5e67de 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -474,12 +474,12 @@ static inline void kasan_populate_early_vm_area_shadow(void *start,
>   * allocations with real shadow memory. With KASAN vmalloc, the special
>   * case is unnecessary, as the work is handled in the generic case.
>   */
> -int kasan_module_alloc(void *addr, size_t size);
> +int kasan_module_alloc(void *addr, size_t size, gfp_t gfp_mask);
>  void kasan_free_shadow(const struct vm_struct *vm);
>
>  #else /* (CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) && !CONFIG_KASAN_VMALLOC */
>
> -static inline int kasan_module_alloc(void *addr, size_t size) { return 0; }
> +static inline int kasan_module_alloc(void *addr, size_t size, gfp_t gfp_mask) { return 0; }
>  static inline void kasan_free_shadow(const struct vm_struct *vm) {}
>
>  #endif /* (CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) && !CONFIG_KASAN_VMALLOC */
> diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
> index 6e022cc712e6..506fc6e6a126 100644
> --- a/include/linux/vmalloc.h
> +++ b/include/linux/vmalloc.h
> @@ -28,6 +28,13 @@ struct notifier_block;               /* in notifier.h */
>  #define VM_MAP_PUT_PAGES       0x00000200      /* put pages and free array in vfree */
>  #define VM_NO_HUGE_VMAP                0x00000400      /* force PAGE_SIZE pte mapping */
>
> +#if defined(CONFIG_KASAN) && (defined(CONFIG_KASAN_GENERIC) || \
> +       defined(CONFIG_KASAN_SW_TAGS)) && !defined(CONFIG_KASAN_VMALLOC)
> +#define VM_DEFER_KMEMLEAK      0x00000800      /* defer kmemleak object creation */
> +#else
> +#define VM_DEFER_KMEMLEAK      0
> +#endif

No need for CONFIG_KASAN check: CONFIG_KASAN_GENERIC ||
CONFIG_KASAN_SW_TAGS implies CONFIG_KASAN.



> +
>  /*
>   * VM_KASAN is used slightly differently depending on CONFIG_KASAN_VMALLOC.
>   *
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 4a4929b29a23..2ade2f484562 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -498,7 +498,7 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
>
>  #else /* CONFIG_KASAN_VMALLOC */
>
> -int kasan_module_alloc(void *addr, size_t size)
> +int kasan_module_alloc(void *addr, size_t size, gfp_t gfp_mask)
>  {
>         void *ret;
>         size_t scaled_size;
> @@ -520,9 +520,14 @@ int kasan_module_alloc(void *addr, size_t size)
>                         __builtin_return_address(0));
>
>         if (ret) {
> +               struct vm_struct *vm = find_vm_area(addr);
>                 __memset(ret, KASAN_SHADOW_INIT, shadow_size);
> -               find_vm_area(addr)->flags |= VM_KASAN;
> +               vm->flags |= VM_KASAN;
>                 kmemleak_ignore(ret);
> +
> +               if (vm->flags & VM_DEFER_KMEMLEAK)
> +                       kmemleak_vmalloc(vm, size, gfp_mask);
> +
>                 return 0;
>         }
>
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index d2a00ad4e1dd..bf3c2fe8f528 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -3074,7 +3074,8 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
>         clear_vm_uninitialized_flag(area);
>
>         size = PAGE_ALIGN(size);
> -       kmemleak_vmalloc(area, size, gfp_mask);
> +       if (!(vm_flags & VM_DEFER_KMEMLEAK))
> +               kmemleak_vmalloc(area, size, gfp_mask);
>
>         return addr;
>
> --
> 2.26.2
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211125080307.27225-1-wangkefeng.wang%40huawei.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcnwJHUQq34VuRxpdoY6_XbJCDJ-jopksS5Eia4PijPzw%40mail.gmail.com.
