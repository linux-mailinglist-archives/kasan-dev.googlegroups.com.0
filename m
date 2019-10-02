Return-Path: <kasan-dev+bncBDX4HWEMTEBRBOUE2LWAKGQEES5PITI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A107C86BD
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Oct 2019 12:55:55 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id y10sf20847797qti.1
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Oct 2019 03:55:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570013754; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kiw1JQVmr0S+pZ21yQ9CjZPKs/SL9wKTxQOcYE0/0BXxqJWqxDbf3RkPWm95AtBMMo
         gUexQPe5sKykm+GyurP8r/Y4PSeRmKiOh55nQ1WHHjxeFJ+gX0RvYUlN/apQlux2S/hA
         rpUw2SQ3EVlhUUJecl1r1p/Qq8LHQLtPkHFC91p1eh0CkU+NzEZ7p0JHw0pgRI9IYs3U
         nmFFQAzHCXWsiUEOwZ89PkXUwPAc7WVA4ekIn2ErvywTqjPjo3Br8mDzOZC7tYNHe1+j
         dcuhFmEq1CpQecFBxnGXaTteaBMrjs+TixLufSieX5o8Qit3IV5MgI+hem1H2/gAcRvK
         JUIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Jnq9lgbjXXhszHikt28bT5l9zO38g0+Sr4QhB4O73O4=;
        b=faQQ6jiv8rb9Pime5cHP0ZiumCB1C4IpPl7d8gQ2EjLAx90MOFTwqCyCbCRIv2Pu8S
         3KhOsieYRZYreQbG/ki0lS7VgaNkjWlqwigJeQKUNetrxnyEEyEafq1hYLy1lgzCMCYg
         lWqpexRmdhW5bqPw72wsoYVpUzsAqylffi+98TRcPq3Cvz3+a0za4cYNmyFvEdyT51I9
         np655/18nW92wzcjpP9gKpozh3OiuoyiUI9tE0NWl9zsbhzaaZAoqT2auc7i8ymYgBg7
         oTGpcG0+SX/Ybi4CUQSNafDJc01t9fpzYM8tUjfFLR8EcarUSxu49Rcdw7KuuzCCV0sJ
         4Llg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TNtdJa+Q;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Jnq9lgbjXXhszHikt28bT5l9zO38g0+Sr4QhB4O73O4=;
        b=a+r+MOAkXgwlzrc/iryDWEqaqWqXB7CIru+ZjiPVnMHi47fBnqF/e6iJIXSfuH6cA3
         vHgc9+/zam/xddxN/yN/tx3iD2/VzoZgUclQzA3pAEQ6rihSdAtxECMKch6hpIZfpRHh
         OWxFDeTLZMUCcP2xa48JZ7khnv6K++0FFfPn/XUip9jHtzu31Cfmkw5dA9492g0IMA+x
         XNPpDblReES07j92gHP+/1+29ofJbKt3h9J/8/K/GMct+2H5grzBkd+RWUmsi9cXM9ce
         V3zyIsMYSwLfmX56VRyuKO9maIWsRpIi0BycNq9vX1Bhu+qYDzSVbZ825fZIKDVTgYpU
         wf8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Jnq9lgbjXXhszHikt28bT5l9zO38g0+Sr4QhB4O73O4=;
        b=lfaPXzcMjpaKt1LPzCQtL+uD6NJTlmqMLQtwvI/OMcsVijrLv0zw+WCSAEUfNOGu61
         eE3LQJhYrgw1gjwr5ni02KtqCUQpsYy/k9aDrFomUfAwZLE852TzKqhRqgGJ6AARVCWJ
         slWUBBobhJ2uSwFsCVPqkWNPEOL4ZFYqXFoNjpXFRferU67WB6vlEYTKJqmHY1ENbs09
         jeWQUvY0XmbmD+W6PdO83ThwJFIbrzujrhJfu9HVRaDrMRnKyWwN64Xu6m0mOqsq+21z
         jeP5708y9ljejINNUJn1ZS4G2VsEHXw5w5R+odajs2jpQaw/sFyKZnfP3Tn/n2TpxthQ
         xZpg==
X-Gm-Message-State: APjAAAV2QJwm+NVlCwjfQoxhg7WgisNvfxZHnShb0AybfdaDr//WzTCU
	xfDtVQIy1k/qHYi1IBePJec=
X-Google-Smtp-Source: APXvYqxvzG5COR3SBt55vrMeEGMVhW1XzNYNB8ocZnyJR/Vy2zpz4fOqSIL1HyzyTpMMQ/GR9vRNew==
X-Received: by 2002:a05:620a:7c8:: with SMTP id 8mr2832632qkb.299.1570013754547;
        Wed, 02 Oct 2019 03:55:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:131b:: with SMTP id o27ls644059qkj.12.gmail; Wed,
 02 Oct 2019 03:55:54 -0700 (PDT)
X-Received: by 2002:a37:95c6:: with SMTP id x189mr2965020qkd.323.1570013754263;
        Wed, 02 Oct 2019 03:55:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570013754; cv=none;
        d=google.com; s=arc-20160816;
        b=u6dTl/bLZNnTcdoEBCnUEW5vOZstgY79hfeOkhpRTHXU/hOnOu87pYDvIWhiKGP9KM
         Dsr5NhBmWOswgdQ2um58pZWwac5H98Q7SQtjdVrbMYo3poVq1GFHil6N3yUTEkwJk2vt
         cnPNPHTRJCud56MsM24c+QPlPfVEivR61ULuU0SICqOXmWsVxtMPXoys/0O5DOBag8mo
         n/MtLgoSLsdq9BrXntsKpt0Twf+J2GnRhUGqIRlR5sNCrxmUeUHEsJP2dNWBKhkDzGxn
         cQUbgPsGb6JKEkgsY5uQANq3+M5cnfHwHtvxHEbTzk05NYcXOPI6qbpWJYzgFQhsWdLO
         JUcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wPzRaZnauK/aSS25BKAe52uX/PkUhE63Xm4WI7PnEsA=;
        b=kPyOWcHn2S/KA12Wu7bVg+xDdjyupP8ZKelTdAa4kTrw3MB4XF3UalxYLmLlZntn+w
         G/6Vt4Pt1DfB2p++4ydHzYvEpGPjdPNnSpR7h2Bw0cRmy/t06Ao83wdQjnTMCsIbQVxu
         sGFXuCtz23x7IOTpJvgGY+zhxnVMqc+MNPR+hW/arBKQjEZD8oNAqqwsVbozgzTp3gy+
         cq8xUCeTj++SocKKrrwWp9ZMu4a0omRuNrxPVvZQnJmcTNAXzK9kQ7yPto34J+SUtkdL
         wW7SHLagAZF1lgF57g+Lbu+wFmG0lipg5YkFdaiT5SaSWBQCIm2A/KAPjCtNZkHu/1I1
         pXhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TNtdJa+Q;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id t53si1332695qte.2.2019.10.02.03.55.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Oct 2019 03:55:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id q12so10123056pff.9
        for <kasan-dev@googlegroups.com>; Wed, 02 Oct 2019 03:55:54 -0700 (PDT)
X-Received: by 2002:a63:d20f:: with SMTP id a15mr3127214pgg.130.1570013752561;
 Wed, 02 Oct 2019 03:55:52 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1569995450.git.nickhu@andestech.com> <8d86d53e904bece0623cb8969cdc70f782fa2bae.1569995450.git.nickhu@andestech.com>
In-Reply-To: <8d86d53e904bece0623cb8969cdc70f782fa2bae.1569995450.git.nickhu@andestech.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 2 Oct 2019 12:55:41 +0200
Message-ID: <CAAeHK+ymEX7qnYi61cAyxtY5qd+_HV=xQotbOaCg_DtMA=peWA@mail.gmail.com>
Subject: Re: [PATCH v2 2/2] riscv: Add KASAN support
To: Nick Hu <nickhu@andestech.com>
Cc: alankao@andestech.com, paul.walmsley@sifive.com, 
	Palmer Dabbelt <palmer@sifive.com>, aou@eecs.berkeley.edu, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, alexios.zavras@intel.com, 
	Allison Randal <allison@lohutok.net>, Anup.Patel@wdc.com, 
	Thomas Gleixner <tglx@linutronix.de>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, atish.patra@wdc.com, 
	Kate Stewart <kstewart@linuxfoundation.org>, linux-riscv@lists.infradead.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TNtdJa+Q;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Wed, Oct 2, 2019 at 8:16 AM Nick Hu <nickhu@andestech.com> wrote:
>
> This patch ports the feature Kernel Address SANitizer (KASAN).

Hi Nick,

Please also update KASAN documentation to mention that riscv is supported.

Thanks!

>
> Note: The start address of shadow memory is at the beginning of kernel
> space, which is 2^64 - (2^39 / 2) in SV39. The size of the kernel space is
> 2^38 bytes so the size of shadow memory should be 2^38 / 8. Thus, the
> shadow memory would not overlap with the fixmap area.
>
> There are currently two limitations in this port,
>
> 1. RV64 only: KASAN need large address space for extra shadow memory
> region.
>
> 2. KASAN can't debug the modules since the modules are allocated in VMALLOC
> area. We mapped the shadow memory, which corresponding to VMALLOC area, to
> the kasan_early_shadow_page because we don't have enough physical space for
> all the shadow memory corresponding to VMALLOC area.
>
> Signed-off-by: Nick Hu <nickhu@andestech.com>
> ---
>  arch/riscv/Kconfig                  |   1 +
>  arch/riscv/include/asm/kasan.h      |  27 ++++++++
>  arch/riscv/include/asm/pgtable-64.h |   5 ++
>  arch/riscv/include/asm/string.h     |   9 +++
>  arch/riscv/kernel/head.S            |   3 +
>  arch/riscv/kernel/riscv_ksyms.c     |   2 +
>  arch/riscv/kernel/setup.c           |   5 ++
>  arch/riscv/kernel/vmlinux.lds.S     |   1 +
>  arch/riscv/lib/memcpy.S             |   5 +-
>  arch/riscv/lib/memset.S             |   5 +-
>  arch/riscv/mm/Makefile              |   6 ++
>  arch/riscv/mm/kasan_init.c          | 104 ++++++++++++++++++++++++++++
>  12 files changed, 169 insertions(+), 4 deletions(-)
>  create mode 100644 arch/riscv/include/asm/kasan.h
>  create mode 100644 arch/riscv/mm/kasan_init.c
>
> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
> index 8eebbc8860bb..ca2fc8ba8550 100644
> --- a/arch/riscv/Kconfig
> +++ b/arch/riscv/Kconfig
> @@ -61,6 +61,7 @@ config RISCV
>         select SPARSEMEM_STATIC if 32BIT
>         select ARCH_WANT_DEFAULT_TOPDOWN_MMAP_LAYOUT if MMU
>         select HAVE_ARCH_MMAP_RND_BITS
> +       select HAVE_ARCH_KASAN if MMU && 64BIT
>
>  config ARCH_MMAP_RND_BITS_MIN
>         default 18 if 64BIT
> diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/kasan.h
> new file mode 100644
> index 000000000000..eb9b1a2f641c
> --- /dev/null
> +++ b/arch/riscv/include/asm/kasan.h
> @@ -0,0 +1,27 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +/* Copyright (C) 2019 Andes Technology Corporation */
> +
> +#ifndef __ASM_KASAN_H
> +#define __ASM_KASAN_H
> +
> +#ifndef __ASSEMBLY__
> +
> +#ifdef CONFIG_KASAN
> +
> +#include <asm/pgtable.h>
> +
> +#define KASAN_SHADOW_SCALE_SHIFT       3
> +
> +#define KASAN_SHADOW_SIZE      (UL(1) << (38 - KASAN_SHADOW_SCALE_SHIFT))
> +#define KASAN_SHADOW_START     0xffffffc000000000 // 2^64 - 2^38
> +#define KASAN_SHADOW_END       (KASAN_SHADOW_START + KASAN_SHADOW_SIZE)
> +
> +#define KASAN_SHADOW_OFFSET    (KASAN_SHADOW_END - (1ULL << \
> +                                       (64 - KASAN_SHADOW_SCALE_SHIFT)))
> +
> +void kasan_init(void);
> +asmlinkage void kasan_early_init(void);
> +
> +#endif
> +#endif
> +#endif /* __ASM_KASAN_H */
> diff --git a/arch/riscv/include/asm/pgtable-64.h b/arch/riscv/include/asm/pgtable-64.h
> index 7df8daa66cc8..777a1dddb3df 100644
> --- a/arch/riscv/include/asm/pgtable-64.h
> +++ b/arch/riscv/include/asm/pgtable-64.h
> @@ -59,6 +59,11 @@ static inline unsigned long pud_page_vaddr(pud_t pud)
>         return (unsigned long)pfn_to_virt(pud_val(pud) >> _PAGE_PFN_SHIFT);
>  }
>
> +static inline struct page *pud_page(pud_t pud)
> +{
> +       return pfn_to_page(pud_val(pud) >> _PAGE_PFN_SHIFT);
> +}
> +
>  #define pmd_index(addr) (((addr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
>
>  static inline pmd_t *pmd_offset(pud_t *pud, unsigned long addr)
> diff --git a/arch/riscv/include/asm/string.h b/arch/riscv/include/asm/string.h
> index 1b5d44585962..a4451f768826 100644
> --- a/arch/riscv/include/asm/string.h
> +++ b/arch/riscv/include/asm/string.h
> @@ -11,8 +11,17 @@
>
>  #define __HAVE_ARCH_MEMSET
>  extern asmlinkage void *memset(void *, int, size_t);
> +extern asmlinkage void *__memset(void *, int, size_t);
>
>  #define __HAVE_ARCH_MEMCPY
>  extern asmlinkage void *memcpy(void *, const void *, size_t);
> +extern asmlinkage void *__memcpy(void *, const void *, size_t);
>
> +// For those files which don't want to check by kasan.
> +#if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
> +
> +#define memcpy(dst, src, len) __memcpy(dst, src, len)
> +#define memset(s, c, n) __memset(s, c, n)
> +
> +#endif
>  #endif /* _ASM_RISCV_STRING_H */
> diff --git a/arch/riscv/kernel/head.S b/arch/riscv/kernel/head.S
> index 72f89b7590dd..95eca23cd811 100644
> --- a/arch/riscv/kernel/head.S
> +++ b/arch/riscv/kernel/head.S
> @@ -102,6 +102,9 @@ clear_bss_done:
>         sw zero, TASK_TI_CPU(tp)
>         la sp, init_thread_union + THREAD_SIZE
>
> +#ifdef CONFIG_KASAN
> +       call kasan_early_init
> +#endif
>         /* Start the kernel */
>         call parse_dtb
>         tail start_kernel
> diff --git a/arch/riscv/kernel/riscv_ksyms.c b/arch/riscv/kernel/riscv_ksyms.c
> index 4800cf703186..376bba7f65ce 100644
> --- a/arch/riscv/kernel/riscv_ksyms.c
> +++ b/arch/riscv/kernel/riscv_ksyms.c
> @@ -14,3 +14,5 @@ EXPORT_SYMBOL(__asm_copy_to_user);
>  EXPORT_SYMBOL(__asm_copy_from_user);
>  EXPORT_SYMBOL(memset);
>  EXPORT_SYMBOL(memcpy);
> +EXPORT_SYMBOL(__memset);
> +EXPORT_SYMBOL(__memcpy);
> diff --git a/arch/riscv/kernel/setup.c b/arch/riscv/kernel/setup.c
> index a990a6cb184f..41f7eae9bc4d 100644
> --- a/arch/riscv/kernel/setup.c
> +++ b/arch/riscv/kernel/setup.c
> @@ -23,6 +23,7 @@
>  #include <asm/smp.h>
>  #include <asm/tlbflush.h>
>  #include <asm/thread_info.h>
> +#include <asm/kasan.h>
>
>  #ifdef CONFIG_DUMMY_CONSOLE
>  struct screen_info screen_info = {
> @@ -70,6 +71,10 @@ void __init setup_arch(char **cmdline_p)
>         swiotlb_init(1);
>  #endif
>
> +#ifdef CONFIG_KASAN
> +       kasan_init();
> +#endif
> +
>  #ifdef CONFIG_SMP
>         setup_smp();
>  #endif
> diff --git a/arch/riscv/kernel/vmlinux.lds.S b/arch/riscv/kernel/vmlinux.lds.S
> index 23cd1a9e52a1..97009803ba9f 100644
> --- a/arch/riscv/kernel/vmlinux.lds.S
> +++ b/arch/riscv/kernel/vmlinux.lds.S
> @@ -46,6 +46,7 @@ SECTIONS
>                 KPROBES_TEXT
>                 ENTRY_TEXT
>                 IRQENTRY_TEXT
> +               SOFTIRQENTRY_TEXT
>                 *(.fixup)
>                 _etext = .;
>         }
> diff --git a/arch/riscv/lib/memcpy.S b/arch/riscv/lib/memcpy.S
> index b4c477846e91..51ab716253fa 100644
> --- a/arch/riscv/lib/memcpy.S
> +++ b/arch/riscv/lib/memcpy.S
> @@ -7,7 +7,8 @@
>  #include <asm/asm.h>
>
>  /* void *memcpy(void *, const void *, size_t) */
> -ENTRY(memcpy)
> +ENTRY(__memcpy)
> +WEAK(memcpy)
>         move t6, a0  /* Preserve return value */
>
>         /* Defer to byte-oriented copy for small sizes */
> @@ -104,4 +105,4 @@ ENTRY(memcpy)
>         bltu a1, a3, 5b
>  6:
>         ret
> -END(memcpy)
> +END(__memcpy)
> diff --git a/arch/riscv/lib/memset.S b/arch/riscv/lib/memset.S
> index 5a7386b47175..34c5360c6705 100644
> --- a/arch/riscv/lib/memset.S
> +++ b/arch/riscv/lib/memset.S
> @@ -8,7 +8,8 @@
>  #include <asm/asm.h>
>
>  /* void *memset(void *, int, size_t) */
> -ENTRY(memset)
> +ENTRY(__memset)
> +WEAK(memset)
>         move t0, a0  /* Preserve return value */
>
>         /* Defer to byte-oriented fill for small sizes */
> @@ -109,4 +110,4 @@ ENTRY(memset)
>         bltu t0, a3, 5b
>  6:
>         ret
> -END(memset)
> +END(__memset)
> diff --git a/arch/riscv/mm/Makefile b/arch/riscv/mm/Makefile
> index 9d9a17335686..b8a8ca71f86e 100644
> --- a/arch/riscv/mm/Makefile
> +++ b/arch/riscv/mm/Makefile
> @@ -17,3 +17,9 @@ ifeq ($(CONFIG_MMU),y)
>  obj-$(CONFIG_SMP) += tlbflush.o
>  endif
>  obj-$(CONFIG_HUGETLB_PAGE) += hugetlbpage.o
> +obj-$(CONFIG_KASAN)   += kasan_init.o
> +
> +ifdef CONFIG_KASAN
> +KASAN_SANITIZE_kasan_init.o := n
> +KASAN_SANITIZE_init.o := n
> +endif
> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> new file mode 100644
> index 000000000000..c3152768cdbe
> --- /dev/null
> +++ b/arch/riscv/mm/kasan_init.c
> @@ -0,0 +1,104 @@
> +// SPDX-License-Identifier: GPL-2.0
> +// Copyright (C) 2019 Andes Technology Corporation
> +
> +#include <linux/pfn.h>
> +#include <linux/init_task.h>
> +#include <linux/kasan.h>
> +#include <linux/kernel.h>
> +#include <linux/memblock.h>
> +#include <asm/tlbflush.h>
> +#include <asm/pgtable.h>
> +#include <asm/fixmap.h>
> +
> +extern pgd_t early_pg_dir[PTRS_PER_PGD];
> +asmlinkage void __init kasan_early_init(void)
> +{
> +       uintptr_t i;
> +       pgd_t *pgd = early_pg_dir + pgd_index(KASAN_SHADOW_START);
> +
> +       for (i = 0; i < PTRS_PER_PTE; ++i)
> +               set_pte(kasan_early_shadow_pte + i,
> +                       mk_pte(virt_to_page(kasan_early_shadow_page),
> +                       PAGE_KERNEL));
> +
> +       for (i = 0; i < PTRS_PER_PMD; ++i)
> +               set_pmd(kasan_early_shadow_pmd + i,
> +                pfn_pmd(PFN_DOWN(__pa((uintptr_t)kasan_early_shadow_pte)),
> +                       __pgprot(_PAGE_TABLE)));
> +
> +       for (i = KASAN_SHADOW_START; i < KASAN_SHADOW_END;
> +            i += PGDIR_SIZE, ++pgd)
> +               set_pgd(pgd,
> +                pfn_pgd(PFN_DOWN(__pa(((uintptr_t)kasan_early_shadow_pmd))),
> +                       __pgprot(_PAGE_TABLE)));
> +
> +       // init for swapper_pg_dir
> +       pgd = pgd_offset_k(KASAN_SHADOW_START);
> +
> +       for (i = KASAN_SHADOW_START; i < KASAN_SHADOW_END;
> +            i += PGDIR_SIZE, ++pgd)
> +               set_pgd(pgd,
> +                pfn_pgd(PFN_DOWN(__pa(((uintptr_t)kasan_early_shadow_pmd))),
> +                       __pgprot(_PAGE_TABLE)));
> +
> +       flush_tlb_all();
> +}
> +
> +static void __init populate(void *start, void *end)
> +{
> +       unsigned long i;
> +       unsigned long vaddr = (unsigned long)start & PAGE_MASK;
> +       unsigned long vend = PAGE_ALIGN((unsigned long)end);
> +       unsigned long n_pages = (vend - vaddr) / PAGE_SIZE;
> +       unsigned long n_pmds =
> +               (n_pages % PTRS_PER_PTE) ? n_pages / PTRS_PER_PTE + 1 :
> +                                               n_pages / PTRS_PER_PTE;
> +       pgd_t *pgd = pgd_offset_k(vaddr);
> +       pmd_t *pmd = memblock_alloc(n_pmds * sizeof(pmd_t), PAGE_SIZE);
> +       pte_t *pte = memblock_alloc(n_pages * sizeof(pte_t), PAGE_SIZE);
> +
> +       for (i = 0; i < n_pages; i++) {
> +               phys_addr_t phys = memblock_phys_alloc(PAGE_SIZE, PAGE_SIZE);
> +
> +               set_pte(pte + i, pfn_pte(PHYS_PFN(phys), PAGE_KERNEL));
> +       }
> +
> +       for (i = 0; i < n_pages; ++pmd, i += PTRS_PER_PTE)
> +               set_pmd(pmd, pfn_pmd(PFN_DOWN(__pa((uintptr_t)(pte + i))),
> +                               __pgprot(_PAGE_TABLE)));
> +
> +       for (i = vaddr; i < vend; i += PGDIR_SIZE, ++pgd)
> +               set_pgd(pgd, pfn_pgd(PFN_DOWN(__pa(((uintptr_t)pmd))),
> +                               __pgprot(_PAGE_TABLE)));
> +
> +       flush_tlb_all();
> +       memset(start, 0, end - start);
> +}
> +
> +void __init kasan_init(void)
> +{
> +       struct memblock_region *reg;
> +       unsigned long i;
> +
> +       kasan_populate_early_shadow((void *)KASAN_SHADOW_START,
> +                       (void *)kasan_mem_to_shadow((void *)VMALLOC_END));
> +
> +       for_each_memblock(memory, reg) {
> +               void *start = (void *)__va(reg->base);
> +               void *end = (void *)__va(reg->base + reg->size);
> +
> +               if (start >= end)
> +                       break;
> +
> +               populate(kasan_mem_to_shadow(start),
> +                        kasan_mem_to_shadow(end));
> +       };
> +
> +       for (i = 0; i < PTRS_PER_PTE; i++)
> +               set_pte(&kasan_early_shadow_pte[i],
> +                       mk_pte(virt_to_page(kasan_early_shadow_page),
> +                       __pgprot(_PAGE_PRESENT | _PAGE_READ | _PAGE_ACCESSED)));
> +
> +       memset(kasan_early_shadow_page, 0, PAGE_SIZE);
> +       init_task.kasan_depth = 0;
> +}
> --
> 2.17.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8d86d53e904bece0623cb8969cdc70f782fa2bae.1569995450.git.nickhu%40andestech.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BymEX7qnYi61cAyxtY5qd%2B_HV%3DxQotbOaCg_DtMA%3DpeWA%40mail.gmail.com.
