Return-Path: <kasan-dev+bncBDAIRSWYXQGRBEPXWXWQKGQEZIDNMWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3a.google.com (mail-vs1-xe3a.google.com [IPv6:2607:f8b0:4864:20::e3a])
	by mail.lfdr.de (Postfix) with ESMTPS id D7CDADE821
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2019 11:34:10 +0200 (CEST)
Received: by mail-vs1-xe3a.google.com with SMTP id d9sf2712213vsq.20
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2019 02:34:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571650449; cv=pass;
        d=google.com; s=arc-20160816;
        b=vKiC19U6IBdVub1YhojJsaWLqXIHxYnj14w+KUeRwwKfrU3+7n0uuNQ90v2u1HDOCE
         0AsWKFty5QllBAeWbI7NFXoi1dX4jWrEsRRynrhxFK/Wj0m+CVSHnNbO6lnMQtGnIBNi
         3iMS1f2+x9gu3zZjY2JS6jJJRa174AY9ifCZFsAVNj2lSsBdCREjHeM/0RRENyIbvIaf
         8gz4MZ7P00HSSnC6c8cuEvsWrGPYxu4ckbPXbFBfZozMEyphi5UQfK1SG1+/EBx483j0
         ZuSgfo7qUW8Old7Te2QMF/RAn/6ZvxVaAkCxRz6nO5oOxpmS6gkhdZKJp3adeD9TIrJo
         9/hg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Q1E3Ycq3IfDM5GUNqTsBJXai+SsM/UH0GTu3CJbd23g=;
        b=L+pWhwaLcYTZJX0A++A503zisAMM2PLafbbCt/k1thIM3GzXJx/2Pq6sswaWoOYITp
         mGK8mkYzBIWL4LdcfLoT4lblgcYyV7/3WewVilBReqnmIYaA8i3lqikDhMf8uz2lZ2tU
         aG1Fu85iVjqqIZw5Xn1vaSFiJ9JHBwX7B/aRRBc/oPwIzsmO5fAcZzrBi/e0GF9lXqMY
         qtus/7uqIO+D2AiF5/UACNsbm9EYR/jQP2+q7N+pCoSIxV6VSrYwtjMIfY+GXutyMXiU
         ejLAFxokov91KwepF0g2EGGBUx58u2eEpS9YclH6lcSW5lZaXnV1zq9YyUGdRrIOnesY
         qY+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=L+kNgEV8;
       spf=pass (google.com: domain of green.hu@gmail.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=green.hu@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Q1E3Ycq3IfDM5GUNqTsBJXai+SsM/UH0GTu3CJbd23g=;
        b=VzumLYwccnafxdiInL9mM2D2sGuoWRB3Hf1hgkcgeitWzO6nji5y9fabCkp5C9ZHiQ
         lPAmM72ebu0wBzinrCVRPwpEHwW6QoaPafkL7h/J2HL9xbAsUvZjk3ObdbXZqgXg2d3v
         /LymoI6ye6H6vxG98aL3XdVshWvcwQPmm47Z1e/R1ZoZMcPderu6USXf2g2l5z9G2U7t
         LZwAjkP1zWVxNGSihdudaa06RGnz4FsXxu4CmgNcpRVTz8Md/Ua8WvRu9/i1/sXWKTV9
         jJwYDa37BOFrsPYsZtXqZKtLc0pkJrscv8ZEb538qejmLBS5Xd146mSLzHXcGZ2vZNzk
         7jWg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Q1E3Ycq3IfDM5GUNqTsBJXai+SsM/UH0GTu3CJbd23g=;
        b=s5rTbOluDaXteGO8z57y40JgbRGbJqrZh/+8cW7pjdQCP215I0mXdPK2P4845IPEWI
         3B8+tQeQbM+1i+7DVUOlG175sbDQzgvnrQbHzeJhHbG4jkT1EgE/8CJa7SsjSkn+4Mrd
         DQKgf6EOeToVCfEDcDyrDavEjIDVYWeSbyv/FuZasF5/z90U3QKpiHteo5rlThcuow1c
         CniNp3dbJ3IpmakPbrkqjqO6Ko/tyjJSluV1NeN90DdVmNODMaeV1ChJRap7pIPiXQz7
         klonJL4JNNkdwVTDedVfpTQvXKQGSxfhNZ3IWpTONg4bW4gtaKaj49gFq17y7ZlwE5Sz
         l3mg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Q1E3Ycq3IfDM5GUNqTsBJXai+SsM/UH0GTu3CJbd23g=;
        b=hzLaK8WIZlLcXInWyx9GmyOaRQCM5s2dOhGCJ0u9uq5ARXPucRZiPAjUJFnemUBOp3
         QsfuWyQRnrojOIaBU6zBs4BNNMP25R3+J7p+UzFrnpoKG3zhwFfD3J2c2GtdBt+rNvIJ
         GPZfXy21dCG9IndNvA8IKqLuIrybnWG9zTRzqSjX5h8IosnexU1qbLGcXB3g8fm1kafv
         VHvxrtBcugmo6e+4tiXrTF85/dh0B8yWbkHZzT5ql4DACMo/dckoQLZC2CyqgydH6wTO
         w6TJoCLPedipyf5w7B84q2WGdJ159UGflvW9o1FVmdOaLPhpRfmvgCbTTz0AyRbsXUHj
         llWw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUZplzISt5aBYnEK4TjoIAza4Sg/rcmh0WH70uQmCy8l0fxa4ud
	eVmZdPp1x9DHWrjwpL6VaC0=
X-Google-Smtp-Source: APXvYqwjn06cmsGHKaYvXGSjINSvzu7i4y43Palb+wMTJjSzY9krfiKrX3PYjwA5ERof3RDDkYwddQ==
X-Received: by 2002:a67:b84e:: with SMTP id o14mr13306146vsh.149.1571650449686;
        Mon, 21 Oct 2019 02:34:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:27ea:: with SMTP id b97ls637011uab.14.gmail; Mon, 21 Oct
 2019 02:34:09 -0700 (PDT)
X-Received: by 2002:ab0:2015:: with SMTP id v21mr12250782uak.94.1571650449170;
        Mon, 21 Oct 2019 02:34:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571650449; cv=none;
        d=google.com; s=arc-20160816;
        b=LP0FtalG5QsCUDfOh31uGSfv5UnW8HmtHCBPSoXo0dP0MbZycIrNQbXSo1d0eDWDAp
         q3hL0S+c+uULk44LvT0dzumyoWzuXSyMFbN136ankvD9klQgdIV2oYjd6Z2SyyYgy9GR
         FoeU+UmdbgLo52PaqUQVVqYnf6HFie7aTh/tGEZh0xKggfIJ1xAvjb00+6MB5Ap1fFmn
         2RWQXNvkCGNAT4rvOkbgj5MgkxonXdbbZBdE7v1qNT0IeW+qXNMQth6BWXIN2EmeIHjo
         7jQQQmN/WUaqV+1D1XBJZtYO6HdmWMv5ThZHzRn/8gsECg+oMxy2UKSehQfpgUoyqlsR
         HX+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=8CxkzgTmPkrymJWAPgp0fFXJhTloQdA6b1Ea9fnYKuY=;
        b=uXIYaPo1ZOm/1GiNiuYj4ZP55fZpaKEt3/d//IM1P2OsB/WDxKVk6WtHhP870eJiN0
         Ndhb8KQXzEDipW5c123Kt8Hqvz9FgGp+EWk/rSFy2hiFIwfwjuHHha2ZKnL3lt0/HFL4
         jmDFcRnc9xfZdoWzggfEvclPCCcGbk4RP3ucQofUhg2nNMx4tvBY5dXILEJbG5KGeMjm
         zfuLRBJ2ts0VavI6zbYk8cfuv8KITBR6ff/UqZRI0ntKDeGSS2oG+Z9e7SwdNAbr6qXc
         WChDHZg4Oa5HG5tserluefRUJXnZ+LsfoQAj+VbYNLt3oJsDhQuty9l0r1A8ElkdqaW3
         2pAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=L+kNgEV8;
       spf=pass (google.com: domain of green.hu@gmail.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=green.hu@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id u65si635604vsb.0.2019.10.21.02.34.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Oct 2019 02:34:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of green.hu@gmail.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id u40so19958593qth.11
        for <kasan-dev@googlegroups.com>; Mon, 21 Oct 2019 02:34:09 -0700 (PDT)
X-Received: by 2002:ac8:24d4:: with SMTP id t20mr23895504qtt.114.1571650448518;
 Mon, 21 Oct 2019 02:34:08 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1570514544.git.nickhu@andestech.com> <8d86d53e904bece0623cb8969cdc70f782fa2bae.1570514544.git.nickhu@andestech.com>
In-Reply-To: <8d86d53e904bece0623cb8969cdc70f782fa2bae.1570514544.git.nickhu@andestech.com>
From: Greentime Hu <green.hu@gmail.com>
Date: Mon, 21 Oct 2019 17:33:31 +0800
Message-ID: <CAEbi=3fTKqt545tEz6c-RCdKniq2ZxOqvamFpJsbe=D+gpGBcQ@mail.gmail.com>
Subject: Re: [PATCH v3 2/3] riscv: Add KASAN support
To: Nick Hu <nickhu@andestech.com>, Greentime Hu <greentime.hu@sifive.com>
Cc: alankao@andestech.com, Paul Walmsley <paul.walmsley@sifive.com>, 
	Palmer Dabbelt <palmer@sifive.com>, Albert Ou <aou@eecs.berkeley.edu>, aryabinin@virtuozzo.com, 
	glider@google.com, dvyukov@google.com, corbet@lwn.net, 
	alexios.zavras@intel.com, allison@lohutok.net, Anup.Patel@wdc.com, 
	Thomas Gleixner <tglx@linutronix.de>, gregkh@linuxfoundation.org, atish.patra@wdc.com, 
	Kate Stewart <kstewart@linuxfoundation.org>, linux-doc@vger.kernel.org, 
	linux-riscv@lists.infradead.org, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: green.hu@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=L+kNgEV8;       spf=pass
 (google.com: domain of green.hu@gmail.com designates 2607:f8b0:4864:20::841
 as permitted sender) smtp.mailfrom=green.hu@gmail.com;       dmarc=pass
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

Nick Hu <nickhu@andestech.com> =E6=96=BC 2019=E5=B9=B410=E6=9C=888=E6=97=A5=
 =E9=80=B1=E4=BA=8C =E4=B8=8B=E5=8D=882:17=E5=AF=AB=E9=81=93=EF=BC=9A
>
> This patch ports the feature Kernel Address SANitizer (KASAN).
>
> Note: The start address of shadow memory is at the beginning of kernel
> space, which is 2^64 - (2^39 / 2) in SV39. The size of the kernel space i=
s
> 2^38 bytes so the size of shadow memory should be 2^38 / 8. Thus, the
> shadow memory would not overlap with the fixmap area.
>
> There are currently two limitations in this port,
>
> 1. RV64 only: KASAN need large address space for extra shadow memory
> region.
>
> 2. KASAN can't debug the modules since the modules are allocated in VMALL=
OC
> area. We mapped the shadow memory, which corresponding to VMALLOC area, t=
o
> the kasan_early_shadow_page because we don't have enough physical space f=
or
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
> diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/kasa=
n.h
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
> +#define KASAN_SHADOW_SIZE      (UL(1) << (38 - KASAN_SHADOW_SCALE_SHIFT)=
)
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
> diff --git a/arch/riscv/include/asm/pgtable-64.h b/arch/riscv/include/asm=
/pgtable-64.h
> index 7df8daa66cc8..777a1dddb3df 100644
> --- a/arch/riscv/include/asm/pgtable-64.h
> +++ b/arch/riscv/include/asm/pgtable-64.h
> @@ -59,6 +59,11 @@ static inline unsigned long pud_page_vaddr(pud_t pud)
>         return (unsigned long)pfn_to_virt(pud_val(pud) >> _PAGE_PFN_SHIFT=
);
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
> diff --git a/arch/riscv/include/asm/string.h b/arch/riscv/include/asm/str=
ing.h
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
> diff --git a/arch/riscv/kernel/riscv_ksyms.c b/arch/riscv/kernel/riscv_ks=
yms.c
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
>  struct screen_info screen_info =3D {
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
> diff --git a/arch/riscv/kernel/vmlinux.lds.S b/arch/riscv/kernel/vmlinux.=
lds.S
> index 23cd1a9e52a1..97009803ba9f 100644
> --- a/arch/riscv/kernel/vmlinux.lds.S
> +++ b/arch/riscv/kernel/vmlinux.lds.S
> @@ -46,6 +46,7 @@ SECTIONS
>                 KPROBES_TEXT
>                 ENTRY_TEXT
>                 IRQENTRY_TEXT
> +               SOFTIRQENTRY_TEXT
>                 *(.fixup)
>                 _etext =3D .;
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
>  obj-$(CONFIG_SMP) +=3D tlbflush.o
>  endif
>  obj-$(CONFIG_HUGETLB_PAGE) +=3D hugetlbpage.o
> +obj-$(CONFIG_KASAN)   +=3D kasan_init.o
> +
> +ifdef CONFIG_KASAN
> +KASAN_SANITIZE_kasan_init.o :=3D n
> +KASAN_SANITIZE_init.o :=3D n
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
> +       pgd_t *pgd =3D early_pg_dir + pgd_index(KASAN_SHADOW_START);
> +
> +       for (i =3D 0; i < PTRS_PER_PTE; ++i)
> +               set_pte(kasan_early_shadow_pte + i,
> +                       mk_pte(virt_to_page(kasan_early_shadow_page),
> +                       PAGE_KERNEL));
> +
> +       for (i =3D 0; i < PTRS_PER_PMD; ++i)
> +               set_pmd(kasan_early_shadow_pmd + i,
> +                pfn_pmd(PFN_DOWN(__pa((uintptr_t)kasan_early_shadow_pte)=
),
> +                       __pgprot(_PAGE_TABLE)));
> +
> +       for (i =3D KASAN_SHADOW_START; i < KASAN_SHADOW_END;
> +            i +=3D PGDIR_SIZE, ++pgd)
> +               set_pgd(pgd,
> +                pfn_pgd(PFN_DOWN(__pa(((uintptr_t)kasan_early_shadow_pmd=
))),
> +                       __pgprot(_PAGE_TABLE)));
> +
> +       // init for swapper_pg_dir
> +       pgd =3D pgd_offset_k(KASAN_SHADOW_START);
> +
> +       for (i =3D KASAN_SHADOW_START; i < KASAN_SHADOW_END;
> +            i +=3D PGDIR_SIZE, ++pgd)
> +               set_pgd(pgd,
> +                pfn_pgd(PFN_DOWN(__pa(((uintptr_t)kasan_early_shadow_pmd=
))),
> +                       __pgprot(_PAGE_TABLE)));
> +
> +       flush_tlb_all();
> +}
> +
> +static void __init populate(void *start, void *end)
> +{
> +       unsigned long i;
> +       unsigned long vaddr =3D (unsigned long)start & PAGE_MASK;
> +       unsigned long vend =3D PAGE_ALIGN((unsigned long)end);
> +       unsigned long n_pages =3D (vend - vaddr) / PAGE_SIZE;
> +       unsigned long n_pmds =3D
> +               (n_pages % PTRS_PER_PTE) ? n_pages / PTRS_PER_PTE + 1 :
> +                                               n_pages / PTRS_PER_PTE;
> +       pgd_t *pgd =3D pgd_offset_k(vaddr);
> +       pmd_t *pmd =3D memblock_alloc(n_pmds * sizeof(pmd_t), PAGE_SIZE);
> +       pte_t *pte =3D memblock_alloc(n_pages * sizeof(pte_t), PAGE_SIZE)=
;
> +
> +       for (i =3D 0; i < n_pages; i++) {
> +               phys_addr_t phys =3D memblock_phys_alloc(PAGE_SIZE, PAGE_=
SIZE);
> +
> +               set_pte(pte + i, pfn_pte(PHYS_PFN(phys), PAGE_KERNEL));
> +       }
> +
> +       for (i =3D 0; i < n_pages; ++pmd, i +=3D PTRS_PER_PTE)
> +               set_pmd(pmd, pfn_pmd(PFN_DOWN(__pa((uintptr_t)(pte + i)))=
,
> +                               __pgprot(_PAGE_TABLE)));
> +
> +       for (i =3D vaddr; i < vend; i +=3D PGDIR_SIZE, ++pgd)
> +               set_pgd(pgd, pfn_pgd(PFN_DOWN(__pa(((uintptr_t)pmd))),
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
> +                               __pgprot(_PAGE_TABLE)));
> +

Hi Nick,

I verify this patch in Qemu and Unleashed board.
I found it works well if DRAM size is less than 4GB.
It will get an access fault if the DRAM size is larger than 4GB.

I spend some time to debug this case and I found it hang in the
following memset().
It is because the mapping is not created correctly. I check the page
table creating logic again and I found it always sets the last pmd
here.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAEbi%3D3fTKqt545tEz6c-RCdKniq2ZxOqvamFpJsbe%3DD%2BgpGBcQ%40mail.=
gmail.com.
