Return-Path: <kasan-dev+bncBAABBPUPQ6TAMGQENT3FTCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 27496764365
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Jul 2023 03:26:24 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-403a4cdbfa2sf4032061cf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jul 2023 18:26:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690421183; cv=pass;
        d=google.com; s=arc-20160816;
        b=kobE2UjOYYhdgS2njR14G8oBkBeHgi7VmIat+rq3ekMhHO7rLDlpSFYwqSnyvw4jBu
         li4ACUV0tR5Ej1eUEUgENv7d6bfAQg4mLusJhu+8W2wc98zCQlYo9Bh6R1kK6Y9/kwxK
         lBToGMS/6h1q8YTrKbBtWUsQ3TfoKkZLZS+sM4zzblDh1MItYdtCuMq8es6b8qjZThxz
         Ld3AJMVQ4sHRkfaH+AaTkxdivrUZrRZB/ShOH7ZRFRG3xiu5w8B3XGJ48zPkrZv4vkQC
         gDzj97JNkY2o2bH1yVJZ2tbMkSs+iztdShJ54OdJbSrR5/e7SIiS+ZxDxyb2k3j3FzbC
         VByA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=F+QOMp5OXZfGpUi/vSnukLkaBvaE/VoD/qHlRMDLAQY=;
        fh=sy4SP3vkEn2BvwOVbcJ42LyDgXjWTkePGWUGK7C0j7Y=;
        b=jdzrvEWQJHpZBH9b2wHrTOPqNf3N/0IojIScJYfYFFVk2TlLm1l0ne9lbYfa9PapC/
         6KKmZEHG7yb14DFPWp4f+79QJAFbOZN1ecE6A5q5BMHx1ULv7seFu7Gceaoc39Ks1z0k
         RLsP83XCgZQzsFXWEDSrUVzU+KawGqQA63AVeRRYcO16PA4egG/9usIOfXgD/dgOC4sc
         yhpqZ+NREmFrw6pAGL18AuDep/4mCDt9pYMX1iSLY4StA8P/xnx5BJA9/OWxravhigp8
         xk5CTfhaNnBvTly4MzaiUhmopdWmPwCfdGYoOrEsHpb8hBOX//NTP1/QGP8S4NCU2b8C
         2TQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=n0mF130n;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690421183; x=1691025983;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=F+QOMp5OXZfGpUi/vSnukLkaBvaE/VoD/qHlRMDLAQY=;
        b=XJ4CNqKTz5KiAK4xINb5T/7UlknYZvVXRGYIRGzzyAnnsFzj+KC6+EYPmQqvPHM/0W
         kYdxgss90cVBMUbsjUeCIdjq9U0gUIIT4vUg+IVOG6cHkH3Q+5QGe08UHnvRuya7W844
         yEfi4OdnNGfZJCdlcj8XNXNZsTb3r1RkWqL9p6H+QyAhptEHbw7GzY9TWv8wVWPsMPY/
         Fvgdezzb0tfOvicxfF6z9epCQbSbixrpZyL69sTgV6T7rwSuVNcQ+aNnoBiWYyPpUDa8
         eUh3E0t3N0CoQcqwvvg1GBlwJKGgjcqr7X0Sb+0WoyoRYG+OWomHdVsvKsduLD3kduTU
         v0Hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690421183; x=1691025983;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=F+QOMp5OXZfGpUi/vSnukLkaBvaE/VoD/qHlRMDLAQY=;
        b=UjvWDlW9g3WBZGFL3eMl9DF7Ix0202diCeUB9mf99M3dFwY3qk+t4luJ6YEi3dUMJ1
         2fTNSZo/u1Ny+UmwyjQRCWC+hO5Tjmre7AYqQ513AK7fYoHE6QvWUww+I1gkJqDOI3RS
         rgeVE8QLUc/eNKLMqT4NIz4gQwuQVl7Db+reNWveDS3qgzlQmYvfdesFnrcHeF983Hvz
         iO1MIARM6gsdUXXG0jKCbfMkj2J35cJnsSvrFpchsFUvvbpLvppnE1hkqNWuyjANjDGZ
         Fy+nvcmLtZHUbZuefBZn0ipwS0NFX+pdRIA+KQWtrDRY5ZHwAEd7BuMphun07K0aNCui
         QQfg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLZKuonJ0BBpZB/X9OmFzc2r2Bl++yYwG1uaXqtp90xXMJghNLJh
	iieHCFdYKnYwXEyThxagotI=
X-Google-Smtp-Source: APBJJlFuKtUU04xoV9eMgJowpdBKCtVYqs8JgG4Ix7o+DfYZssYUF8V9D7eoDMV0tK4RndUgQyHEwg==
X-Received: by 2002:a05:622a:1491:b0:403:ce1f:fd51 with SMTP id t17-20020a05622a149100b00403ce1ffd51mr4903533qtx.55.1690421182747;
        Wed, 26 Jul 2023 18:26:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:2c0b:b0:403:c0cb:532d with SMTP id
 kk11-20020a05622a2c0b00b00403c0cb532dls292694qtb.1.-pod-prod-05-us; Wed, 26
 Jul 2023 18:26:21 -0700 (PDT)
X-Received: by 2002:a05:620a:2211:b0:767:82e8:eb88 with SMTP id m17-20020a05620a221100b0076782e8eb88mr3436752qkh.7.1690421181700;
        Wed, 26 Jul 2023 18:26:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690421181; cv=none;
        d=google.com; s=arc-20160816;
        b=TiuV6GdjN4wcrW66FRwu8cAMpkv6EJYL2R3FQT4cXG/E2sJuT6pYJGkVCtNFudTHFl
         qw3kYIdLWIfKanN36pHNIfW2tUQBvcUU3z++rhN5wFY3eeWzfOQamfo28xLft1r3cRZ3
         /MV3VaOH5g7c3/+g5HgHk6BOKlF7L3WhSbUshPne/g7BrnXYH/qmhxlERcj+BCLVbWLV
         3XbE5Y5RCvUR2Rlr05w2wHgMtTsSJattBLqdgElKxkdbioHWhiC9OB5HyJWdSWzhShIC
         YV/YDCXmKIAW1EGm6KaSYQw3u3/R/EeXV7w56P5otlxQ+leMaKYD3b0w++QLU3riUyVz
         yj+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=kF2KsmExiWYczznuEgVtdNQkEJ9KvvlP0zAgsbXMSzU=;
        fh=sy4SP3vkEn2BvwOVbcJ42LyDgXjWTkePGWUGK7C0j7Y=;
        b=cFAA/wGlsCdzZMN+rY/NXRojC0ICe3XQgZfRnc89psdteNOUX4oB7GdQBWRem4JH6R
         eVapPhuHvmjiv9I6jKjftieJ/IfR19pLi/2Iur47Tb3bSbD2jH8MuShQQPmDq7mk9bpz
         vrSiTc9Y92t0Y7cDHhwpK4a2U+hpHEPT1lexgPDakNRdkUVTNGplnHK5EKrmghH06tRS
         HMn47APW0HaeyBKLNGzf19PzxC8DIup62l4SVJbxSeeyzSJExE68dU83glJTvX0uzNwA
         DRy0DtzJ+W6nAUVkTK/3EWj7eN5leN02XIcyVKDZHvSLQbWxcIh2LQof5yUGnm28dpxH
         k64g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=n0mF130n;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id i2-20020a05620a27c200b0076709fdb678si11590qkp.4.2023.07.26.18.26.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 26 Jul 2023 18:26:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 2595561A4F
	for <kasan-dev@googlegroups.com>; Thu, 27 Jul 2023 01:26:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8BC9AC433CB
	for <kasan-dev@googlegroups.com>; Thu, 27 Jul 2023 01:26:20 +0000 (UTC)
Received: by mail-ej1-f50.google.com with SMTP id a640c23a62f3a-99bc0a20b54so45473966b.1
        for <kasan-dev@googlegroups.com>; Wed, 26 Jul 2023 18:26:20 -0700 (PDT)
X-Received: by 2002:a17:906:845c:b0:993:eddd:6df4 with SMTP id
 e28-20020a170906845c00b00993eddd6df4mr641132ejy.10.1690421178609; Wed, 26 Jul
 2023 18:26:18 -0700 (PDT)
MIME-Version: 1.0
References: <20230725061451.1231480-1-lienze@kylinos.cn> <20230725061451.1231480-5-lienze@kylinos.cn>
In-Reply-To: <20230725061451.1231480-5-lienze@kylinos.cn>
From: Huacai Chen <chenhuacai@kernel.org>
Date: Thu, 27 Jul 2023 09:26:04 +0800
X-Gmail-Original-Message-ID: <CAAhV-H4RB4SDpdozkktq45yRbextEUctXEYy+t+6gKONytwKQA@mail.gmail.com>
Message-ID: <CAAhV-H4RB4SDpdozkktq45yRbextEUctXEYy+t+6gKONytwKQA@mail.gmail.com>
Subject: Re: [PATCH 4/4 v2] LoongArch: Add KFENCE support
To: Enze Li <lienze@kylinos.cn>
Cc: kernel@xen0n.name, loongarch@lists.linux.dev, glider@google.com, 
	elver@google.com, akpm@linux-foundation.org, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, zhangqing@loongson.cn, yangtiezhu@loongson.cn, 
	dvyukov@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=n0mF130n;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Jul 25, 2023 at 2:15=E2=80=AFPM Enze Li <lienze@kylinos.cn> wrote:
>
> The LoongArch architecture is quite different from other architectures.
> When the allocating of KFENCE itself is done, it is mapped to the direct
> mapping configuration window [1] by default on LoongArch.  It means that
> it is not possible to use the page table mapped mode which required by
> the KFENCE system and therefore it should be remapped to the appropriate
> region.
>
> This patch adds architecture specific implementation details for KFENCE.
> In particular, this implements the required interface in <asm/kfence.h>.
>
> Tested this patch by running the testcases and all passed.
>
> [1] https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.=
html#virtual-address-space-and-address-translation-mode
>
> Signed-off-by: Enze Li <lienze@kylinos.cn>
> ---
>  arch/loongarch/Kconfig               |  1 +
>  arch/loongarch/include/asm/kfence.h  | 62 ++++++++++++++++++++++++++++
>  arch/loongarch/include/asm/pgtable.h | 14 ++++++-
>  arch/loongarch/mm/fault.c            | 22 ++++++----
>  4 files changed, 90 insertions(+), 9 deletions(-)
>  create mode 100644 arch/loongarch/include/asm/kfence.h
>
> diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
> index 70635ea3d1e4..5b63b16be49e 100644
> --- a/arch/loongarch/Kconfig
> +++ b/arch/loongarch/Kconfig
> @@ -91,6 +91,7 @@ config LOONGARCH
>         select HAVE_ARCH_AUDITSYSCALL
>         select HAVE_ARCH_JUMP_LABEL
>         select HAVE_ARCH_JUMP_LABEL_RELATIVE
> +       select HAVE_ARCH_KFENCE
>         select HAVE_ARCH_MMAP_RND_BITS if MMU
>         select HAVE_ARCH_SECCOMP_FILTER
>         select HAVE_ARCH_TRACEHOOK
> diff --git a/arch/loongarch/include/asm/kfence.h b/arch/loongarch/include=
/asm/kfence.h
> new file mode 100644
> index 000000000000..fb39076fe4d7
> --- /dev/null
> +++ b/arch/loongarch/include/asm/kfence.h
> @@ -0,0 +1,62 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +/*
> + * KFENCE support for LoongArch.
> + *
> + * Author: Enze Li <lienze@kylinos.cn>
> + * Copyright (C) 2022-2023 KylinSoft Corporation.
> + */
> +
> +#ifndef _ASM_LOONGARCH_KFENCE_H
> +#define _ASM_LOONGARCH_KFENCE_H
> +
> +#include <linux/kfence.h>
> +#include <asm/pgtable.h>
> +#include <asm/tlb.h>
> +
> +static inline bool arch_kfence_init_pool(void)
> +{
> +       char *kfence_pool =3D __kfence_pool;
> +       struct vm_struct *area;
> +       int err;
> +
> +       area =3D __get_vm_area_caller(KFENCE_POOL_SIZE, VM_IOREMAP,
> +                                   KFENCE_AREA_START, KFENCE_AREA_END,
> +                                   __builtin_return_address(0));
> +       if (!area)
> +               return false;
> +
> +       __kfence_pool =3D (char *)area->addr;
> +       err =3D ioremap_page_range((unsigned long)__kfence_pool,
> +                                (unsigned long)__kfence_pool + KFENCE_PO=
OL_SIZE,
> +                                virt_to_phys((void *)kfence_pool),
> +                                PAGE_KERNEL);
> +       if (err) {
> +               free_vm_area(area);
> +               return false;
> +       }
> +
> +       return true;
> +}
> +
> +/* Protect the given page and flush TLB. */
> +static inline bool kfence_protect_page(unsigned long addr, bool protect)
> +{
> +       pte_t *pte =3D virt_to_kpte(addr);
> +
> +       if (WARN_ON(!pte) || pte_none(*pte))
> +               return false;
> +
> +       if (protect)
> +               set_pte(pte, __pte(pte_val(*pte) & ~(_PAGE_VALID | _PAGE_=
PRESENT)));
> +       else
> +               set_pte(pte, __pte(pte_val(*pte) | (_PAGE_VALID | _PAGE_P=
RESENT)));
> +
> +       /* Flush this CPU's TLB. */
> +       preempt_disable();
> +       local_flush_tlb_one(addr);
> +       preempt_enable();
> +
> +       return true;
> +}
> +
> +#endif /* _ASM_LOONGARCH_KFENCE_H */
> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/includ=
e/asm/pgtable.h
> index 98a0c98de9d1..2702a6ba7122 100644
> --- a/arch/loongarch/include/asm/pgtable.h
> +++ b/arch/loongarch/include/asm/pgtable.h
> @@ -77,6 +77,13 @@ extern unsigned long zero_page_mask;
>         (virt_to_page((void *)(empty_zero_page + (((unsigned long)(vaddr)=
) & zero_page_mask))))
>  #define __HAVE_COLOR_ZERO_PAGE
>
> +#ifdef CONFIG_KFENCE
> +#define KFENCE_AREA_SIZE \
> +       (((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 + 2) * PAGE_SIZE)
Another question: Why define KFENCE_AREA_SIZE while there is already
KFENCE_POOL_SIZE? And why is KFENCE_AREA_SIZE a little larger than
KFENCE_POOL_SIZE? If we can reuse KFENCE_POOL_SIZE,
KFENCE_AREA_START/KFENCE_AREA_END can be renamed to
KFENCE_POOL_START/KFENCE_POOL_END.

Huacai

> +#else
> +#define KFENCE_AREA_SIZE       0
> +#endif
> +
>  /*
>   * TLB refill handlers may also map the vmalloc area into xkvrange.
>   * Avoid the first couple of pages so NULL pointer dereferences will
> @@ -88,11 +95,16 @@ extern unsigned long zero_page_mask;
>  #define VMALLOC_START  MODULES_END
>  #define VMALLOC_END    \
>         (vm_map_base +  \
> -        min(PTRS_PER_PGD * PTRS_PER_PUD * PTRS_PER_PMD * PTRS_PER_PTE * =
PAGE_SIZE, (1UL << cpu_vabits)) - PMD_SIZE - VMEMMAP_SIZE)
> +        min(PTRS_PER_PGD * PTRS_PER_PUD * PTRS_PER_PMD * PTRS_PER_PTE * =
PAGE_SIZE, (1UL << cpu_vabits)) - PMD_SIZE - VMEMMAP_SIZE - KFENCE_AREA_SIZ=
E)
>
>  #define vmemmap                ((struct page *)((VMALLOC_END + PMD_SIZE)=
 & PMD_MASK))
>  #define VMEMMAP_END    ((unsigned long)vmemmap + VMEMMAP_SIZE - 1)
>
> +#ifdef CONFIG_KFENCE
> +#define KFENCE_AREA_START      VMEMMAP_END
> +#define KFENCE_AREA_END                (KFENCE_AREA_START + KFENCE_AREA_=
SIZE)
> +#endif
> +
>  #define pte_ERROR(e) \
>         pr_err("%s:%d: bad pte %016lx.\n", __FILE__, __LINE__, pte_val(e)=
)
>  #ifndef __PAGETABLE_PMD_FOLDED
> diff --git a/arch/loongarch/mm/fault.c b/arch/loongarch/mm/fault.c
> index da5b6d518cdb..c0319128b221 100644
> --- a/arch/loongarch/mm/fault.c
> +++ b/arch/loongarch/mm/fault.c
> @@ -23,6 +23,7 @@
>  #include <linux/kprobes.h>
>  #include <linux/perf_event.h>
>  #include <linux/uaccess.h>
> +#include <linux/kfence.h>
>
>  #include <asm/branch.h>
>  #include <asm/mmu_context.h>
> @@ -30,7 +31,8 @@
>
>  int show_unhandled_signals =3D 1;
>
> -static void __kprobes no_context(struct pt_regs *regs, unsigned long add=
ress)
> +static void __kprobes no_context(struct pt_regs *regs, unsigned long add=
ress,
> +                                unsigned long write)
>  {
>         const int field =3D sizeof(unsigned long) * 2;
>
> @@ -38,6 +40,9 @@ static void __kprobes no_context(struct pt_regs *regs, =
unsigned long address)
>         if (fixup_exception(regs))
>                 return;
>
> +       if (kfence_handle_page_fault(address, write, regs))
> +               return;
> +
>         /*
>          * Oops. The kernel tried to access some bad page. We'll have to
>          * terminate things with extreme prejudice.
> @@ -51,14 +56,15 @@ static void __kprobes no_context(struct pt_regs *regs=
, unsigned long address)
>         die("Oops", regs);
>  }
>
> -static void __kprobes do_out_of_memory(struct pt_regs *regs, unsigned lo=
ng address)
> +static void __kprobes do_out_of_memory(struct pt_regs *regs, unsigned lo=
ng address,
> +                                      unsigned long write)
>  {
>         /*
>          * We ran out of memory, call the OOM killer, and return the user=
space
>          * (which will retry the fault, or kill us if we got oom-killed).
>          */
>         if (!user_mode(regs)) {
> -               no_context(regs, address);
> +               no_context(regs, address, write);
>                 return;
>         }
>         pagefault_out_of_memory();
> @@ -69,7 +75,7 @@ static void __kprobes do_sigbus(struct pt_regs *regs,
>  {
>         /* Kernel mode? Handle exceptions or die */
>         if (!user_mode(regs)) {
> -               no_context(regs, address);
> +               no_context(regs, address, write);
>                 return;
>         }
>
> @@ -90,7 +96,7 @@ static void __kprobes do_sigsegv(struct pt_regs *regs,
>
>         /* Kernel mode? Handle exceptions or die */
>         if (!user_mode(regs)) {
> -               no_context(regs, address);
> +               no_context(regs, address, write);
>                 return;
>         }
>
> @@ -149,7 +155,7 @@ static void __kprobes __do_page_fault(struct pt_regs =
*regs,
>          */
>         if (address & __UA_LIMIT) {
>                 if (!user_mode(regs))
> -                       no_context(regs, address);
> +                       no_context(regs, address, write);
>                 else
>                         do_sigsegv(regs, write, address, si_code);
>                 return;
> @@ -211,7 +217,7 @@ static void __kprobes __do_page_fault(struct pt_regs =
*regs,
>
>         if (fault_signal_pending(fault, regs)) {
>                 if (!user_mode(regs))
> -                       no_context(regs, address);
> +                       no_context(regs, address, write);
>                 return;
>         }
>
> @@ -232,7 +238,7 @@ static void __kprobes __do_page_fault(struct pt_regs =
*regs,
>         if (unlikely(fault & VM_FAULT_ERROR)) {
>                 mmap_read_unlock(mm);
>                 if (fault & VM_FAULT_OOM) {
> -                       do_out_of_memory(regs, address);
> +                       do_out_of_memory(regs, address, write);
>                         return;
>                 } else if (fault & VM_FAULT_SIGSEGV) {
>                         do_sigsegv(regs, write, address, si_code);
> --
> 2.34.1
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H4RB4SDpdozkktq45yRbextEUctXEYy%2Bt%2B6gKONytwKQA%40mail.gm=
ail.com.
