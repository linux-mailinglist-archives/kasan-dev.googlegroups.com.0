Return-Path: <kasan-dev+bncBAABB4H47WSQMGQEKHG5V4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id E14DA760C56
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jul 2023 09:49:05 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-403cddf284bsf69293101cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jul 2023 00:49:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690271345; cv=pass;
        d=google.com; s=arc-20160816;
        b=NVyDKKBiI6OlKRku6tbsjiLK2ymtB5dT5B++B2vXTJXtwprEd5tu3fQgxhJn8MKng6
         Yp54TlpXSPet6ciBBm8lWyometzu/uPHjFwHw2Z2AP4dHk+KAL3+1NzeNgiSQpxw/UE2
         K8oxhuW38nyFCDVuxPG2fZKIGm0PdoSivS7mXP5116qUgSI6D6Iy70d7Eqe9AhXAkmEI
         GRnxW5t58MCqwBRZ0pOJD/iaH4K5GZIW0vPAmHeaRJeb/AgWH/wH79xNeDzNADt85PpY
         PF+q73t1F7Bk/6VH5oc4mov+xx9D+4NJRDqplFHZmYR66uzyoKjGNiRal5gcFwoqLGCK
         zSDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=5u+heO3ii011xBPjS9CIG5Pko8nm/R63WU2LlteBh1o=;
        fh=sy4SP3vkEn2BvwOVbcJ42LyDgXjWTkePGWUGK7C0j7Y=;
        b=mDyHIfa14g9Z2h4RnX49cy0kyh+LJKqS3bn2dDEnuG2N5rMN48Q9sMlOBX/TxFvcoJ
         3IY4ZMActGecHVSWlbqdvsznCUgp8Lz7NmOeDovPKE0AWezPdTPILHQX7RH38AQWCszP
         IOjm0yFxt5sA/PGtIQQXQQIsbWYXl3vgz5GIUAoNi5sSJU1wu7MrkBgxuODeNMgag551
         lU/WQwv4vrQVqd+nWmmqLNKAbaS60EQZQMwUuvVjiCLvySpPRMUn78iUzs8I4p4TvX7R
         wkCTlFepHPwcpXaPwBdBZw4mFfRGMVmjbTCSxnslezvj0IV26YTs/DtnifsLcegFoU7/
         Is7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WybcbO8m;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690271345; x=1690876145;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=5u+heO3ii011xBPjS9CIG5Pko8nm/R63WU2LlteBh1o=;
        b=Swh+bxwPQ2F45ItYhwhBeVtD+/8Z5cxkMIITB/Jd4kVxWg7TQ7LG+IPG+7fjrZkzmy
         sldZADUOXOTQCpYaTkT+Hykbw8hwEO34czQHPWDikTcQLLqceTQaE92c77JXK0RnUmsG
         ucON+eh8dvzPkKCdktP+qwVgR2tZDZy4Ad3UvGeHrzlphS8K1mM+UZlfn5y6PtFZ67xi
         9sq6UZa90pkAdgi2ZgVvAIWE4FDE6KKs7OhKbWJSBNPa+fxcGwnJSTK5zGfkQyOgLh1R
         lJs5JlFDnia0v/XTbNfRfit3ezAP9h1w/TxQSXTGfa3Ktcq6j/qrhYX/vP0RwpBdTmzQ
         Njlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690271345; x=1690876145;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=5u+heO3ii011xBPjS9CIG5Pko8nm/R63WU2LlteBh1o=;
        b=IvjewYOy3M1pLHAT6vtUkXroVvtvz7LdLMGdRy2G5OAl6TbavA0n0Ic9H+IMhhLbcn
         s83/07nWD0Y48IJmw1EjQZrbr9FUvwf3dIf1QCgNy4bu5qM2hAvU+RkxGG5x90QneRn3
         X8QOHADhZb/pxv7MpqK0wpS5uraVXYU9ONwYhOT//N5//iCQU2JFLgt0E6XDhevpZ9pt
         C/8RMbeD1Wldk1piGqX0igGyvm/UzUG7DF0kTBYCuz1KzsjZ0Umf6wF0R0fjhxQz9TOV
         lGhPVhVW6YvDaIuf0KTZsPUj0ZEQlR5CnYrUtxk6jmnmuUOOkEgdMsB/CTBQ3tJjrswM
         eTXQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLbBlUiKLYO8xq+JycyDYD2U2Dv9YEq1NGbT5VuIxohkcBy/IOsm
	3QhE3BnfPa94wQQX04ZbVG8=
X-Google-Smtp-Source: APBJJlHBs6XJEW1F0XQZUvJlDS06B8DZfgHF/6bGnWjlxQaeBAlfRn7KY78TTBbiXGQ+2tf7zHsecQ==
X-Received: by 2002:ac8:5f91:0:b0:3f6:f839:15ec with SMTP id j17-20020ac85f91000000b003f6f83915ecmr2509380qta.56.1690271344616;
        Tue, 25 Jul 2023 00:49:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:6007:b0:403:ee8a:77b6 with SMTP id
 he7-20020a05622a600700b00403ee8a77b6ls6972027qtb.0.-pod-prod-07-us; Tue, 25
 Jul 2023 00:49:04 -0700 (PDT)
X-Received: by 2002:a05:620a:3843:b0:76a:ca95:a5fd with SMTP id po3-20020a05620a384300b0076aca95a5fdmr1773341qkn.61.1690271344051;
        Tue, 25 Jul 2023 00:49:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690271344; cv=none;
        d=google.com; s=arc-20160816;
        b=VqtAxRYlrOtDguHKYmuHlKAXpthJ29ZwTIDzx2GDbeCUZ5m055Xy7rtmlS3hoz4ij/
         xPIVK8Czn8Sl7OtqbemUihWsmjc6wfVi+HWnGXPksEvURNu2Shx/6U30RmTwvjDmi2d0
         EHY83NGu2Tl63BahmmcjEzevT+R8/XV49CTxGpGCPfv72JXvx59vnxDUSEyvDkpAcB8m
         SIbPnlEQ7+SbDY7xKHd82eNUozDiVi5T2fT2PYcNxd+g8YVSNwxuqgB+TqV3FPFaxPah
         T9r7/WdM96b/I3PJG8LcjcHz2F34y/UQnpVFHOnh2pTJ+dV2WelISfGjZgKBXX4OJJuU
         6eHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=KmakmmEgZueO/YFdbpdTsIKHFwM4SrXCiaoJfcNVhDM=;
        fh=sy4SP3vkEn2BvwOVbcJ42LyDgXjWTkePGWUGK7C0j7Y=;
        b=jjuxAx0q2OuKeUFm5M0rQ/rxs5IzqqfX+o2DNPTPHy+9MnSDuGMaVoSFB9EHvbRCBj
         7IioleUyEygtIAJv8ji4gGVOoA++1FdwBsDlDl1UCq+Mp1joOiljSxeelANmtjto3l16
         S0tU7yjKtRB9P1ARHIkqJkyhzaAvJ4fun5/CNQpIWyCCwTVEAj89asB7Fc7fQVES45E1
         NFeIda2VMJ9tbm/AVY6EOtZtsHB7lREPi8oxrv+b54IoMQA/4p1J46oakQObOaritHF7
         jz0QBvp3EGnV+yyNbfSF/bUOuRqNXzRqKxADFaGw684DmLzQUixAsCga7W1vw129WJf7
         RkjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WybcbO8m;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id pt6-20020a17090b3d0600b00262c6d85bdbsi602278pjb.0.2023.07.25.00.49.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Jul 2023 00:49:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 57E3461387
	for <kasan-dev@googlegroups.com>; Tue, 25 Jul 2023 07:49:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 46CA9C433D9
	for <kasan-dev@googlegroups.com>; Tue, 25 Jul 2023 07:49:02 +0000 (UTC)
Received: by mail-lf1-f47.google.com with SMTP id 2adb3069b0e04-4fb7dc16ff0so7767678e87.2
        for <kasan-dev@googlegroups.com>; Tue, 25 Jul 2023 00:49:02 -0700 (PDT)
X-Received: by 2002:a05:6512:2523:b0:4f7:6966:36fb with SMTP id
 be35-20020a056512252300b004f7696636fbmr7905252lfb.12.1690271340083; Tue, 25
 Jul 2023 00:49:00 -0700 (PDT)
MIME-Version: 1.0
References: <20230725061451.1231480-1-lienze@kylinos.cn> <20230725061451.1231480-5-lienze@kylinos.cn>
In-Reply-To: <20230725061451.1231480-5-lienze@kylinos.cn>
From: Huacai Chen <chenhuacai@kernel.org>
Date: Tue, 25 Jul 2023 15:48:30 +0800
X-Gmail-Original-Message-ID: <CAAhV-H7j6R5zWvXuLucnq0Xvu=1Q-pxQzG1DavTAx63AL+GzbA@mail.gmail.com>
Message-ID: <CAAhV-H7j6R5zWvXuLucnq0Xvu=1Q-pxQzG1DavTAx63AL+GzbA@mail.gmail.com>
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
 header.i=@kernel.org header.s=k20201202 header.b=WybcbO8m;       spf=pass
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

Hi, Enze,

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
This comment can be removed since the logic is obvious.

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
Needn't change to a new line.

Others look good to me.

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
kasan-dev/CAAhV-H7j6R5zWvXuLucnq0Xvu%3D1Q-pxQzG1DavTAx63AL%2BGzbA%40mail.gm=
ail.com.
