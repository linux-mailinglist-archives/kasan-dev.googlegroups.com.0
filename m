Return-Path: <kasan-dev+bncBAABBBEC4CSQMGQEUBB3YJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 45E747599B4
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jul 2023 17:28:07 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id 41be03b00d2f7-53f06f7cc74sf525462a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jul 2023 08:28:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689780485; cv=pass;
        d=google.com; s=arc-20160816;
        b=m7n2tDsDp83wXJ/kT9ly+tA4hVrtNCLhLztdQcjvbpsZLM8bMrpZDVoRxTL2x40dPD
         PmxqVA2xiEKc9xJcFjfZOyFCGg/WFDk9JITBEAGQnW06vrUmTemU7m5U4hD5LBCHT0nB
         XKXW9FGwpvMWp2F6DHtVY99zsLU5gL7SUJA6OQfstRPg3bYgHyp++1qyHIZCpcEkzCIp
         UjmFPct0vTZeCEUIoE6UMcs8B8zZ953qH9/HTWiNM74ZTSYbeAIVEzpVBVW7FMOpH0iU
         0KVPi7w/iVGWvMLJOSUsOm1Jv+s5/qNOdcBEzZrhMTWp1+LevaA3gelPo6f3mWHKwXUT
         FBcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=ydr54EhAOdGKha/U0bQh7W+AGANFTxzeEpv3EMzevJI=;
        fh=sy4SP3vkEn2BvwOVbcJ42LyDgXjWTkePGWUGK7C0j7Y=;
        b=cu2gkFynBQjMrHvqJIXPcbPYg/Lkzr4KYdkk8TZDCAXLP6ibXItoVBXP6+tPzYmnvj
         56UtZU1GEFJd/R0oGTZeLJEMouTgd1GSU+RRTmKyjj4cgvv6KUy4InXQjOXJDhGQDsQH
         m/TMOCbJ/tX4+ehepT+gikfTf0xL91IJM/MSVN7SdN6fJtcm2AgvnxfoZFLv+ZjxfZgN
         3aOh30mpL8VsiGT1uYeGflXh/ut6jBYbVXeCYPLoOPUQ0IRz5ZmuJ57+aQ12ASjxqb2D
         TTO09V38Rej0qJjwF/D/vHrIKjc4Vev3H3H98bwJmBy6NSvM8Z3Ue39Pwq6qWUNA1N6I
         2wCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Z97JdpsC;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689780485; x=1692372485;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ydr54EhAOdGKha/U0bQh7W+AGANFTxzeEpv3EMzevJI=;
        b=RsfP+K08qGok+KS70znU6nuaIzrfNbnhkjORt0ENUXCSaPV96ZDriS6uKE1bCQWy/G
         CfOWkQX9rn7fckLlEXTK9TbruZf8jZ6vniKmC1m2QAxmZPmXH5K7Sm6IO+3fVzJHHNZd
         AQLibms8a5REC0JjfQRSBTbAjXr1omHDIEv0H8ZpCQWYrmyDP1CJHljrVi8idYdWiaIM
         RgvQoyyiysLqHJjlRRCuQduXUF7rMm4r4Zo89nQZMKvuIV5bznJ0D48OvQ45m46Noyof
         srHR6gslvlj9R8BWTIKWJUCDRA1287P68I+FGP38bwPGRFfEEWhgzhqjZPJs2tZYa+sw
         I97Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689780485; x=1692372485;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ydr54EhAOdGKha/U0bQh7W+AGANFTxzeEpv3EMzevJI=;
        b=R2pqlnTqzafWOZrwqhaAYr62vmtjzOqJupGAza77fnAuSYUYd2BY73070m6Wz1eOBk
         QAbLBlsyNWo2pvgUOmBxAbKiZ34wW0FFGFadMdRXhLqjcbt96nIrted/mQq7WfYliqEL
         wbqRz5qiFfwyH0sA6I/api3U8fRsgsLio2Tl5oxpE2sjWdlXi39BosRjbKLxjHJvU2zg
         SDKFnBHTUS90Bgh/jd+J1w/IFth1sX4fMVHY6Mq67USka78DALFmX8MkuZuGh1AgBTBX
         36ATBMxT2943hQwQwCXNkS1jYtK+9B2ypVp75iQ64T9QHMGecibLbjYtSyp9h4Dc4Mjm
         BFFA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLZjr1YPpvHutJnnCQ46pVDjR8boypSc4dmvA63Vv60amG3oTpER
	mrV6eU/qySs6MKLIsfZ9W+E=
X-Google-Smtp-Source: APBJJlHsZirxTh1T1igx9/mIVTglZoGw/scD70AnzqmzMbJTS+r9M1X9+eDtYHEtN0I2ce1IWlD1AA==
X-Received: by 2002:a17:90a:1b44:b0:25d:d224:9fb9 with SMTP id q62-20020a17090a1b4400b0025dd2249fb9mr3007116pjq.24.1689780485021;
        Wed, 19 Jul 2023 08:28:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:805:b0:260:d941:57d8 with SMTP id
 bk5-20020a17090b080500b00260d94157d8ls3898796pjb.2.-pod-prod-00-us-canary;
 Wed, 19 Jul 2023 08:28:04 -0700 (PDT)
X-Received: by 2002:a05:6a20:144c:b0:132:c1fd:aaab with SMTP id a12-20020a056a20144c00b00132c1fdaaabmr3056862pzi.30.1689780484136;
        Wed, 19 Jul 2023 08:28:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689780484; cv=none;
        d=google.com; s=arc-20160816;
        b=dPDfd6OyEmc+C+t55U8DiBrI+RXr6n3jT0Ui4tFzPeWOvp5UkY9CF4D15AwwIJWEQR
         Awdy6LX3195UD0MAG2JXjiySBn7c+JIJB/gHQkQ6fQJ75zeNsjU98/WO+tx2rnOjrfSy
         lq4J/m0/OpT5lblx56gKsQmoyMq/YZHf5FT4TAPZ4SHRmbh/5jEG2hYbT0rVHdXBPvEg
         fJchEUE2zv+XhUGZH1WKDfUKTaslWobbXIemrYNqDEP7ouJYoMCCABxswiuF79ACRWRq
         jo9Pt4XkRlnaGtcLVfs6ykFmwLa9xaC70euKIf2dp2WV/uGVhCBSeesFqGgXI1A3OIEO
         ojRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=KFt4BkJ2H2so/ro+TZYvoG+vX9g4beBLicnUoRPY/08=;
        fh=sy4SP3vkEn2BvwOVbcJ42LyDgXjWTkePGWUGK7C0j7Y=;
        b=R8OkiYqAWC1X6yZukvZL3ErTA8mtBXtoCs/a13KGFe3iasahzxxN7g1BEbOlmBad8i
         LM/hZuOffFfp+bmpW/GkDDuiYUy+amNtYEdGfCrWcVamhFlC8OTQWgvwkiixTuobbU1r
         GD/oItqcDZIHAsEnDhSjKniolxNsgRHQqBH6oaNmNAGL83Fa97ZBy/fOyUfNM1e82RQF
         XenSwXX6yG2FSKIgE8YbUiDq8G12R31XPI+Otq8gTFOTKDARxh/3M6jAP0gAsRr56Gm2
         FF/Xi3ud4V2KL7LYKDXDFPrsAah2f4nH3sNB4+HaLL7fFQXdsB3nkOFF8Q5fJtEIZPJ3
         JitQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Z97JdpsC;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id ca13-20020a056a00418d00b00682537b2c0fsi458405pfb.2.2023.07.19.08.28.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jul 2023 08:28:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 753DA61764
	for <kasan-dev@googlegroups.com>; Wed, 19 Jul 2023 15:28:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A0174C433C9
	for <kasan-dev@googlegroups.com>; Wed, 19 Jul 2023 15:28:02 +0000 (UTC)
Received: by mail-ed1-f43.google.com with SMTP id 4fb4d7f45d1cf-51e57874bfdso9938484a12.0
        for <kasan-dev@googlegroups.com>; Wed, 19 Jul 2023 08:28:02 -0700 (PDT)
X-Received: by 2002:a05:6402:2037:b0:51e:293b:e1ce with SMTP id
 ay23-20020a056402203700b0051e293be1cemr2706511edb.31.1689780480858; Wed, 19
 Jul 2023 08:28:00 -0700 (PDT)
MIME-Version: 1.0
References: <20230719082732.2189747-1-lienze@kylinos.cn> <20230719082732.2189747-5-lienze@kylinos.cn>
In-Reply-To: <20230719082732.2189747-5-lienze@kylinos.cn>
From: Huacai Chen <chenhuacai@kernel.org>
Date: Wed, 19 Jul 2023 23:27:50 +0800
X-Gmail-Original-Message-ID: <CAAhV-H71sv+VeLfNzuiqitYcuB4rHnho=dRYQftwo1__3bLZSQ@mail.gmail.com>
Message-ID: <CAAhV-H71sv+VeLfNzuiqitYcuB4rHnho=dRYQftwo1__3bLZSQ@mail.gmail.com>
Subject: Re: [PATCH 4/4] LoongArch: Add KFENCE support
To: Enze Li <lienze@kylinos.cn>
Cc: kernel@xen0n.name, loongarch@lists.linux.dev, glider@google.com, 
	elver@google.com, akpm@linux-foundation.org, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, zhangqing@loongson.cn, yangtiezhu@loongson.cn, 
	dvyukov@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Z97JdpsC;       spf=pass
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

On Wed, Jul 19, 2023 at 4:34=E2=80=AFPM Enze Li <lienze@kylinos.cn> wrote:
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
> Tested this patch by using the testcases and all passed.
>
> [1] https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.=
html#virtual-address-space-and-address-translation-mode
>
> Signed-off-by: Enze Li <lienze@kylinos.cn>
> ---
>  arch/loongarch/Kconfig               |  1 +
>  arch/loongarch/include/asm/kfence.h  | 62 ++++++++++++++++++++++++++++
>  arch/loongarch/include/asm/pgtable.h |  6 +++
>  arch/loongarch/mm/fault.c            | 22 ++++++----
>  4 files changed, 83 insertions(+), 8 deletions(-)
>  create mode 100644 arch/loongarch/include/asm/kfence.h
>
> diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
> index 5411e3a4eb88..db27729003d3 100644
> --- a/arch/loongarch/Kconfig
> +++ b/arch/loongarch/Kconfig
> @@ -93,6 +93,7 @@ config LOONGARCH
>         select HAVE_ARCH_JUMP_LABEL
>         select HAVE_ARCH_JUMP_LABEL_RELATIVE
>         select HAVE_ARCH_KASAN
> +       select HAVE_ARCH_KFENCE if 64BIT
"if 64BIT" can be dropped here.

>         select HAVE_ARCH_MMAP_RND_BITS if MMU
>         select HAVE_ARCH_SECCOMP_FILTER
>         select HAVE_ARCH_TRACEHOOK
> diff --git a/arch/loongarch/include/asm/kfence.h b/arch/loongarch/include=
/asm/kfence.h
> new file mode 100644
> index 000000000000..2a85acc2bc70
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
> +static inline char *arch_kfence_init_pool(void)
> +{
> +       char *__kfence_pool_orig =3D __kfence_pool;
I prefer kfence_pool than __kfence_pool_orig here.

> +       struct vm_struct *area;
> +       int err;
> +
> +       area =3D __get_vm_area_caller(KFENCE_POOL_SIZE, VM_IOREMAP,
> +                                   KFENCE_AREA_START, KFENCE_AREA_END,
> +                                   __builtin_return_address(0));
> +       if (!area)
> +               return NULL;
> +
> +       __kfence_pool =3D (char *)area->addr;
> +       err =3D ioremap_page_range((unsigned long)__kfence_pool,
> +                                (unsigned long)__kfence_pool + KFENCE_PO=
OL_SIZE,
> +                                virt_to_phys((void *)__kfence_pool_orig)=
,
> +                                PAGE_KERNEL);
> +       if (err) {
> +               free_vm_area(area);
> +               return NULL;
> +       }
> +
> +       return __kfence_pool;
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
> index 0fc074b8bd48..5a9c81298fe3 100644
> --- a/arch/loongarch/include/asm/pgtable.h
> +++ b/arch/loongarch/include/asm/pgtable.h
> @@ -85,7 +85,13 @@ extern unsigned long zero_page_mask;
>  #define MODULES_VADDR  (vm_map_base + PCI_IOSIZE + (2 * PAGE_SIZE))
>  #define MODULES_END    (MODULES_VADDR + SZ_256M)
>
> +#ifdef CONFIG_KFENCE
> +#define KFENCE_AREA_START      MODULES_END
> +#define KFENCE_AREA_END                (KFENCE_AREA_START + SZ_512M)
Why you choose 512M here?

> +#define VMALLOC_START          KFENCE_AREA_END
> +#else
>  #define VMALLOC_START  MODULES_END
> +#endif
I don't like to put KFENCE_AREA between module and vmalloc range (it
may cause some problems), can we put it after vmemmap?

Huacai
>
>  #ifndef CONFIG_KASAN
>  #define VMALLOC_END    \
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
kasan-dev/CAAhV-H71sv%2BVeLfNzuiqitYcuB4rHnho%3DdRYQftwo1__3bLZSQ%40mail.gm=
ail.com.
