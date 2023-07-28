Return-Path: <kasan-dev+bncBAABBOEKRWTAMGQEAGOSLTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 39AB676632D
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jul 2023 06:34:02 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id 3f1490d57ef6-d114bc2057fsf1568366276.3
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Jul 2023 21:34:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690518841; cv=pass;
        d=google.com; s=arc-20160816;
        b=LVkWhAJjnfuWmHckI7n0yNNhFijPHBedBsvIe25cDxQTvKXMFnj5uHe2vSWLlQk2j9
         1ECWwchpy6epphmVkRJVXKxGbbOTcrRsipOsjUMBi1Q4qihUZ/nXLaYNOu5RkcT4t7yh
         vqBkf0GrZCy7P0MgRp8gQggzEMO53Jdr8JGHhxBWKVYoJPUx1g759Oy4nhK8CRUz0kgD
         z4v3cQui+PjDRQdU82hGZ4hY/ZjfI6iNW7y42+1L3mhLTs4IGzlSdnq6cdMd+MLCW2Hd
         xexoD+gWHriHDlOTyyH6gzY79uEAOLy6fTgWCBUAv6HFbcHc1sFmhAVvo0cU1OySQpF6
         2Pzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=ohTyeShmfDj1qAcrAac7JsxlnUuq+I5mM306Vfpqrzk=;
        fh=sy4SP3vkEn2BvwOVbcJ42LyDgXjWTkePGWUGK7C0j7Y=;
        b=aauKw52xNEZbDEC5RVzayLp7xApamuwd3UCglTg36eoOlDKJGciyJADPauuG+OZhOm
         8fXTtBi4nL2oD2wygdSls9fRFoH5TAWXsEzGKisFy7ITyy5/sKkUrcFq49VNqGLDURr8
         eJOoLEC+XYudKd4s2mYmBxYiXQRPptlEBhdwaxDgkSoyvDYocD+RIrwVv9WkdqeVJkfa
         ++y/JOXzTtOlW+wCCHvJWv0yzPNoJ1F7hY8eSTx8rhCB1+vV2LlPR4K99e1veIHyVDpZ
         OsYBo7us8LXtJKXGbEVX1OfndGmaqQFKwm43uBoyJ9EerHJbiYi09BkDIrCG+i7u2Pe4
         Fs1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OmQ6Y05j;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690518841; x=1691123641;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ohTyeShmfDj1qAcrAac7JsxlnUuq+I5mM306Vfpqrzk=;
        b=CXSu2z8muYDnJD9TkA/+/mLKQeBK4bIyoI/Ia18/X9833RKLtaTrbKQF76xFM3jAu8
         SfkmF75hhW7MPIWKlo8k8qCBokCEA0Lnd/aJwBlXXFWj+9QEf+O9BzZLfRZi15SuKbUX
         /ypWSgzZz6zV14Z0YFGYBT2Jb4BbbXHeggZcuT5xGk3d5DA/SVRBe/ZPTBeLaRL9zkEm
         dhjhZuwRE8KOgAQ7b5CGgGbUySTIIuzHnZTzAA4Z61u8FpynAI4jg+hUSvYD3EENl5E1
         iFMB506HpgtSth1TlGLjyCAQO6w/50UPeDPmSulH3A6qa0PFZFY1nfddUJVWO9fDC0Gi
         gWlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690518841; x=1691123641;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ohTyeShmfDj1qAcrAac7JsxlnUuq+I5mM306Vfpqrzk=;
        b=UgCxuXx/2fv5UtiVvZa99ZdwzeB9pRtApdg8MyGCzeQ9NoQeM9AReRrho5Xz432Fcn
         A83RqAERnJ+uONSU+DIfbAqjpY9LhLqHC/93AGChPZLfQtYnajFPWNy8bgP98npkbjVD
         nvjYzuioiU0FprOhQRAaQKmNTlabnWr4QFHa1zT9ZbDXcxf2FneRI2xrUmN8eaM2Gpnm
         mpDYDGCrF5NAHcjsGC2TawWvhnIl5Fb8NR8GnJZ2/83w68AQ03XxU8OCUSKVnCFJYuQb
         MUgEs1Wjz/eQubq9MoaeCrip1x1fWmen7bowXBlRHzCzRhZUpFYLH9Hfm+Emu5/EOKVH
         aqtg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLbQYULd8F1V4mdxG/9zP+gSBuIy724Cj//pppgdYE7Ol7hddmOf
	FY6vb9IaliNRpEIpg12BgpE=
X-Google-Smtp-Source: APBJJlHEbS7jktHFKpJykoCPDZKH898yCDfwK4ohvwuRmVRPgo/VUtdTmaJ6DfdT7Bxls+QAIgZyng==
X-Received: by 2002:a25:cb17:0:b0:d15:779b:6e93 with SMTP id b23-20020a25cb17000000b00d15779b6e93mr1006368ybg.27.1690518840767;
        Thu, 27 Jul 2023 21:34:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:124c:b0:d20:62b1:3a26 with SMTP id
 t12-20020a056902124c00b00d2062b13a26ls1647710ybu.1.-pod-prod-02-us; Thu, 27
 Jul 2023 21:34:00 -0700 (PDT)
X-Received: by 2002:a5b:d0c:0:b0:d18:d821:2f8a with SMTP id y12-20020a5b0d0c000000b00d18d8212f8amr785348ybp.1.1690518839931;
        Thu, 27 Jul 2023 21:33:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690518839; cv=none;
        d=google.com; s=arc-20160816;
        b=WlUERhCY7x8tn0idb/IyvL9dT1k31Lm+CAnECcWVLeWNtKLwb1ptF6hoou0Pz+XdQ5
         ZkZo2j8Jea3dsLcTHNVegYNBgYvli/Y/mc7SkK0F26q+3rUd7I3ZZRF+5RG64vxWICmI
         bo/mb2VsstOwzrogTOV6sFDijNOadqj/ObKlco8CVj6fvvw9xSR/Zclhw1KXEkdvxUHN
         9wQUepIwsPx5pT5JD1GqmIg3w6ST9iI/aeCZe9Rg9vdiRSgsxfq+srYLm/BlWkG9UyEl
         kvV42cZt+7EMd0tf4wbt0E4LBM5L46GERQxqwFvT+st0LuxH0CXugisK6yHAhW45NTuK
         gYXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=S/DU8nON0tgoZVa1jDyPcOUGS3PljhpZo8rP6RWSV18=;
        fh=sy4SP3vkEn2BvwOVbcJ42LyDgXjWTkePGWUGK7C0j7Y=;
        b=oWaev3hhZ9j8R+wg85bP9pMwRyt+eqhdZ2O05cMg99obabVUZLcX6CqEdBRmERL4bx
         +JZHngGN/2MUmbKAy1Gkr9OYmNg72r3dF9cm8anV7gMr5euRfnTyLYRogeF4Bs+hAKz7
         SFFRC7mEFV4dgP/NAiyVAe8Fka8ZfZUfu5YjeVguREoEOpsHh19GmcGXabLjgmWD6mgF
         lIFRrxiImm4JpBLJxafLIcT3mZ35ddV8VGWywUeL9KxEyoUyRSKk3Uh/9tMc+R1wmcw6
         K9Zq7Hj7NeflznsXBkS3d3yHDhjrGOkdeCSfmpOpb3q4qWB5LSbnzmg/uZm/DeTkuP2w
         ei/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OmQ6Y05j;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id p33-20020a056a000a2100b00681f56016b9si225645pfh.4.2023.07.27.21.33.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Jul 2023 21:33:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 2B17461FCF
	for <kasan-dev@googlegroups.com>; Fri, 28 Jul 2023 04:33:59 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5FC0CC433CC
	for <kasan-dev@googlegroups.com>; Fri, 28 Jul 2023 04:33:58 +0000 (UTC)
Received: by mail-ed1-f52.google.com with SMTP id 4fb4d7f45d1cf-52164adea19so2139845a12.1
        for <kasan-dev@googlegroups.com>; Thu, 27 Jul 2023 21:33:58 -0700 (PDT)
X-Received: by 2002:aa7:d0c8:0:b0:522:3ea4:81a9 with SMTP id
 u8-20020aa7d0c8000000b005223ea481a9mr869403edo.34.1690518836394; Thu, 27 Jul
 2023 21:33:56 -0700 (PDT)
MIME-Version: 1.0
References: <20230725061451.1231480-1-lienze@kylinos.cn> <20230725061451.1231480-5-lienze@kylinos.cn>
 <CAAhV-H4RB4SDpdozkktq45yRbextEUctXEYy+t+6gKONytwKQA@mail.gmail.com> <87wmykaf6v.fsf@kylinos.cn>
In-Reply-To: <87wmykaf6v.fsf@kylinos.cn>
From: Huacai Chen <chenhuacai@kernel.org>
Date: Fri, 28 Jul 2023 12:33:43 +0800
X-Gmail-Original-Message-ID: <CAAhV-H4Hu-NT54G8_JuU1+Qi6OsnjTr14Ohc3-qHf7-mcNK6aw@mail.gmail.com>
Message-ID: <CAAhV-H4Hu-NT54G8_JuU1+Qi6OsnjTr14Ohc3-qHf7-mcNK6aw@mail.gmail.com>
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
 header.i=@kernel.org header.s=k20201202 header.b=OmQ6Y05j;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
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

On Fri, Jul 28, 2023 at 11:28=E2=80=AFAM Enze Li <lienze@kylinos.cn> wrote:
>
> On Thu, Jul 27 2023 at 09:26:04 AM +0800, Huacai Chen wrote:
>
> > On Tue, Jul 25, 2023 at 2:15=E2=80=AFPM Enze Li <lienze@kylinos.cn> wro=
te:
> >>
> >> The LoongArch architecture is quite different from other architectures=
.
> >> When the allocating of KFENCE itself is done, it is mapped to the dire=
ct
> >> mapping configuration window [1] by default on LoongArch.  It means th=
at
> >> it is not possible to use the page table mapped mode which required by
> >> the KFENCE system and therefore it should be remapped to the appropria=
te
> >> region.
> >>
> >> This patch adds architecture specific implementation details for KFENC=
E.
> >> In particular, this implements the required interface in <asm/kfence.h=
>.
> >>
> >> Tested this patch by running the testcases and all passed.
> >>
> >> [1] https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-=
EN.html#virtual-address-space-and-address-translation-mode
> >>
> >> Signed-off-by: Enze Li <lienze@kylinos.cn>
> >> ---
> >>  arch/loongarch/Kconfig               |  1 +
> >>  arch/loongarch/include/asm/kfence.h  | 62 +++++++++++++++++++++++++++=
+
> >>  arch/loongarch/include/asm/pgtable.h | 14 ++++++-
> >>  arch/loongarch/mm/fault.c            | 22 ++++++----
> >>  4 files changed, 90 insertions(+), 9 deletions(-)
> >>  create mode 100644 arch/loongarch/include/asm/kfence.h
> >>
> >> diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
> >> index 70635ea3d1e4..5b63b16be49e 100644
> >> --- a/arch/loongarch/Kconfig
> >> +++ b/arch/loongarch/Kconfig
> >> @@ -91,6 +91,7 @@ config LOONGARCH
> >>         select HAVE_ARCH_AUDITSYSCALL
> >>         select HAVE_ARCH_JUMP_LABEL
> >>         select HAVE_ARCH_JUMP_LABEL_RELATIVE
> >> +       select HAVE_ARCH_KFENCE
> >>         select HAVE_ARCH_MMAP_RND_BITS if MMU
> >>         select HAVE_ARCH_SECCOMP_FILTER
> >>         select HAVE_ARCH_TRACEHOOK
> >> diff --git a/arch/loongarch/include/asm/kfence.h b/arch/loongarch/incl=
ude/asm/kfence.h
> >> new file mode 100644
> >> index 000000000000..fb39076fe4d7
> >> --- /dev/null
> >> +++ b/arch/loongarch/include/asm/kfence.h
> >> @@ -0,0 +1,62 @@
> >> +/* SPDX-License-Identifier: GPL-2.0 */
> >> +/*
> >> + * KFENCE support for LoongArch.
> >> + *
> >> + * Author: Enze Li <lienze@kylinos.cn>
> >> + * Copyright (C) 2022-2023 KylinSoft Corporation.
> >> + */
> >> +
> >> +#ifndef _ASM_LOONGARCH_KFENCE_H
> >> +#define _ASM_LOONGARCH_KFENCE_H
> >> +
> >> +#include <linux/kfence.h>
> >> +#include <asm/pgtable.h>
> >> +#include <asm/tlb.h>
> >> +
> >> +static inline bool arch_kfence_init_pool(void)
> >> +{
> >> +       char *kfence_pool =3D __kfence_pool;
> >> +       struct vm_struct *area;
> >> +       int err;
> >> +
> >> +       area =3D __get_vm_area_caller(KFENCE_POOL_SIZE, VM_IOREMAP,
> >> +                                   KFENCE_AREA_START, KFENCE_AREA_END=
,
> >> +                                   __builtin_return_address(0));
> >> +       if (!area)
> >> +               return false;
> >> +
> >> +       __kfence_pool =3D (char *)area->addr;
> >> +       err =3D ioremap_page_range((unsigned long)__kfence_pool,
> >> +                                (unsigned long)__kfence_pool + KFENCE=
_POOL_SIZE,
> >> +                                virt_to_phys((void *)kfence_pool),
> >> +                                PAGE_KERNEL);
> >> +       if (err) {
> >> +               free_vm_area(area);
> >> +               return false;
> >> +       }
> >> +
> >> +       return true;
> >> +}
> >> +
> >> +/* Protect the given page and flush TLB. */
> >> +static inline bool kfence_protect_page(unsigned long addr, bool prote=
ct)
> >> +{
> >> +       pte_t *pte =3D virt_to_kpte(addr);
> >> +
> >> +       if (WARN_ON(!pte) || pte_none(*pte))
> >> +               return false;
> >> +
> >> +       if (protect)
> >> +               set_pte(pte, __pte(pte_val(*pte) & ~(_PAGE_VALID | _PA=
GE_PRESENT)));
> >> +       else
> >> +               set_pte(pte, __pte(pte_val(*pte) | (_PAGE_VALID | _PAG=
E_PRESENT)));
> >> +
> >> +       /* Flush this CPU's TLB. */
> >> +       preempt_disable();
> >> +       local_flush_tlb_one(addr);
> >> +       preempt_enable();
> >> +
> >> +       return true;
> >> +}
> >> +
> >> +#endif /* _ASM_LOONGARCH_KFENCE_H */
> >> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/inc=
lude/asm/pgtable.h
> >> index 98a0c98de9d1..2702a6ba7122 100644
> >> --- a/arch/loongarch/include/asm/pgtable.h
> >> +++ b/arch/loongarch/include/asm/pgtable.h
> >> @@ -77,6 +77,13 @@ extern unsigned long zero_page_mask;
> >>         (virt_to_page((void *)(empty_zero_page + (((unsigned long)(vad=
dr)) & zero_page_mask))))
> >>  #define __HAVE_COLOR_ZERO_PAGE
> >>
> >> +#ifdef CONFIG_KFENCE
> >> +#define KFENCE_AREA_SIZE \
> >> +       (((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 + 2) * PAGE_SIZE)
>
> Hi Huacai,
>
> > Another question: Why define KFENCE_AREA_SIZE while there is already
> > KFENCE_POOL_SIZE?
>
> The KFENCE_POOL_SIZE macro is defined in linux/kfence.h.  When I trying
> to include this header file, I see the following error,
>
> ----------------------------------------------------------------------
>   CC      arch/loongarch/kernel/asm-offsets.s
> In file included from ./arch/loongarch/include/asm/pgtable.h:64,
>                  from ./include/linux/pgtable.h:6,
>                  from ./include/linux/mm.h:29,
>                  from arch/loongarch/kernel/asm-offsets.c:9:
> ./include/linux/kfence.h:93:35: warning: =E2=80=98struct kmem_cache=E2=80=
=99 declared inside parameter list will not be visible outside of this defi=
nition or declaration
>    93 | void kfence_shutdown_cache(struct kmem_cache *s);
>       |                                   ^~~~~~~~~~
> ./include/linux/kfence.h:99:29: warning: =E2=80=98struct kmem_cache=E2=80=
=99 declared inside parameter list will not be visible outside of this defi=
nition or declaration
>    99 | void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t fla=
gs);
>       |                             ^~~~~~~~~~
> ./include/linux/kfence.h:117:50: warning: =E2=80=98struct kmem_cache=E2=
=80=99 declared inside parameter list will not be visible outside of this d=
efinition or declaration
>   117 | static __always_inline void *kfence_alloc(struct kmem_cache *s, s=
ize_t size, gfp_t flags)
>       |                                                  ^~~~~~~~~~
> ./include/linux/kfence.h: In function =E2=80=98kfence_alloc=E2=80=99:
> ./include/linux/kfence.h:128:31: error: passing argument 1 of =E2=80=98__=
kfence_alloc=E2=80=99 from incompatible pointer type [-Werror=3Dincompatibl=
e-pointer-types]
>   128 |         return __kfence_alloc(s, size, flags);
>       |                               ^
>       |                               |
>       |                               struct kmem_cache *
> --------------------------------------------------------------------
>
> The root cause of this issue is that linux/kfence.h should be expanded
> after linux/mm.h, not before.  That said, we can not put any
> "high-level" header files in the "low-level" ones.
>
> > And why is KFENCE_AREA_SIZE a little larger than
> > KFENCE_POOL_SIZE? If we can reuse KFENCE_POOL_SIZE,
> > KFENCE_AREA_START/KFENCE_AREA_END can be renamed to
> > KFENCE_POOL_START/KFENCE_POOL_END.
>
> +#define KFENCE_AREA_SIZE \
> +       (((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 + 2) * PAGE_SIZE)
>                                               ^^^^^
>
> Here I've added two extra pages, that's due to working with
> __get_vm_area_caller() to request the space correctly.
>
> 1. arch_kfence_init_pool
>      __get_vm_area_caller
>        __get_vm_area_node
>          =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>            if (!(flags & VM_NO_GUARD))
>                    size +=3D PAGE_SIZE;
>          =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>
> If we do not set VM_NO_GUARD, we would get one more page as "GUARD".
> Setting VM_NO_GUARD is dangerous behavior and I suggest we keep this
> page.
>
> 2. arch_kfence_init_pool
>      __get_vm_area_caller
>        __get_vm_area_node                        !!!This is my comment--
>            =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D                  =
   |
>            if (flags & VM_IOREMAP)                                     |
>                    align =3D 1ul << clamp_t(int, ...                     =
|
>            *** We got "align=3D=3D0x200000" here.  Based on the default  =
<--
>                KFENCE objects of 255, we got the maximum align here. ***
>            =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>
>            alloc_vmap_area
>              __alloc_vmap_area
>                =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>                nva_start_addr =3D ALIGN(vstart, align);
>                *** When running here, the starting address will be
>                    moved forward one byte due to alignment
>                    requirements.  If we do not give enough space, we'll
>                    fail on the next line. ***
>
>                if (nva_start_addr + size > vend)
>                        return vend;
>                =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>
> Theoretically, this alignment requires at most 2MB of space.  However,
> considering that the starting address is fixed (the starting position is
> determined by VMEMMAP_END), I think that adding another page will be
> enough.
OK, that makes sense.

Huacai
>
> Best Regards,
> Enze
>
> >> +#else
> >> +#define KFENCE_AREA_SIZE       0
> >> +#endif
> >> +
> >>  /*
> >>   * TLB refill handlers may also map the vmalloc area into xkvrange.
> >>   * Avoid the first couple of pages so NULL pointer dereferences will
> >> @@ -88,11 +95,16 @@ extern unsigned long zero_page_mask;
> >>  #define VMALLOC_START  MODULES_END
> >>  #define VMALLOC_END    \
> >>         (vm_map_base +  \
> >> -        min(PTRS_PER_PGD * PTRS_PER_PUD * PTRS_PER_PMD * PTRS_PER_PTE=
 * PAGE_SIZE, (1UL << cpu_vabits)) - PMD_SIZE - VMEMMAP_SIZE)
> >> +        min(PTRS_PER_PGD * PTRS_PER_PUD * PTRS_PER_PMD * PTRS_PER_PTE=
 * PAGE_SIZE, (1UL << cpu_vabits)) - PMD_SIZE - VMEMMAP_SIZE - KFENCE_AREA_=
SIZE)
> >>
> >>  #define vmemmap                ((struct page *)((VMALLOC_END + PMD_SI=
ZE) & PMD_MASK))
> >>  #define VMEMMAP_END    ((unsigned long)vmemmap + VMEMMAP_SIZE - 1)
> >>
> >> +#ifdef CONFIG_KFENCE
> >> +#define KFENCE_AREA_START      VMEMMAP_END
> >> +#define KFENCE_AREA_END                (KFENCE_AREA_START + KFENCE_AR=
EA_SIZE)
> >> +#endif
> >> +
> >>  #define pte_ERROR(e) \
> >>         pr_err("%s:%d: bad pte %016lx.\n", __FILE__, __LINE__, pte_val=
(e))
> >>  #ifndef __PAGETABLE_PMD_FOLDED
> >> diff --git a/arch/loongarch/mm/fault.c b/arch/loongarch/mm/fault.c
> >> index da5b6d518cdb..c0319128b221 100644
> >> --- a/arch/loongarch/mm/fault.c
> >> +++ b/arch/loongarch/mm/fault.c
> >> @@ -23,6 +23,7 @@
> >>  #include <linux/kprobes.h>
> >>  #include <linux/perf_event.h>
> >>  #include <linux/uaccess.h>
> >> +#include <linux/kfence.h>
> >>
> >>  #include <asm/branch.h>
> >>  #include <asm/mmu_context.h>
> >> @@ -30,7 +31,8 @@
> >>
> >>  int show_unhandled_signals =3D 1;
> >>
> >> -static void __kprobes no_context(struct pt_regs *regs, unsigned long =
address)
> >> +static void __kprobes no_context(struct pt_regs *regs, unsigned long =
address,
> >> +                                unsigned long write)
> >>  {
> >>         const int field =3D sizeof(unsigned long) * 2;
> >>
> >> @@ -38,6 +40,9 @@ static void __kprobes no_context(struct pt_regs *reg=
s, unsigned long address)
> >>         if (fixup_exception(regs))
> >>                 return;
> >>
> >> +       if (kfence_handle_page_fault(address, write, regs))
> >> +               return;
> >> +
> >>         /*
> >>          * Oops. The kernel tried to access some bad page. We'll have =
to
> >>          * terminate things with extreme prejudice.
> >> @@ -51,14 +56,15 @@ static void __kprobes no_context(struct pt_regs *r=
egs, unsigned long address)
> >>         die("Oops", regs);
> >>  }
> >>
> >> -static void __kprobes do_out_of_memory(struct pt_regs *regs, unsigned=
 long address)
> >> +static void __kprobes do_out_of_memory(struct pt_regs *regs, unsigned=
 long address,
> >> +                                      unsigned long write)
> >>  {
> >>         /*
> >>          * We ran out of memory, call the OOM killer, and return the u=
serspace
> >>          * (which will retry the fault, or kill us if we got oom-kille=
d).
> >>          */
> >>         if (!user_mode(regs)) {
> >> -               no_context(regs, address);
> >> +               no_context(regs, address, write);
> >>                 return;
> >>         }
> >>         pagefault_out_of_memory();
> >> @@ -69,7 +75,7 @@ static void __kprobes do_sigbus(struct pt_regs *regs=
,
> >>  {
> >>         /* Kernel mode? Handle exceptions or die */
> >>         if (!user_mode(regs)) {
> >> -               no_context(regs, address);
> >> +               no_context(regs, address, write);
> >>                 return;
> >>         }
> >>
> >> @@ -90,7 +96,7 @@ static void __kprobes do_sigsegv(struct pt_regs *reg=
s,
> >>
> >>         /* Kernel mode? Handle exceptions or die */
> >>         if (!user_mode(regs)) {
> >> -               no_context(regs, address);
> >> +               no_context(regs, address, write);
> >>                 return;
> >>         }
> >>
> >> @@ -149,7 +155,7 @@ static void __kprobes __do_page_fault(struct pt_re=
gs *regs,
> >>          */
> >>         if (address & __UA_LIMIT) {
> >>                 if (!user_mode(regs))
> >> -                       no_context(regs, address);
> >> +                       no_context(regs, address, write);
> >>                 else
> >>                         do_sigsegv(regs, write, address, si_code);
> >>                 return;
> >> @@ -211,7 +217,7 @@ static void __kprobes __do_page_fault(struct pt_re=
gs *regs,
> >>
> >>         if (fault_signal_pending(fault, regs)) {
> >>                 if (!user_mode(regs))
> >> -                       no_context(regs, address);
> >> +                       no_context(regs, address, write);
> >>                 return;
> >>         }
> >>
> >> @@ -232,7 +238,7 @@ static void __kprobes __do_page_fault(struct pt_re=
gs *regs,
> >>         if (unlikely(fault & VM_FAULT_ERROR)) {
> >>                 mmap_read_unlock(mm);
> >>                 if (fault & VM_FAULT_OOM) {
> >> -                       do_out_of_memory(regs, address);
> >> +                       do_out_of_memory(regs, address, write);
> >>                         return;
> >>                 } else if (fault & VM_FAULT_SIGSEGV) {
> >>                         do_sigsegv(regs, write, address, si_code);
> >> --
> >> 2.34.1
> >>
> >>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H4Hu-NT54G8_JuU1%2BQi6OsnjTr14Ohc3-qHf7-mcNK6aw%40mail.gmai=
l.com.
