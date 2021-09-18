Return-Path: <kasan-dev+bncBCCMH5WKTMGRBPFFS6FAMGQEWRCUW3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8039541061B
	for <lists+kasan-dev@lfdr.de>; Sat, 18 Sep 2021 13:51:25 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id oa15-20020a17090b1bcf00b0019c736b088fsf8112464pjb.5
        for <lists+kasan-dev@lfdr.de>; Sat, 18 Sep 2021 04:51:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631965884; cv=pass;
        d=google.com; s=arc-20160816;
        b=a7UqnPEKRjzRvcyKGIScHgh8KMgjd1k496KbsN/a9DnM6vXghwK2QlDRCamxQ8hpOB
         3kEaDU7o91jrlgFQngRUbDvE/BzmNNOgLy6iM05KoC+l5vgh5PYmB/KrRdSoXXBaVLu1
         gHNfxYScom5xdWhd4Ls+psxNzq4dfnKXblHGFHOIYXFfIVaa3+XYu0JY/cuxfKEtKZKq
         2HXbde7PhmJoVsD6SmVqWd5KEPoD1g7RW7HQo1vC9E9JLCBLzfYbZqbYVXaNa1cowJLc
         zQ3pkS/L2TbtjAMg9BG9okEoV+JruJs8kyPRHoKsxQe0GVs4uP3XnBvtWrCSAt8qZlOb
         0VCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=u1eecuxbfJAB5FOYlJxXu7mv9W7rFnXzAtkOGVUrm90=;
        b=zjGccGk0LsRYZkiOS/7sus0snDG98x+VY8LbaGR9hQaAYncBlMccRZpCd4EsqTLe4v
         J5NPKqbeXhdRRAsSxdpKfbGyEnYQ7h/CwZqljlpYkaohNgHw1Vt3xT/j3sBvGTYJMpu4
         rOTKbFC/Mp/1hhGPGPJFSgU8I6ZmciSHQIJoqqpuNE7Z4E1GTrLGe+A81GRiqQEE2UzS
         G2nk+uVE+oXz5TaU19beIYyOlQRH4xKTDtarPvX9edryeYSJwWFLk0F9zEV5V9x/ZTM6
         NbxnRgbfY2ihJp+CJRZepNWOhIBQ/zQppapjViY65mthiG0ndIuEsh0DB0YQjgb7GIf4
         WG0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kzWzPD2O;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=u1eecuxbfJAB5FOYlJxXu7mv9W7rFnXzAtkOGVUrm90=;
        b=oxh+7EF+oy5Omrivs2zj9ZLsLaElUejjVlUJj+u5RnhlWR+dFJC6dhlEh879tW+KDz
         /oq5mF+wm5bK9Q8cn2nFJ7UwfKxSwQeybMKiBR2+Tr35zOsJccpIviOb2NEK35IP5MI1
         9jZOg8Ac3Z/Gd158JE2JBk6981ipaeyRq3ciWsxX8nw4YSbaqGvw39siwNrBdz6REeWo
         ejKveKvwU8gYujItje09cAXYnDmNXfjjiryj+zVwobN+D8RjiPvKs+rBiRd4X/fQTJ3C
         c0J3/6ISuGL413qsf3sLzdX1ogb900/7sFnvWtDwKFzKe0FB3VhEgc3iy42kdOByefo3
         Psyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=u1eecuxbfJAB5FOYlJxXu7mv9W7rFnXzAtkOGVUrm90=;
        b=Nxz9BGQ/u70EgadrXTZC4/Y2HnCNgxtVBe6/oyTj7QzO3ajTQH7OHOTFZvyRGVe3sV
         R6jyk5Sis4ME/RDT7fHb6sAKk4dHS2XDYjP54JbJl1NC+VENQqoOasLEaexd4r6U+Qt/
         N/4HXh1w2k54L1NceiBy8rmMDoHErOZNbxos+Rg+LltoBe5KfH5xtjg+dsANPX0eDsAx
         ojl/p8Zul2kPURie/ghrYj4uOS4YeIxZ7PM0e98lK9YjtCsu2S9FvoQ1Y8bSlNa979Ek
         1eFU5Yqj1CEE7XkCQB8R3NiMR6DyYXpf0J3Ix2SjL3PZ+oRLrIvxE8gIuuD3jaMraUxY
         ECgQ==
X-Gm-Message-State: AOAM5315QCHQMGzYEyOH8O8atcY2eun4HItsC0xAfsOgfijPNXVJrDgH
	t01UDiieT2wVxdeEqyzJW4k=
X-Google-Smtp-Source: ABdhPJwzqyuazkH6lPKPaaqnf8+L2z1RIBGmpxVqNl9ask+Mt26lfXEy9KOYOTo+IwynTgQrJMKsog==
X-Received: by 2002:a17:90b:a4a:: with SMTP id gw10mr18075597pjb.245.1631965884217;
        Sat, 18 Sep 2021 04:51:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e57:: with SMTP id p23ls8138095pja.2.canary-gmail;
 Sat, 18 Sep 2021 04:51:23 -0700 (PDT)
X-Received: by 2002:a17:903:22c7:b0:13c:855a:3d74 with SMTP id y7-20020a17090322c700b0013c855a3d74mr14179486plg.74.1631965883644;
        Sat, 18 Sep 2021 04:51:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631965883; cv=none;
        d=google.com; s=arc-20160816;
        b=JH20YueWbgx1F6R4dXKJUsUhemzgEE+V/mbVCrDlN6E3jBhWJimTsguNnerxb6MAnQ
         2+PKrDRpuzVSj87Vt0f9xyJlAohYSGRaw185FaTjGmZZHYVOvsAGpWdE0Q+srqsjAuB7
         PmoQt3BJNP2FMm/dn8Fj2LXXvfYXWb4NgSK4viBGj13Jn8Z0Fk0XPeV11PUHQuPna7je
         J7KYtQ1T2PXNHn7apMyng0jSbTiOYEFdmgFwBNq19fh4lYXwMPlxtFtUS3W2wJ+EfQJe
         JZ11fy08A6mja+Ro36oMU/uAXcjV3p5XFndKqhGydcb2O7WobDM78d+477qEL9ZZO2wh
         4nzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=g4n08dQJMaesgf8J0xabMK1i7+F7RpBHsMNZa6B0wFg=;
        b=bGCPJR5ChQU4FsjIWGmmTThm/kn2E8Aoz9KOfD4C8q9Nf0UZN+EAyanXm73u509jOV
         K71nPBs8IWXHXtR9Y9MjHeW/kSTlC0/zpFAgFc6heE9YzJ/bP0R06Dbl/sUyPke8iynf
         B3cukfiCM/dShEUUnA7+RR2CVA/Owog3BMrkqq+MHwtyx9+3XkrfnXZ0oSQbbS7xp9G5
         Ana1tGrHqDVfazIYQEVJC4M9qRy+goQGZziJNKLr0hhv21QVO2t274IQNNR57ZjR5p6B
         q41vcLr+xjkxRJf9sQ/2nghr+mAT6nKl3EY7kxUIVrKvaSyEUIcZ9U5oiGFJwEtX3VKT
         LEVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kzWzPD2O;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72d.google.com (mail-qk1-x72d.google.com. [2607:f8b0:4864:20::72d])
        by gmr-mx.google.com with ESMTPS id n63si1117772pfd.3.2021.09.18.04.51.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 18 Sep 2021 04:51:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72d as permitted sender) client-ip=2607:f8b0:4864:20::72d;
Received: by mail-qk1-x72d.google.com with SMTP id ay33so25948964qkb.10
        for <kasan-dev@googlegroups.com>; Sat, 18 Sep 2021 04:51:23 -0700 (PDT)
X-Received: by 2002:a37:f903:: with SMTP id l3mr14896801qkj.502.1631965883097;
 Sat, 18 Sep 2021 04:51:23 -0700 (PDT)
MIME-Version: 1.0
References: <20210918083849.2696287-1-liushixin2@huawei.com>
In-Reply-To: <20210918083849.2696287-1-liushixin2@huawei.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 18 Sep 2021 13:50:47 +0200
Message-ID: <CAG_fn=X=k3w-jr3iCevB_t7Hh0r=qZ=nOxwk5ujsO+LZ7hA4Aw@mail.gmail.com>
Subject: Re: [PATCH] arm64: remove page granularity limitation from KFENCE
To: Liu Shixin <liushixin2@huawei.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, LKML <linux-kernel@vger.kernel.org>, 
	Jisheng.Zhang@synaptics.com, Ard Biesheuvel <ard.biesheuvel@linaro.org>, 
	Mark Rutland <mark.rutland@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=kzWzPD2O;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72d as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Sat, Sep 18, 2021 at 10:10 AM Liu Shixin <liushixin2@huawei.com> wrote:
>
> Currently if KFENCE is enabled in arm64, the entire linear map will be
> mapped at page granularity which seems overkilled. Actually only the
> kfence pool requires to be mapped at page granularity. We can remove the
> restriction from KFENCE and force the linear mapping of the kfence pool
> at page granularity later in arch_kfence_init_pool().

There was a previous patch by Jisheng Zhang intended to remove this
requirement: https://lore.kernel.org/linux-arm-kernel/20210524180656.395e45=
f6@xhacker.debian/
Which of the two is more preferable?

> Signed-off-by: Liu Shixin <liushixin2@huawei.com>
> ---
>  arch/arm64/include/asm/kfence.h | 69 ++++++++++++++++++++++++++++++++-
>  arch/arm64/mm/mmu.c             |  4 +-
>  2 files changed, 70 insertions(+), 3 deletions(-)
>
> diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfe=
nce.h
> index aa855c6a0ae6..bee101eced0b 100644
> --- a/arch/arm64/include/asm/kfence.h
> +++ b/arch/arm64/include/asm/kfence.h
> @@ -8,9 +8,76 @@
>  #ifndef __ASM_KFENCE_H
>  #define __ASM_KFENCE_H
>
> +#include <linux/kfence.h>
>  #include <asm/set_memory.h>
> +#include <asm/pgalloc.h>
>
> -static inline bool arch_kfence_init_pool(void) { return true; }
> +static inline int split_pud_page(pud_t *pud, unsigned long addr)
> +{
> +       int i;
> +       pmd_t *pmd =3D pmd_alloc_one(&init_mm, addr);
> +       unsigned long pfn =3D PFN_DOWN(__pa(addr));
> +
> +       if (!pmd)
> +               return -ENOMEM;
> +
> +       for (i =3D 0; i < PTRS_PER_PMD; i++)
> +               set_pmd(pmd + i, pmd_mkhuge(pfn_pmd(pfn + i * PTRS_PER_PT=
E, PAGE_KERNEL)));
> +
> +       smp_wmb(); /* See comment in __pte_alloc */
> +       pud_populate(&init_mm, pud, pmd);
> +       flush_tlb_kernel_range(addr, addr + PUD_SIZE);
> +       return 0;
> +}
> +
> +static inline int split_pmd_page(pmd_t *pmd, unsigned long addr)
> +{
> +       int i;
> +       pte_t *pte =3D pte_alloc_one_kernel(&init_mm);
> +       unsigned long pfn =3D PFN_DOWN(__pa(addr));
> +
> +       if (!pte)
> +               return -ENOMEM;
> +
> +       for (i =3D 0; i < PTRS_PER_PTE; i++)
> +               set_pte(pte + i, pfn_pte(pfn + i, PAGE_KERNEL));
> +
> +       smp_wmb(); /* See comment in __pte_alloc */
> +       pmd_populate_kernel(&init_mm, pmd, pte);
> +
> +       flush_tlb_kernel_range(addr, addr + PMD_SIZE);
> +       return 0;
> +}
> +
> +static inline bool arch_kfence_init_pool(void)
> +{
> +       unsigned long addr;
> +       pgd_t *pgd;
> +       p4d_t *p4d;
> +       pud_t *pud;
> +       pmd_t *pmd;
> +
> +       for (addr =3D (unsigned long)__kfence_pool; is_kfence_address((vo=
id *)addr);
> +            addr +=3D PAGE_SIZE) {
> +               pgd =3D pgd_offset(&init_mm, addr);
> +               if (pgd_leaf(*pgd))
> +                       return false;
> +               p4d =3D p4d_offset(pgd, addr);
> +               if (p4d_leaf(*p4d))
> +                       return false;
> +               pud =3D pud_offset(p4d, addr);
> +               if (pud_leaf(*pud)) {
> +                       if (split_pud_page(pud, addr & PUD_MASK))
> +                               return false;
> +               }
> +               pmd =3D pmd_offset(pud, addr);
> +               if (pmd_leaf(*pmd)) {
> +                       if (split_pmd_page(pmd, addr & PMD_MASK))
> +                               return false;
> +               }
> +       }
> +       return true;
> +}
>
>  static inline bool kfence_protect_page(unsigned long addr, bool protect)
>  {
> diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
> index cfd9deb347c3..b2c79ccfb1c5 100644
> --- a/arch/arm64/mm/mmu.c
> +++ b/arch/arm64/mm/mmu.c
> @@ -516,7 +516,7 @@ static void __init map_mem(pgd_t *pgdp)
>          */
>         BUILD_BUG_ON(pgd_index(direct_map_end - 1) =3D=3D pgd_index(direc=
t_map_end));
>
> -       if (can_set_direct_map() || crash_mem_map || IS_ENABLED(CONFIG_KF=
ENCE))
> +       if (can_set_direct_map() || crash_mem_map)
>                 flags |=3D NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
>
>         /*
> @@ -1485,7 +1485,7 @@ int arch_add_memory(int nid, u64 start, u64 size,
>          * KFENCE requires linear map to be mapped at page granularity, s=
o that
>          * it is possible to protect/unprotect single pages in the KFENCE=
 pool.
>          */
> -       if (can_set_direct_map() || IS_ENABLED(CONFIG_KFENCE))
> +       if (can_set_direct_map())
>                 flags |=3D NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
>
>         __create_pgd_mapping(swapper_pg_dir, start, __phys_to_virt(start)=
,
> --
> 2.18.0.huawei.25
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/20210918083849.2696287-1-liushixin2%40huawei.com.



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DX%3Dk3w-jr3iCevB_t7Hh0r%3DqZ%3DnOxwk5ujsO%2BLZ7hA4Aw%40m=
ail.gmail.com.
