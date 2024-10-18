Return-Path: <kasan-dev+bncBAABBNFFY64AMGQEVJAXM6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1EFD89A333A
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 05:15:02 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id 3f1490d57ef6-e293b3e014asf2729010276.3
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2024 20:15:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729221301; cv=pass;
        d=google.com; s=arc-20240605;
        b=KAMFKK4rH9r8s69N321ascIoWaybmptX8hV+Zt3RdYs9EaHADAbo8QJXkmgAUzYCPu
         4al6WH1xBb3kztLR3crqazH/f6Umkbvf421/DtLAbej0t+LyStgtVf44Xn3oyKWGfbj2
         YM+j87acaKE5NFi2/MdgKxgT8+AMXh2QZr8LHas+GU66SKeExpowmGelY1Z+xeUWdnTU
         uE24u+ECg0jki9VIREIbrI9UTSnhv8lqYcEXoXeSqeqvrtnHCOIf6UKfCfVjagz+juAN
         HIaouvMSiiHgmIHZyEMqGNC+ZTZApnGug8mJ6+vRL2uBfssx2Cocd/ctXSvrfR/grmCi
         btpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XiyGxP8IrgPgtj0cg8ePP6AD9Yo6dOJjmcJ27XBYjUU=;
        fh=rYPVRM2i/yi450g6q/P1Z6OgJGKumwxNVE2bytHvogQ=;
        b=K3ws2sd67n7Gh0xAdD0kvCZMIG6WgfsnCUwA8H0tuWPyVP2lBGS/pLF+SPpdikGiit
         AhEMrsggxymajwSYzRNrQJsExMNU/cut+hrPYbpKGiktlFPhgNeAvbwkWSA8wFje62Xd
         vNCfvuIlar9nBJg6ZTdsB8XUFe/lkY7OnHvR87byC85TKpj6lvSCBoKURv6nFu4ORlIg
         l7HbZFKws/xB1timmMlqb97EGhcng/zci/NL4j5vH1UJnddVRn9hd6TRO+fr9o8vgOCs
         YD+Rp3GiylaosdrFHtDIbRNrSYfWFBBJzj6l5RZc98h2zLt763NjwHKB+xYgcBJ0S5kZ
         ED4g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KEDbctta;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729221301; x=1729826101; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XiyGxP8IrgPgtj0cg8ePP6AD9Yo6dOJjmcJ27XBYjUU=;
        b=rIBlumqmHRnecbICJ23yQto1NQfoL/+Qa7lm7MtY/dNw9GEBBseodsn3LWoZhzeqgx
         nIaZpSDvPv/AF4/l5zR5835ufV71+RoV0rb3UfaCXynMD2kB7Ed0athmSXNkmqvE72hf
         9Fo+NhOHdzNFw2m79qTbNKMKn7sYUakTeCHUB29teg+s1GEkCfIFm2jhl/v/M1mFZ3i1
         Hrx+NmKmbkiiQzRqeZ/oV2AIFKoZdZjZIPLTrknhq/QXzaFmos4+Q/PKRqm5WZaDYl4v
         xGIvVAcyBuvGVuKE87Y2BSeHIdn3uJCuZNpt1q+wtjFl+efyOAGGSuyoSO8cPCIlCFeP
         TtBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729221301; x=1729826101;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=XiyGxP8IrgPgtj0cg8ePP6AD9Yo6dOJjmcJ27XBYjUU=;
        b=kfzOMRavnS3f81BmV088l07zscf0sugL8JJuuKl9PFKwowpc1RPhd8Ly+Ehx6vO3GB
         plDmmPUCiSujOSTg3Z0jPX0xMpM+d7oyK4+BlpoaMAiCrru4NEYbd/9Mi0E5H8CvHGrt
         m44yNVD0fOhvxXriuxUCHTjhoieU7Z2hyzS3ZQlHFVqUT9TdApp9dUJjbBTQsbbP0UUT
         6GuoGKQvoGc748pXtDkdgK5TMpNg/DEhWDaHvA/oINbzlRQNH8ujUoF5pLg5DlFUqbVr
         IXz98lbBMO3hQcx/5BlR/W0yKoHdMVlWW9VfKYul2CU/8SL9qDUZ9G4p5gvYfP3qciQt
         37Iw==
X-Forwarded-Encrypted: i=2; AJvYcCWTvrM4Q4UcW2banHld2JhfAqrPbDF74abiUtVOPrfDBlDNeZUuh+FLIfdSVKBGv4hOKhS1nQ==@lfdr.de
X-Gm-Message-State: AOJu0YzG3FsuHSZqvAvVQ0ObzIjM/S1rrQvhDXYd+eDhGzhTg8EtRgTF
	MZkdXkiEqSWy/3uhVmug3bopQUnhio+vX2q6in62GBX0woF/CPB9
X-Google-Smtp-Source: AGHT+IGnbY+v4Y7qH9Pj745ZVjm7VSlM7SKcNUfqdmr//NvWPvgomJc5ezPKCkMHFqFkNEc176VwNg==
X-Received: by 2002:a05:6902:2087:b0:e29:db3:23eb with SMTP id 3f1490d57ef6-e2bb11bd742mr982308276.3.1729221300706;
        Thu, 17 Oct 2024 20:15:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:120c:b0:e28:ee2b:34fe with SMTP id
 3f1490d57ef6-e2b9ce231eals1930557276.2.-pod-prod-04-us; Thu, 17 Oct 2024
 20:15:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVxfEpuWU1MEWywHqExodgy/NUL9QJ+7/DaB8yjBVN1XxsksSDNKP4vfJlDEUT/l6080W4WugmdPbE=@googlegroups.com
X-Received: by 2002:a05:6902:20c6:b0:e28:687e:c151 with SMTP id 3f1490d57ef6-e2bb16c33a2mr849037276.54.1729221299895;
        Thu, 17 Oct 2024 20:14:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729221299; cv=none;
        d=google.com; s=arc-20240605;
        b=eLBGJ6C3x1g1SwC2ZQMAYHf4nafWB39qcPe6ZCPvJq1FfUdZplottrunAsI48o/t1+
         zyZ6u4Cvj+nH0GOw+pSZJOc7KZ5ha/cdFGGuYAIwW3aEXABVlWpUSC7cHTFt1Jh7HEPT
         2/SR+Hvif0JP7MVirt33knfGBKzrvIguqO2if+BtxXdwk4YvMAHEatId7eM8UwoqiNEi
         xPf49XWKkqlUqXPmio9DbJ6eAkdHw28X3fcYUvL8CUrWMd4MXo4/GDGpzZf604Arx+cg
         ETufFYuTQI4q6NQIjJiG1HOxCP9oeTdQR86LACUCJmUomY35O7ceo6PY9Hp9GBQTkmNv
         n8nA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=V0cKLvDud0XHZnRbbPgpBZzBUmEg/ZW4X36LpK7ngME=;
        fh=C41OdIP15BE//ZPE8fFoTZ0ns//dR2s1Uy1UXQylmUk=;
        b=S8YyxptAHoSj46M4gEbYrfOcXkdRg/M8hvqSjK+yjTk/ntk+hCBB9lckOhNAUGLeOP
         ocMsjaQZ6jBSF/fpgfe2X+skGRIOjfAgDf4UBXDt/xDybf0mShlQWQxB8SEBttlO5xTX
         u3HzE2MwFDxaDQBg8o/wssUMs93dVMEZA8U7i1ymxzfbMNCGAEQv0z56tYjo9+kdxZHB
         1WBLxUhnEN2N+SbwHPEoPYQS+05nLuXrBr5d1/cRThy6uEyY0cxEVI6KR8c2BKdlYXJf
         ze3vs0aM9t9vpmcI9kJe3UJZHL9zbRAM4pEp07u59Sgl33Uz5PF3kdw9IHCgC1+SDql7
         re3w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KEDbctta;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e2bb03fbe9bsi36116276.3.2024.10.17.20.14.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Oct 2024 20:14:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 045BD5C5E7C
	for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 03:14:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1E9D0C4CECE
	for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 03:14:59 +0000 (UTC)
Received: by mail-ed1-f49.google.com with SMTP id 4fb4d7f45d1cf-5c903f5bd0eso2855090a12.3
        for <kasan-dev@googlegroups.com>; Thu, 17 Oct 2024 20:14:59 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVoXf/tDwENVvbfWhkqHwRbpmewQdArshHMnsB41UvBi0AboalzLKf6HUXrEYQCcYzX/R7KSzlNuHw=@googlegroups.com
X-Received: by 2002:a17:907:6e86:b0:a99:e82a:87ee with SMTP id
 a640c23a62f3a-a9a69cd2ffemr63769566b.57.1729221297651; Thu, 17 Oct 2024
 20:14:57 -0700 (PDT)
MIME-Version: 1.0
References: <20241014035855.1119220-1-maobibo@loongson.cn> <20241014035855.1119220-2-maobibo@loongson.cn>
In-Reply-To: <20241014035855.1119220-2-maobibo@loongson.cn>
From: "'Huacai Chen' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Oct 2024 11:14:45 +0800
X-Gmail-Original-Message-ID: <CAAhV-H5QkULWp6fciR1Lnds0r00fUdrmj86K_wBuxd0D=RkaXQ@mail.gmail.com>
Message-ID: <CAAhV-H5QkULWp6fciR1Lnds0r00fUdrmj86K_wBuxd0D=RkaXQ@mail.gmail.com>
Subject: Re: [PATCH v2 1/3] LoongArch: Set initial pte entry with PAGE_GLOBAL
 for kernel space
To: Bibo Mao <maobibo@loongson.cn>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	David Hildenbrand <david@redhat.com>, Barry Song <baohua@kernel.org>, loongarch@lists.linux.dev, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=KEDbctta;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Huacai Chen <chenhuacai@kernel.org>
Reply-To: Huacai Chen <chenhuacai@kernel.org>
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

Hi, Bibo,

I applied this patch but drop the part of arch/loongarch/mm/kasan_init.c:
https://git.kernel.org/pub/scm/linux/kernel/git/chenhuacai/linux-loongson.g=
it/commit/?h=3Dloongarch-next&id=3D15832255e84494853f543b4c70ced50afc403067

Because kernel_pte_init() should operate on page-table pages, not on
data pages. You have already handle page-table page in
mm/kasan/init.c, and if we don't drop the modification on data pages
in arch/loongarch/mm/kasan_init.c, the kernel fail to boot if KASAN is
enabled.

Huacai

On Mon, Oct 14, 2024 at 11:59=E2=80=AFAM Bibo Mao <maobibo@loongson.cn> wro=
te:
>
> Unlike general architectures, there are two pages in one TLB entry
> on LoongArch system. For kernel space, it requires both two pte
> entries with PAGE_GLOBAL bit set, else HW treats it as non-global
> tlb, there will be potential problems if tlb entry for kernel space
> is not global. Such as fail to flush kernel tlb with function
> local_flush_tlb_kernel_range() which only flush tlb with global bit.
>
> With function kernel_pte_init() added, it can be used to init pte
> table when it is created for kernel address space, and the default
> initial pte value is PAGE_GLOBAL rather than zero at beginning.
>
> Kernel address space areas includes fixmap, percpu, vmalloc, kasan
> and vmemmap areas set default pte entry with PAGE_GLOBAL set.
>
> Signed-off-by: Bibo Mao <maobibo@loongson.cn>
> ---
>  arch/loongarch/include/asm/pgalloc.h | 13 +++++++++++++
>  arch/loongarch/include/asm/pgtable.h |  1 +
>  arch/loongarch/mm/init.c             |  4 +++-
>  arch/loongarch/mm/kasan_init.c       |  4 +++-
>  arch/loongarch/mm/pgtable.c          | 22 ++++++++++++++++++++++
>  include/linux/mm.h                   |  1 +
>  mm/kasan/init.c                      |  8 +++++++-
>  mm/sparse-vmemmap.c                  |  5 +++++
>  8 files changed, 55 insertions(+), 3 deletions(-)
>
> diff --git a/arch/loongarch/include/asm/pgalloc.h b/arch/loongarch/includ=
e/asm/pgalloc.h
> index 4e2d6b7ca2ee..b2698c03dc2c 100644
> --- a/arch/loongarch/include/asm/pgalloc.h
> +++ b/arch/loongarch/include/asm/pgalloc.h
> @@ -10,8 +10,21 @@
>
>  #define __HAVE_ARCH_PMD_ALLOC_ONE
>  #define __HAVE_ARCH_PUD_ALLOC_ONE
> +#define __HAVE_ARCH_PTE_ALLOC_ONE_KERNEL
>  #include <asm-generic/pgalloc.h>
>
> +static inline pte_t *pte_alloc_one_kernel(struct mm_struct *mm)
> +{
> +       pte_t *pte;
> +
> +       pte =3D (pte_t *) __get_free_page(GFP_KERNEL);
> +       if (!pte)
> +               return NULL;
> +
> +       kernel_pte_init(pte);
> +       return pte;
> +}
> +
>  static inline void pmd_populate_kernel(struct mm_struct *mm,
>                                        pmd_t *pmd, pte_t *pte)
>  {
> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/includ=
e/asm/pgtable.h
> index 9965f52ef65b..22e3a8f96213 100644
> --- a/arch/loongarch/include/asm/pgtable.h
> +++ b/arch/loongarch/include/asm/pgtable.h
> @@ -269,6 +269,7 @@ extern void set_pmd_at(struct mm_struct *mm, unsigned=
 long addr, pmd_t *pmdp, pm
>  extern void pgd_init(void *addr);
>  extern void pud_init(void *addr);
>  extern void pmd_init(void *addr);
> +extern void kernel_pte_init(void *addr);
>
>  /*
>   * Encode/decode swap entries and swap PTEs. Swap PTEs are all PTEs that
> diff --git a/arch/loongarch/mm/init.c b/arch/loongarch/mm/init.c
> index 8a87a482c8f4..9f26e933a8a3 100644
> --- a/arch/loongarch/mm/init.c
> +++ b/arch/loongarch/mm/init.c
> @@ -198,9 +198,11 @@ pte_t * __init populate_kernel_pte(unsigned long add=
r)
>         if (!pmd_present(pmdp_get(pmd))) {
>                 pte_t *pte;
>
> -               pte =3D memblock_alloc(PAGE_SIZE, PAGE_SIZE);
> +               pte =3D memblock_alloc_raw(PAGE_SIZE, PAGE_SIZE);
>                 if (!pte)
>                         panic("%s: Failed to allocate memory\n", __func__=
);
> +
> +               kernel_pte_init(pte);
>                 pmd_populate_kernel(&init_mm, pmd, pte);
>         }
>
> diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_ini=
t.c
> index 427d6b1aec09..34988573b0d5 100644
> --- a/arch/loongarch/mm/kasan_init.c
> +++ b/arch/loongarch/mm/kasan_init.c
> @@ -152,6 +152,8 @@ static void __init kasan_pte_populate(pmd_t *pmdp, un=
signed long addr,
>                 phys_addr_t page_phys =3D early ?
>                                         __pa_symbol(kasan_early_shadow_pa=
ge)
>                                               : kasan_alloc_zeroed_page(n=
ode);
> +               if (!early)
> +                       kernel_pte_init(__va(page_phys));
>                 next =3D addr + PAGE_SIZE;
>                 set_pte(ptep, pfn_pte(__phys_to_pfn(page_phys), PAGE_KERN=
EL));
>         } while (ptep++, addr =3D next, addr !=3D end && __pte_none(early=
, ptep_get(ptep)));
> @@ -287,7 +289,7 @@ void __init kasan_init(void)
>                 set_pte(&kasan_early_shadow_pte[i],
>                         pfn_pte(__phys_to_pfn(__pa_symbol(kasan_early_sha=
dow_page)), PAGE_KERNEL_RO));
>
> -       memset(kasan_early_shadow_page, 0, PAGE_SIZE);
> +       kernel_pte_init(kasan_early_shadow_page);
>         csr_write64(__pa_symbol(swapper_pg_dir), LOONGARCH_CSR_PGDH);
>         local_flush_tlb_all();
>
> diff --git a/arch/loongarch/mm/pgtable.c b/arch/loongarch/mm/pgtable.c
> index eb6a29b491a7..228ffc1db0a3 100644
> --- a/arch/loongarch/mm/pgtable.c
> +++ b/arch/loongarch/mm/pgtable.c
> @@ -38,6 +38,28 @@ pgd_t *pgd_alloc(struct mm_struct *mm)
>  }
>  EXPORT_SYMBOL_GPL(pgd_alloc);
>
> +void kernel_pte_init(void *addr)
> +{
> +       unsigned long *p, *end;
> +       unsigned long entry;
> +
> +       entry =3D (unsigned long)_PAGE_GLOBAL;
> +       p =3D (unsigned long *)addr;
> +       end =3D p + PTRS_PER_PTE;
> +
> +       do {
> +               p[0] =3D entry;
> +               p[1] =3D entry;
> +               p[2] =3D entry;
> +               p[3] =3D entry;
> +               p[4] =3D entry;
> +               p +=3D 8;
> +               p[-3] =3D entry;
> +               p[-2] =3D entry;
> +               p[-1] =3D entry;
> +       } while (p !=3D end);
> +}
> +
>  void pgd_init(void *addr)
>  {
>         unsigned long *p, *end;
> diff --git a/include/linux/mm.h b/include/linux/mm.h
> index ecf63d2b0582..6909fe059a2c 100644
> --- a/include/linux/mm.h
> +++ b/include/linux/mm.h
> @@ -3818,6 +3818,7 @@ void *sparse_buffer_alloc(unsigned long size);
>  struct page * __populate_section_memmap(unsigned long pfn,
>                 unsigned long nr_pages, int nid, struct vmem_altmap *altm=
ap,
>                 struct dev_pagemap *pgmap);
> +void kernel_pte_init(void *addr);
>  void pmd_init(void *addr);
>  void pud_init(void *addr);
>  pgd_t *vmemmap_pgd_populate(unsigned long addr, int node);
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index 89895f38f722..ac607c306292 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -106,6 +106,10 @@ static void __ref zero_pte_populate(pmd_t *pmd, unsi=
gned long addr,
>         }
>  }
>
> +void __weak __meminit kernel_pte_init(void *addr)
> +{
> +}
> +
>  static int __ref zero_pmd_populate(pud_t *pud, unsigned long addr,
>                                 unsigned long end)
>  {
> @@ -126,8 +130,10 @@ static int __ref zero_pmd_populate(pud_t *pud, unsig=
ned long addr,
>
>                         if (slab_is_available())
>                                 p =3D pte_alloc_one_kernel(&init_mm);
> -                       else
> +                       else {
>                                 p =3D early_alloc(PAGE_SIZE, NUMA_NO_NODE=
);
> +                               kernel_pte_init(p);
> +                       }
>                         if (!p)
>                                 return -ENOMEM;
>
> diff --git a/mm/sparse-vmemmap.c b/mm/sparse-vmemmap.c
> index edcc7a6b0f6f..c0388b2e959d 100644
> --- a/mm/sparse-vmemmap.c
> +++ b/mm/sparse-vmemmap.c
> @@ -184,6 +184,10 @@ static void * __meminit vmemmap_alloc_block_zero(uns=
igned long size, int node)
>         return p;
>  }
>
> +void __weak __meminit kernel_pte_init(void *addr)
> +{
> +}
> +
>  pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, unsigned long addr, i=
nt node)
>  {
>         pmd_t *pmd =3D pmd_offset(pud, addr);
> @@ -191,6 +195,7 @@ pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, un=
signed long addr, int node)
>                 void *p =3D vmemmap_alloc_block_zero(PAGE_SIZE, node);
>                 if (!p)
>                         return NULL;
> +               kernel_pte_init(p);
>                 pmd_populate_kernel(&init_mm, pmd, p);
>         }
>         return pmd;
> --
> 2.39.3
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H5QkULWp6fciR1Lnds0r00fUdrmj86K_wBuxd0D%3DRkaXQ%40mail.gmai=
l.com.
