Return-Path: <kasan-dev+bncBAABB6MPRC4QMGQETDZKPPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6092E9B5FDD
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2024 11:18:35 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-2e3be80e9f3sf699698a91.1
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2024 03:18:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730283514; cv=pass;
        d=google.com; s=arc-20240605;
        b=TKzZTlwTnVPSpAuNGT2rw8voJdqQskmUWV1xSSiANMmtPwhNaEBLnq/6RWEnbF4rQI
         QojEaO1I8hm4UJTqpgwk7mVG5smDqxOc36d5FGcKzCv+0S0Qvsx3VvQG+sbrk4R38r1x
         oXrJ+VV9GPKD4uCL/3fnlMUeBnvP4cyUxlIrsYuOhOmOIuIhxKZsh7lweXwma5fzcRPQ
         31BpQYli3WtzhmE8iAIew5F5Hgue0/WoDpSr3WCfDv2kiyFdbLWThkWM0h+WC6e7mH6n
         ruVKWJ7G8dNxN9m7qPrV3lwZRTOVxORhoPKCrqsXEN46o4nWECPc2MN32PLBv/lOTxQT
         oiMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yJUC8ttA3qe7YCleItFiNn8l477/z5Byr/jC95qS4p4=;
        fh=W8n4hd+DL7tFcYYJOo0PCLSHbW98kIDk7Bob5k3CGCs=;
        b=NsVbp/WOeiK/XzHVZBMq/OAQQin7im0Xz/dswsE9wLrcBHhhxxzGP1wmeJLxAMeFSk
         u9jwjNngQLXTX0JvI37ljYaSsLWGzmcOK4vrya0rXATob9/U3RsS9VxKc1BD496K9E6A
         r/bXYXbrBsPmaCLgTPDWcv4u3YL4OEQYtwnWGB9zfrTUETrQ2mqV2gijhRmH/HdIumJN
         2cLGyYKE5i3mfzuNI7HykmsgQbwFOJHrc6PP4oyd36wuuON8jt47r9Duf58yOkSEvTVv
         Pi9em9ffmTAfOQT48+r4PZYUbf7CrrzrhzYcWXDZ+QfqLkZgqVCbUM24cYspdz7FeNU8
         NVtA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QmLBYLiQ;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730283514; x=1730888314; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yJUC8ttA3qe7YCleItFiNn8l477/z5Byr/jC95qS4p4=;
        b=ukbRT9aorWC/oqVZhaZLr2IjdvLbrNingRzgRYMHiKa8jq3SWAUVV7OkLBkatifieG
         meBwlsnsS2bjY6q049hilUIzlOc95LGL82QKadgg0diS155dnNlpxI+KWGAH/g3iwVni
         9w2PfdxziZ+yQgD0+9ZcJmVyI2i7u+YcxsioG74/I9dcL35pVlU+rjSntZzjtWzs6Nfy
         lnMexyz+8EnJWJ8x/9WbKOsaVBuklxYy2ATJc0aKwR3XtEZLRHFRN1gnILIT23iwuXWK
         2AmRdbjoTKnfbH3u1Bf+4G8MszfTbhddCfgHtylw/Wg+EnU78ba+QtQfR5X4DUdzFc8Z
         MGVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730283514; x=1730888314;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=yJUC8ttA3qe7YCleItFiNn8l477/z5Byr/jC95qS4p4=;
        b=bDumqUnmAAaEclz5v7Dtgr5WQyXzfJ4Sg317BaYuvxMf9970KjWR+M/bu7n0MEALEe
         rIGr95RzbUwm8xgs7GIGQQSN4TA3aYBTpST5iF0+K457dCecSG5nE4wB4wIwU/Z0p0s9
         AYf7o0jPPlB8v/EOp9HmYz13f4UJRCLpmjOXqpLOu8p7rU5sFzjRXtW5OSTZKKfEKSe7
         QJw6XwSiYSmKfS2o+BfMrX76Klns3yToMw77MthDN1ON4A2jd/UcTfTSjSaNBG6KZYZe
         fyu0ylUcaHXXD0/hF12huKh4RY4HGwYb2wA0YfQa52jR8yzqPXt7DbPndvj2/TIa03bK
         x2bg==
X-Forwarded-Encrypted: i=2; AJvYcCXrHqTMIoB7P/iXjGe1t2xD8oub7WfDkzavg15uA9FOUhITuhrM9NgxdV+y4zJuT0ExNdIiOQ==@lfdr.de
X-Gm-Message-State: AOJu0YwpHvo7NEwMmgfp03CMdX4MhHfGMG54axoLRsDzX7NI6QFLUHQN
	RIXcTlADZbvpmK3ZkQ7QW6Qe8WUm7bsqFQD3z5yz1MgLAAfbFE+e
X-Google-Smtp-Source: AGHT+IFjk/PoUif6ZmygujumLyZmEq78HfBoq2/QPYwo/REoUZxierzMbenEumwze5HyehxnZ8ZHng==
X-Received: by 2002:a17:90b:507:b0:2d8:b043:9414 with SMTP id 98e67ed59e1d1-2e9224d9dbemr8112469a91.18.1730283513575;
        Wed, 30 Oct 2024 03:18:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3101:b0:2e2:b20d:f6a3 with SMTP id
 98e67ed59e1d1-2e92d792093ls482455a91.1.-pod-prod-00-us-canary; Wed, 30 Oct
 2024 03:18:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCViajHUFRO1mrTyW8jRdNYCltLM0HIiufm75NTzjT6STGz4029DtXIp0PXrl9EPuuEyNjKYrqD35hU=@googlegroups.com
X-Received: by 2002:a17:903:22c3:b0:20c:cb6b:3631 with SMTP id d9443c01a7336-210ed469538mr78664915ad.27.1730283512355;
        Wed, 30 Oct 2024 03:18:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730283512; cv=none;
        d=google.com; s=arc-20240605;
        b=EAgcHjXDMKsTyooB2IRJ0VVfOa5nnZVX+7Pzz1clS+zzq9f/s+yd9XZeR0BBXLiwI0
         LVLnqGcEBirNgK8lf9bmsqE22zn2sB/x8v8Q5kGuhbKHUlFVtDhRIv2BE03CX7OPD8n8
         rV50F5cNU2UjY6EPRuIFPilEHbbaUfOx38KsaKax00vVuyABagZQwmZb9Y+nqjjqevIb
         cu29k6kD9zBTBpaxCD7Omca9yhOPA6AiTitrziHJPsTsM9fLW556vmLBCbGmcdu+84x6
         lk0RWHJIq53qDj3g9gsplnI3xCza+VEZPY6zr38v/gsCAW6b83JgL4O9LFz/Bb+CRGt0
         rIDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wKc28QdF+vvrcEl4ukrPCmM1V6U1/x4aUsBDxFh3gv0=;
        fh=/05bH+4A4js4VkijbV/9z2eM33hSQCIadAsJJOz4feM=;
        b=BCNxH8bMIJijVpECUB0teLx2fUkhqVePBSBfTJn1UBnuFWOOmxTQrIyGsuP65BaNYw
         cQgTjf1mSTdWEM3Sm8wRKtugtIEGOk7ej8mKydzw2fKZtJvP0TVMxptGy7pLUkMTfGv2
         ZjxJvWnLftVCtFX3nkog+/OLbabqQ+FbdF5yuQdYNyvAwNULzh+2F4FxiiqpGvISf0Hi
         pumr7+f+DpG41P6DBTXiNos6+jAz27ted7fNYxDcpePdSi4w9kn/atw3Gq4aNTCWu2E6
         DDngqm5ksN/MkvqXEX0wgabAOeROUFL8w/G3T1G/vEBDpbOOkq8nH8jLlsHKarw5uGVv
         NFLg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QmLBYLiQ;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-210bbfde225si3553975ad.11.2024.10.30.03.18.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Oct 2024 03:18:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 982C45C6049
	for <kasan-dev@googlegroups.com>; Wed, 30 Oct 2024 10:17:46 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0ABCBC4AF0C
	for <kasan-dev@googlegroups.com>; Wed, 30 Oct 2024 10:18:30 +0000 (UTC)
Received: by mail-ej1-f41.google.com with SMTP id a640c23a62f3a-a99f629a7aaso116082966b.1
        for <kasan-dev@googlegroups.com>; Wed, 30 Oct 2024 03:18:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWBRPrUoXb4XvEr4/CzGXfSMOVEa4nvtgtigopXLl8HwTN1mocuu0AwZHB+bNgdPlKWPpbS2969pN0=@googlegroups.com
X-Received: by 2002:a17:906:730b:b0:a9a:c57f:964b with SMTP id
 a640c23a62f3a-a9e40bc5d44mr134325766b.8.1730283509388; Wed, 30 Oct 2024
 03:18:29 -0700 (PDT)
MIME-Version: 1.0
References: <20241030063905.2434824-1-maobibo@loongson.cn>
In-Reply-To: <20241030063905.2434824-1-maobibo@loongson.cn>
From: "'Huacai Chen' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 30 Oct 2024 18:18:16 +0800
X-Gmail-Original-Message-ID: <CAAhV-H4KXMyj0hpmhEWxiyapVNVcWk3K7HcshNyx5_wp2NBUWA@mail.gmail.com>
Message-ID: <CAAhV-H4KXMyj0hpmhEWxiyapVNVcWk3K7HcshNyx5_wp2NBUWA@mail.gmail.com>
Subject: Re: [PATCH v2] mm: define general function pXd_init()
To: Bibo Mao <maobibo@loongson.cn>
Cc: Thomas Bogendoerfer <tsbogend@alpha.franken.de>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, loongarch@lists.linux.dev, 
	linux-kernel@vger.kernel.org, linux-mips@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, WANG Xuerui <kernel@xen0n.name>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=QmLBYLiQ;       spf=pass
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

Reviewed-by: Huacai Chen <chenhuacai@loongson.cn>

On Wed, Oct 30, 2024 at 2:39=E2=80=AFPM Bibo Mao <maobibo@loongson.cn> wrot=
e:
>
> Function pud_init(), pmd_init() and kernel_pte_init() are duplicated
> defined in file kasan.c and sparse-vmemmap.c as weak functions. Move
> them to generic header file pgtable.h, architecture can redefine them.
>
> Signed-off-by: Bibo Mao <maobibo@loongson.cn>
> ---
> v1 ... v2:
>   1. Add general function definition about kernel_pte_init().
> ---
>  arch/loongarch/include/asm/pgtable.h |  3 +++
>  arch/mips/include/asm/pgtable-64.h   |  2 ++
>  include/linux/mm.h                   |  3 ---
>  include/linux/pgtable.h              | 21 +++++++++++++++++++++
>  mm/kasan/init.c                      | 12 ------------
>  mm/sparse-vmemmap.c                  | 12 ------------
>  6 files changed, 26 insertions(+), 27 deletions(-)
>
> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/includ=
e/asm/pgtable.h
> index 20714b73f14c..df5889d995f9 100644
> --- a/arch/loongarch/include/asm/pgtable.h
> +++ b/arch/loongarch/include/asm/pgtable.h
> @@ -267,8 +267,11 @@ extern void set_pmd_at(struct mm_struct *mm, unsigne=
d long addr, pmd_t *pmdp, pm
>   * Initialize a new pgd / pud / pmd table with invalid pointers.
>   */
>  extern void pgd_init(void *addr);
> +#define pud_init pud_init
>  extern void pud_init(void *addr);
> +#define pmd_init pmd_init
>  extern void pmd_init(void *addr);
> +#define kernel_pte_init kernel_pte_init
>  extern void kernel_pte_init(void *addr);
>
>  /*
> diff --git a/arch/mips/include/asm/pgtable-64.h b/arch/mips/include/asm/p=
gtable-64.h
> index 401c1d9e4409..45c8572a0462 100644
> --- a/arch/mips/include/asm/pgtable-64.h
> +++ b/arch/mips/include/asm/pgtable-64.h
> @@ -316,7 +316,9 @@ static inline pmd_t *pud_pgtable(pud_t pud)
>   * Initialize a new pgd / pud / pmd table with invalid pointers.
>   */
>  extern void pgd_init(void *addr);
> +#define pud_init pud_init
>  extern void pud_init(void *addr);
> +#define pmd_init pmd_init
>  extern void pmd_init(void *addr);
>
>  /*
> diff --git a/include/linux/mm.h b/include/linux/mm.h
> index 61fff5d34ed5..651bdc1bef48 100644
> --- a/include/linux/mm.h
> +++ b/include/linux/mm.h
> @@ -3818,9 +3818,6 @@ void *sparse_buffer_alloc(unsigned long size);
>  struct page * __populate_section_memmap(unsigned long pfn,
>                 unsigned long nr_pages, int nid, struct vmem_altmap *altm=
ap,
>                 struct dev_pagemap *pgmap);
> -void pud_init(void *addr);
> -void pmd_init(void *addr);
> -void kernel_pte_init(void *addr);
>  pgd_t *vmemmap_pgd_populate(unsigned long addr, int node);
>  p4d_t *vmemmap_p4d_populate(pgd_t *pgd, unsigned long addr, int node);
>  pud_t *vmemmap_pud_populate(p4d_t *p4d, unsigned long addr, int node);
> diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
> index e8b2ac6bd2ae..adee214c21f8 100644
> --- a/include/linux/pgtable.h
> +++ b/include/linux/pgtable.h
> @@ -90,6 +90,27 @@ static inline unsigned long pud_index(unsigned long ad=
dress)
>  #define pgd_index(a)  (((a) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
>  #endif
>
> +#ifndef kernel_pte_init
> +static inline void kernel_pte_init(void *addr)
> +{
> +}
> +#define kernel_pte_init kernel_pte_init
> +#endif
> +
> +#ifndef pmd_init
> +static inline void pmd_init(void *addr)
> +{
> +}
> +#define pmd_init pmd_init
> +#endif
> +
> +#ifndef pud_init
> +static inline void pud_init(void *addr)
> +{
> +}
> +#define pud_init pud_init
> +#endif
> +
>  #ifndef pte_offset_kernel
>  static inline pte_t *pte_offset_kernel(pmd_t *pmd, unsigned long address=
)
>  {
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index ac607c306292..ced6b29fcf76 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -106,10 +106,6 @@ static void __ref zero_pte_populate(pmd_t *pmd, unsi=
gned long addr,
>         }
>  }
>
> -void __weak __meminit kernel_pte_init(void *addr)
> -{
> -}
> -
>  static int __ref zero_pmd_populate(pud_t *pud, unsigned long addr,
>                                 unsigned long end)
>  {
> @@ -145,10 +141,6 @@ static int __ref zero_pmd_populate(pud_t *pud, unsig=
ned long addr,
>         return 0;
>  }
>
> -void __weak __meminit pmd_init(void *addr)
> -{
> -}
> -
>  static int __ref zero_pud_populate(p4d_t *p4d, unsigned long addr,
>                                 unsigned long end)
>  {
> @@ -187,10 +179,6 @@ static int __ref zero_pud_populate(p4d_t *p4d, unsig=
ned long addr,
>         return 0;
>  }
>
> -void __weak __meminit pud_init(void *addr)
> -{
> -}
> -
>  static int __ref zero_p4d_populate(pgd_t *pgd, unsigned long addr,
>                                 unsigned long end)
>  {
> diff --git a/mm/sparse-vmemmap.c b/mm/sparse-vmemmap.c
> index c0388b2e959d..cec67c5f37d8 100644
> --- a/mm/sparse-vmemmap.c
> +++ b/mm/sparse-vmemmap.c
> @@ -184,10 +184,6 @@ static void * __meminit vmemmap_alloc_block_zero(uns=
igned long size, int node)
>         return p;
>  }
>
> -void __weak __meminit kernel_pte_init(void *addr)
> -{
> -}
> -
>  pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, unsigned long addr, i=
nt node)
>  {
>         pmd_t *pmd =3D pmd_offset(pud, addr);
> @@ -201,10 +197,6 @@ pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, u=
nsigned long addr, int node)
>         return pmd;
>  }
>
> -void __weak __meminit pmd_init(void *addr)
> -{
> -}
> -
>  pud_t * __meminit vmemmap_pud_populate(p4d_t *p4d, unsigned long addr, i=
nt node)
>  {
>         pud_t *pud =3D pud_offset(p4d, addr);
> @@ -218,10 +210,6 @@ pud_t * __meminit vmemmap_pud_populate(p4d_t *p4d, u=
nsigned long addr, int node)
>         return pud;
>  }
>
> -void __weak __meminit pud_init(void *addr)
> -{
> -}
> -
>  p4d_t * __meminit vmemmap_p4d_populate(pgd_t *pgd, unsigned long addr, i=
nt node)
>  {
>         p4d_t *p4d =3D p4d_offset(pgd, addr);
>
> base-commit: 81983758430957d9a5cb3333fe324fd70cf63e7e
> --
> 2.39.3
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AAhV-H4KXMyj0hpmhEWxiyapVNVcWk3K7HcshNyx5_wp2NBUWA%40mail.gmail.com.
