Return-Path: <kasan-dev+bncBAABB34C4CSQMGQEUOPAEBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 549A57599BE
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jul 2023 17:29:53 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-262ef5650acsf1456309a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jul 2023 08:29:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689780592; cv=pass;
        d=google.com; s=arc-20160816;
        b=j8b/s0bkGqzgpl5a/B49ONYStoAgIfau9cZvdELYGUyNSQhDchWS5a4yxralQh2cYz
         tIyqMXU4QzuTkjBQt/KJmkylGVTrPg2XASzGYr0jPysu2PpyJrDt3QN6TWUQYst5YCv4
         IlPTkD0dUW8xbRVUyW1fTySPQXieFVTYzwO9xm+OUcEuuOrO8X7tV3TmLAyG87uo4VdX
         Lc4o/eRArl3wk7icGBBym1x7/3Iezm70mWNK2TpRmNn6q0no0h9OuL0fpC/ezUslGTnY
         HJTm4lJ0G0XBzJGNZpMGbpkDcfPpu3h/Kiygd7QhR36Jn1Pp9ta7HMjL+uTEHdXEY2US
         QtHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=egWjvCSwvt0v0CqpMQ4Gn605Y29Lri/n4CE0uNSRi6c=;
        fh=sy4SP3vkEn2BvwOVbcJ42LyDgXjWTkePGWUGK7C0j7Y=;
        b=A7/+W6ljxopyeiWvdQBy+S8Ch4njX3N2uAsiF3E9ogq5SMYf5ochjQ0oQBSV5JIX3l
         SdW3TUvh+vHaIoVqDBpm6les0nUzOmwXGCtWYahEAWfucd60hoRIzG2zEHHyP0CLhGx7
         O6ibO1FhxrXYxl8fSAR0D4YvnpkfUZeXo8nqtY1pmk9ChDGnZ1zEuuQOkJg8C43LsdKt
         +n2UQZ6wzdnBTYJ3gqp1vKbY6ltIhEFoWNibFq/bHP3rwiIJ2AnI1ImMmPIi+/vc8EWs
         ecsl+nXu++bxEj7vIdJxnkLibyviV27JvU7WEwdKoYbXRMAm01HmEfJhKJJAjVVRe3Dn
         MTNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=aE57eKlq;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689780592; x=1692372592;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=egWjvCSwvt0v0CqpMQ4Gn605Y29Lri/n4CE0uNSRi6c=;
        b=DKY/qb3Szmvj+m24PuTNuw7iDCFc2Kbpb7rOWa4IKJwJevOL3Vu3Fypo6CH0iKVcf1
         6bvc9YSsbI/BrwRVhX8g7+s8gPiA7Qy2x7Q+ydD0RYQJJVtqus93kSUuMhZfKGtqf7zk
         ZmnCtR0PUvqRjg0iotsHp5Uav8lKWDzIGxp2P8sfNfNepxt0kK3aQtpUJp90KKnObRGr
         U8of9qAWKI61n20H9J/bFERyH7dpCToGLNxK6GS/yq1XjkiwtgoeYdZnTBW7olvKsAwf
         UfmdXvv1c9ujKn7aUm1ic7XWpNU+jMgnHT4dF4lkvS+h3ZuNVIt4XhuSwBrOpPZCee8k
         ZLbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689780592; x=1692372592;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=egWjvCSwvt0v0CqpMQ4Gn605Y29Lri/n4CE0uNSRi6c=;
        b=O827ppidn3LBkjqLn3+eMx4ittHSS46HeM642ZHHnfMkNbr8fKZXE1vODgIkF2VHpe
         YM96VRdKamExOYlAaVPj0ZZXSsSC3I099foZ32gbyDJy2xXqkkzkQDdzNzxE8ivMS0zt
         gTNXWhb2sCAz5HF+ufSWHcH9YtwE+3IZBgtP7wSU3Ww32bofuxC+WFZtGu44t7TIg9rc
         09f7DfE0iyLQ9k1JJOcMUX6LA+7qc4F8LHAgiJFkkj+QGxgMXSRzY/WWJuLNVS8YUebY
         cV8k2YZGh7jE8jH5mDAExukvw10ObpmzPY2Av5mPvl7o+y+VJ0Dx/yaroZpZBZ+jC2m9
         CPRA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLYrWoEIXpelCoUg4JqWtE9istqoyCmPtXnR1l/fc2UYMAYZypKS
	hWe6NR2fxc4z3nYvQO9474k=
X-Google-Smtp-Source: APBJJlH9T8aWLkei64WNy1WFeSOXMfGcQ4eXkmfsXleHAjcLRpdno8WEbpwNOaDvTG7qzoYZ3O1nPQ==
X-Received: by 2002:a17:90a:6d89:b0:25b:88bc:bb6b with SMTP id a9-20020a17090a6d8900b0025b88bcbb6bmr2354078pjk.2.1689780591334;
        Wed, 19 Jul 2023 08:29:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1885:b0:262:df46:d00f with SMTP id
 mn5-20020a17090b188500b00262df46d00fls823144pjb.1.-pod-prod-08-us; Wed, 19
 Jul 2023 08:29:50 -0700 (PDT)
X-Received: by 2002:a17:90b:198:b0:263:514:5ee3 with SMTP id t24-20020a17090b019800b0026305145ee3mr17615363pjs.32.1689780590732;
        Wed, 19 Jul 2023 08:29:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689780590; cv=none;
        d=google.com; s=arc-20160816;
        b=bCrXZhd26PYN+x1aQfo3Ix/nQG40rujPf5y7mtxFeJpuhmn//2KcT7mHmrAPXyUjse
         AvnamcbOP8hPeaXkMYnz4UQWzMJtukShllAECdU085cImZYv0G09pUBdMsZftVdh1Vm5
         t5AxZCf7URP2PNi8HjhbQMxmU557meKpH5gTkqhG7Fe4bJmuOCqRz4/q7RXDWKVLMGq3
         KjuIFdRn2NWhKuUYhwuNxeIh3LtTtwPal1rQrOewGtdCdXYJCjpl3XLFGrqvclPuBAQT
         s5XaHrj3AI0mx2Vx7caD5a1cPJqhI+hqh6JiNMeyG/rBNGgk2YrWSzyVkZpp2Q4zS0Gh
         Ye5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=IdN7vdVOZg7Exr6pjGBZTBejDO8Y0wA5aiknBnRxQJk=;
        fh=sy4SP3vkEn2BvwOVbcJ42LyDgXjWTkePGWUGK7C0j7Y=;
        b=iUAR8jnmMbqQXPXk6O+4kTV4gazAXyV1UMLVITKJXLPFczjsKymm8cjnSOZBoBwjnL
         rJg84Aq7FuM/D7Rvo4yM9U5yb2UzyUWhljBc7bo3OkxlEINI2R90v3xmT7ZVOu/sjKKM
         EtLkGS8EFWgco71xG/nwvH7+Oa7rPkNG8dZR3i+AiG+hgP+bEBGTdkeQAYxQnZY3V4Y/
         rJ6yNpcSSGfyoLgPDOAYPGSlc/GzWtZrmhV4ydp14wOI0rFCCpd9KxueN8oEWKRIhN+2
         8dNgdbXEQIrz8wVWHxyKis4minW1SnbcV6elMXiRKMOR9pydoeiAT31CtG7do8sCG0PX
         6SCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=aE57eKlq;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id pt7-20020a17090b3d0700b0025e843646d0si97913pjb.3.2023.07.19.08.29.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jul 2023 08:29:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 19F05616DD
	for <kasan-dev@googlegroups.com>; Wed, 19 Jul 2023 15:29:50 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 55E72C433C8
	for <kasan-dev@googlegroups.com>; Wed, 19 Jul 2023 15:29:49 +0000 (UTC)
Received: by mail-ed1-f49.google.com with SMTP id 4fb4d7f45d1cf-51e48e1f6d1so9609593a12.1
        for <kasan-dev@googlegroups.com>; Wed, 19 Jul 2023 08:29:49 -0700 (PDT)
X-Received: by 2002:a05:6402:608:b0:51e:1a51:d414 with SMTP id
 n8-20020a056402060800b0051e1a51d414mr2367053edv.32.1689780587597; Wed, 19 Jul
 2023 08:29:47 -0700 (PDT)
MIME-Version: 1.0
References: <20230719082732.2189747-1-lienze@kylinos.cn> <20230719082732.2189747-2-lienze@kylinos.cn>
In-Reply-To: <20230719082732.2189747-2-lienze@kylinos.cn>
From: Huacai Chen <chenhuacai@kernel.org>
Date: Wed, 19 Jul 2023 23:29:37 +0800
X-Gmail-Original-Message-ID: <CAAhV-H5pWmd2owMgH9hiqxoWpeAOKGv_=j2V-urA+D87_uCMyg@mail.gmail.com>
Message-ID: <CAAhV-H5pWmd2owMgH9hiqxoWpeAOKGv_=j2V-urA+D87_uCMyg@mail.gmail.com>
Subject: Re: [PATCH 1/4] LoongArch: mm: Add page table mapped mode support
To: Enze Li <lienze@kylinos.cn>
Cc: kernel@xen0n.name, loongarch@lists.linux.dev, glider@google.com, 
	elver@google.com, akpm@linux-foundation.org, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, zhangqing@loongson.cn, yangtiezhu@loongson.cn, 
	dvyukov@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=aE57eKlq;       spf=pass
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
> According to LoongArch documentation online, there are two types of addre=
ss
> translation modes: direct mapped address translation mode (direct mapped =
mode)
> and page table mapped address translation mode (page table mapped mode).
>
> Currently, the upstream code only supports DMM (Direct Mapped Mode).
> This patch adds a function that determines whether PTMM (Page Table
> Mapped Mode) should be used, and also adds the corresponding handler
> funcitons for both modes.
>
> For more details on the two modes, see [1].
>
> [1] https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.=
html#virtual-address-space-and-address-translation-mode
>
> Signed-off-by: Enze Li <lienze@kylinos.cn>
> ---
>  arch/loongarch/include/asm/page.h    | 10 ++++++++++
>  arch/loongarch/include/asm/pgtable.h |  6 ++++++
>  arch/loongarch/mm/pgtable.c          | 25 +++++++++++++++++++++++++
>  3 files changed, 41 insertions(+)
>
> diff --git a/arch/loongarch/include/asm/page.h b/arch/loongarch/include/a=
sm/page.h
> index 26e8dccb6619..05919be15801 100644
> --- a/arch/loongarch/include/asm/page.h
> +++ b/arch/loongarch/include/asm/page.h
> @@ -84,7 +84,17 @@ typedef struct { unsigned long pgprot; } pgprot_t;
>  #define sym_to_pfn(x)          __phys_to_pfn(__pa_symbol(x))
>
>  #define virt_to_pfn(kaddr)     PFN_DOWN(PHYSADDR(kaddr))
> +
> +#ifdef CONFIG_64BIT
> +#define virt_to_page(kaddr)                                            \
> +({                                                                     \
> +       is_PTMM_addr((unsigned long)kaddr) ?                            \
> +       PTMM_virt_to_page((unsigned long)kaddr) :                       \
> +       DMM_virt_to_page((unsigned long)kaddr);                         \
> +})
1, Rename these helpers to
is_dmw_addr()/dmw_virt_to_page()/tlb_virt_to_page() will be better.
2, These helpers are so simple so can be defined as inline function or
macros in page.h.
3, CONFIG_64BIT can be removed here.

Huacai

> +#else
>  #define virt_to_page(kaddr)    pfn_to_page(virt_to_pfn(kaddr))
> +#endif
>
>  extern int __virt_addr_valid(volatile void *kaddr);
>  #define virt_addr_valid(kaddr) __virt_addr_valid((volatile void *)(kaddr=
))
> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/includ=
e/asm/pgtable.h
> index ed6a37bb55b5..0fc074b8bd48 100644
> --- a/arch/loongarch/include/asm/pgtable.h
> +++ b/arch/loongarch/include/asm/pgtable.h
> @@ -360,6 +360,12 @@ static inline void pte_clear(struct mm_struct *mm, u=
nsigned long addr, pte_t *pt
>  #define PMD_T_LOG2     (__builtin_ffs(sizeof(pmd_t)) - 1)
>  #define PTE_T_LOG2     (__builtin_ffs(sizeof(pte_t)) - 1)
>
> +#ifdef CONFIG_64BIT
> +struct page *DMM_virt_to_page(unsigned long kaddr);
> +struct page *PTMM_virt_to_page(unsigned long kaddr);
> +bool is_PTMM_addr(unsigned long kaddr);
> +#endif
> +
>  extern pgd_t swapper_pg_dir[];
>  extern pgd_t invalid_pg_dir[];
>
> diff --git a/arch/loongarch/mm/pgtable.c b/arch/loongarch/mm/pgtable.c
> index 36a6dc0148ae..4c6448f996b6 100644
> --- a/arch/loongarch/mm/pgtable.c
> +++ b/arch/loongarch/mm/pgtable.c
> @@ -9,6 +9,31 @@
>  #include <asm/pgtable.h>
>  #include <asm/tlbflush.h>
>
> +#ifdef CONFIG_64BIT
> +/* DMM stands for Direct Mapped Mode. */
> +struct page *DMM_virt_to_page(unsigned long kaddr)
> +{
> +       return pfn_to_page(virt_to_pfn(kaddr));
> +}
> +EXPORT_SYMBOL_GPL(DMM_virt_to_page);
> +
> +/* PTMM stands for Page Table Mapped Mode. */
> +struct page *PTMM_virt_to_page(unsigned long kaddr)
> +{
> +       return pte_page(*virt_to_kpte(kaddr));
> +}
> +EXPORT_SYMBOL_GPL(PTMM_virt_to_page);
> +
> +bool is_PTMM_addr(unsigned long kaddr)
> +{
> +       if (unlikely((kaddr & GENMASK(BITS_PER_LONG - 1, cpu_vabits)) =3D=
=3D
> +                    GENMASK(BITS_PER_LONG - 1, cpu_vabits)))
> +               return true;
> +       return false;
> +}
> +EXPORT_SYMBOL_GPL(is_PTMM_addr);
> +#endif
> +
>  pgd_t *pgd_alloc(struct mm_struct *mm)
>  {
>         pgd_t *ret, *init;
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
kasan-dev/CAAhV-H5pWmd2owMgH9hiqxoWpeAOKGv_%3Dj2V-urA%2BD87_uCMyg%40mail.gm=
ail.com.
