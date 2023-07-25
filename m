Return-Path: <kasan-dev+bncBAABBIHY7WSQMGQE7FTZBXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id D69E8760C11
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jul 2023 09:39:14 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-1bb893e61d5sf12162795ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jul 2023 00:39:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690270753; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ht6cmUdXxzsbHDDjVLvg5AK5D6HZTG6efgPuRJUrxt4fKgWNixjQQi7NyN0hHQLXyI
         kcnPE1n3IX3Imt2aIoeAwqIfpVbdjWckqMGfBKjjG0dKJ8JOuCgkyGoM5WaLRudCdsig
         fVMtgTB3h0A+dlld/im44V7eO576cPTZUn5vZaaEmgcpdAG8MsbKeh3Vv1MB9402nH3X
         QSCnEjLPsVnOScDC7xqCrv/8Zgi5rf8NQ3jzMrP/gH0+XzpvZsumaUDhHEJM6qmjJTAV
         sd3eg7e22rFHYeeTBH41ooVytVIyzbr7XCqi4jhKHlceHav8qEmNSuMHu6k+lnlXJ1g8
         H5mQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=ue2mZ6nKxBhCxNWYVgifkzf6Y0fYK6xOVgQuyxN2iN4=;
        fh=sy4SP3vkEn2BvwOVbcJ42LyDgXjWTkePGWUGK7C0j7Y=;
        b=a/UxHJFeBKx3KZDvN1eeoH/wFLNdtrHhrRSfw5L0vr4nXdhSk0SXjFF1+79NQ6x4/v
         RFrdLSQBKqcCwOGyowOXyBT+5NBD/BZT/ZdSmd7bSu6FSZOcgnTS8wYbnm+vY7/AtkXG
         ViuEzdF+UBlXuFEx0W6gyQRGhY513HJZP3R8aGTZuDsQ5DEXHrfvIisrGnICSENd7OSy
         ve9RRvw62G/9IH3QebSEy9AAkkrWoZU1xQ4iS7dFpQpodxxAMXfX98eoieMt423bQLSW
         h9wM4aWUNS/I+4sS9lZAbxRNYMZov6GisHN/m9JqtuwHw9R6kuNnJV8mPJMJK50dCbyE
         zNZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Zx0mGrx5;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690270753; x=1690875553;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ue2mZ6nKxBhCxNWYVgifkzf6Y0fYK6xOVgQuyxN2iN4=;
        b=E6qaU/+m0H6vI2PwI3TYIL+RPTBdlMtldyxo9/aHaV21L7MVNraRWGXzv0bkQswA2O
         0Z2Xams8ncRebJfB/ZoONRWcRn7HJSht48sptk4y1oeBVIzBtu4dbqwOpg6gCKkbOxNd
         C18apUpXbeQ/bCg2mgBf/dtJxIoXOJjtiY3h7Yj1sSbk02aHjx2aoflUhD8fNJWQCklN
         RHsO9YxQsWc9v9/Y5w1C4CjDWQzad1NYEzCT/Oz0H0hinVDdBcgdjqwGmbn54X4R/Ot5
         zFiGXmToxXRpWBwHwSXtLNCg61NeR+4CqPpsD9rSKNjqXKj2nG0UHkdB26hnaMcnnblf
         zL+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690270753; x=1690875553;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ue2mZ6nKxBhCxNWYVgifkzf6Y0fYK6xOVgQuyxN2iN4=;
        b=A9AcSxENGxQyZqnGS/8NzItq9QfcpUMYGNfnld1E3VBm/yomJtfpj//XnaDinPPDon
         sIONDvu8JnNKgiKNTAEpi5J4MNOwg0wE1ljfFLSlIlU/1PtTXqyNem1aK+Ghk31tA/m9
         aQIRoA7oTB906U6xLNjTcFjVqIbf8nYXsCmjEFJAH+tHOmaWUv3nuRv3bjEU59D0cWHa
         nBjyaWYGUX9epfRRGq5e3T6mDiGjKn+X3plD6hdsU2QxQ3pTO6AzDa1EozOMXJO3MJRN
         jbThez5TlTAqWmfwE33bghLwr5suJ+XOyHOXh07aUrxWMTERtJutWXhzfF91eqE2sPc1
         xvHw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLZ6hteCURGGzrcnoWEGB/UAKB09UI/+0/ij5GE6+dp+Ft0smnbu
	j04FRvaNMbefd4+wYtjQTUo=
X-Google-Smtp-Source: APBJJlFc8ldZwHK1Y8e/1yqOPCOrTCSZpTf01sR8IbgTFXAl09J6yLvS4S0oh8M84gwVCJYh/HfSug==
X-Received: by 2002:a17:902:e5d1:b0:1b8:8b72:fa28 with SMTP id u17-20020a170902e5d100b001b88b72fa28mr11638189plf.58.1690270752964;
        Tue, 25 Jul 2023 00:39:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7fc1:b0:1b7:e4d4:b92a with SMTP id
 t1-20020a1709027fc100b001b7e4d4b92als2345689plb.0.-pod-prod-09-us; Tue, 25
 Jul 2023 00:39:12 -0700 (PDT)
X-Received: by 2002:a17:902:bcca:b0:1b6:af1a:7dd3 with SMTP id o10-20020a170902bcca00b001b6af1a7dd3mr8925359pls.23.1690270752190;
        Tue, 25 Jul 2023 00:39:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690270752; cv=none;
        d=google.com; s=arc-20160816;
        b=Oga2LGkXZCU2ZOgq3URQPXB6sVg3GO5qnDtAjWNLkciwhvqAl+eQIf1TItJwVraNS+
         uUYoSJBp96RLZ148hNXtsSXPAZJd5aQ0pQsskWpH0PXbwDt0Yh1glPLdiZtC4Kb4ZrtF
         fksP+YwYz2UkKzvDRIUMq0KCfKo33LHaq+K/eXrTYQhQjdk32iT6m/tw2qsaZP9IzLMb
         YH6M4ocF68Pt3elVcB8E5XUuDzvrDwpbIqgUGMt0X79+RLimLgxA7Hw2sjokzDjVaAma
         zJc17LkTo0Sit9tDMpQqAkkXKTfqk5KrI8Do2w0GOYmhIFe2Cq+HRkSWrglnWN8cTJfu
         rUmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=sEHcsGYIXyfMK1lecIsR9+QVH9TullIDbpkeYECcxtk=;
        fh=sy4SP3vkEn2BvwOVbcJ42LyDgXjWTkePGWUGK7C0j7Y=;
        b=EuOM+a9cM9Wt5xW18GDZO9CqSc6E1Bxd0iwhZ000ahSJG2X9WChvfLzobE2uyEqPUg
         rNScdGWbU06R3s4OdZBBSjBPpUU+CIUIEjwej2Oj5mrYQE2LcO93EJXlrU8AO59TwcwZ
         X736WOFOAuaCCyVygTiHdoqH638ty+HlK0FCu0j4gRDpKXdCat4qcapoHZje5qO46mGh
         voAT4wh3DXV0DNcqvqC0okqmj2ybhdte7j5595c5g9fZxYVEt02iMraEKcsf5b8i631T
         jslh/26J7H1cbSo9p4YlxqShSPU7XjoYTBKIeVdPFyz4ZWoec0ttrPhEAXQbFc8JMvgn
         hC1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Zx0mGrx5;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id x4-20020a1709028ec400b001bb840d2832si270786plo.9.2023.07.25.00.39.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Jul 2023 00:39:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 7643F612BF
	for <kasan-dev@googlegroups.com>; Tue, 25 Jul 2023 07:39:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E03F7C433CD
	for <kasan-dev@googlegroups.com>; Tue, 25 Jul 2023 07:39:10 +0000 (UTC)
Received: by mail-ed1-f44.google.com with SMTP id 4fb4d7f45d1cf-52229d3b8c8so2994531a12.2
        for <kasan-dev@googlegroups.com>; Tue, 25 Jul 2023 00:39:10 -0700 (PDT)
X-Received: by 2002:aa7:c394:0:b0:521:a740:29b7 with SMTP id
 k20-20020aa7c394000000b00521a74029b7mr10427977edq.36.1690270748946; Tue, 25
 Jul 2023 00:39:08 -0700 (PDT)
MIME-Version: 1.0
References: <20230725061451.1231480-1-lienze@kylinos.cn> <20230725061451.1231480-2-lienze@kylinos.cn>
In-Reply-To: <20230725061451.1231480-2-lienze@kylinos.cn>
From: Huacai Chen <chenhuacai@kernel.org>
Date: Tue, 25 Jul 2023 15:38:56 +0800
X-Gmail-Original-Message-ID: <CAAhV-H7ymPQkHUzqs-D03cT=JgkJd_=ZXjCVB1v_hhfop4pqYA@mail.gmail.com>
Message-ID: <CAAhV-H7ymPQkHUzqs-D03cT=JgkJd_=ZXjCVB1v_hhfop4pqYA@mail.gmail.com>
Subject: Re: [PATCH 1/4 v2] LoongArch: mm: Add page table mapped mode support
To: Enze Li <lienze@kylinos.cn>
Cc: kernel@xen0n.name, loongarch@lists.linux.dev, glider@google.com, 
	elver@google.com, akpm@linux-foundation.org, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, zhangqing@loongson.cn, yangtiezhu@loongson.cn, 
	dvyukov@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Zx0mGrx5;       spf=pass
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

Hi, Enze,

On Tue, Jul 25, 2023 at 2:15=E2=80=AFPM Enze Li <lienze@kylinos.cn> wrote:
>
> According to LoongArch documentation online, there are two types of addre=
ss
> translation modes: direct mapped address translation mode (direct mapped =
mode)
> and page table mapped address translation mode (page table mapped mode).
>
> Currently, the upstream kernel only supports direct mapped mode.
> This patch adds a function that determines whether page table mapped
> mode should be used, and also adds the corresponding handler functions
> for both modes.
>
> For more details on the two modes, see [1].
>
> [1] https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.=
html#virtual-address-space-and-address-translation-mode
>
> Signed-off-by: Enze Li <lienze@kylinos.cn>
> ---
>  arch/loongarch/include/asm/page.h    | 19 ++++++++++++++++++-
>  arch/loongarch/include/asm/pgtable.h |  2 ++
>  arch/loongarch/mm/pgtable.c          |  6 ++++++
>  3 files changed, 26 insertions(+), 1 deletion(-)
>
> diff --git a/arch/loongarch/include/asm/page.h b/arch/loongarch/include/a=
sm/page.h
> index 26e8dccb6619..e43a2385b2cd 100644
> --- a/arch/loongarch/include/asm/page.h
> +++ b/arch/loongarch/include/asm/page.h
> @@ -32,6 +32,7 @@
>
>  #include <linux/kernel.h>
>  #include <linux/pfn.h>
> +#include <asm/cpu-features.h>
>
>  /*
>   * It's normally defined only for FLATMEM config but it's
> @@ -84,7 +85,23 @@ typedef struct { unsigned long pgprot; } pgprot_t;
>  #define sym_to_pfn(x)          __phys_to_pfn(__pa_symbol(x))
>
>  #define virt_to_pfn(kaddr)     PFN_DOWN(PHYSADDR(kaddr))
> -#define virt_to_page(kaddr)    pfn_to_page(virt_to_pfn(kaddr))
> +
> +static inline bool is_tlb_addr(unsigned long kaddr)
> +{
> +       if (unlikely((kaddr & GENMASK(BITS_PER_LONG - 1, cpu_vabits)) =3D=
=3D
> +                    GENMASK(BITS_PER_LONG - 1, cpu_vabits)))
> +               return true;
> +       return false;
I think this helper can simply "return (kaddr >=3D vm_map_base)"? If so,
we can even remove this helper and use the simple condition in
virt_to_page().

> +}
> +
> +#define dwm_virt_to_page(kaddr)        pfn_to_page(virt_to_pfn(kaddr))
This should be "dmw", not "dwm", and since tlb_virt_to_page is in .c
file, this one should also be there.

Huacai
> +
> +#define virt_to_page(kaddr)                                            \
> +({                                                                     \
> +       is_tlb_addr((unsigned long)kaddr) ?                             \
> +       tlb_virt_to_page((unsigned long)kaddr) :                        \
> +       dwm_virt_to_page((unsigned long)kaddr);                         \
> +})
>
>  extern int __virt_addr_valid(volatile void *kaddr);
>  #define virt_addr_valid(kaddr) __virt_addr_valid((volatile void *)(kaddr=
))
> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/includ=
e/asm/pgtable.h
> index 38afeb7dd58b..98a0c98de9d1 100644
> --- a/arch/loongarch/include/asm/pgtable.h
> +++ b/arch/loongarch/include/asm/pgtable.h
> @@ -353,6 +353,8 @@ static inline void pte_clear(struct mm_struct *mm, un=
signed long addr, pte_t *pt
>  #define PMD_T_LOG2     (__builtin_ffs(sizeof(pmd_t)) - 1)
>  #define PTE_T_LOG2     (__builtin_ffs(sizeof(pte_t)) - 1)
>
> +inline struct page *tlb_virt_to_page(unsigned long kaddr);
> +
>  extern pgd_t swapper_pg_dir[];
>  extern pgd_t invalid_pg_dir[];
>
> diff --git a/arch/loongarch/mm/pgtable.c b/arch/loongarch/mm/pgtable.c
> index 36a6dc0148ae..20e7425d235d 100644
> --- a/arch/loongarch/mm/pgtable.c
> +++ b/arch/loongarch/mm/pgtable.c
> @@ -9,6 +9,12 @@
>  #include <asm/pgtable.h>
>  #include <asm/tlbflush.h>
>
> +inline struct page *tlb_virt_to_page(unsigned long kaddr)
> +{
> +       return pte_page(*virt_to_kpte(kaddr));
> +}
> +EXPORT_SYMBOL_GPL(tlb_virt_to_page);
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
kasan-dev/CAAhV-H7ymPQkHUzqs-D03cT%3DJgkJd_%3DZXjCVB1v_hhfop4pqYA%40mail.gm=
ail.com.
