Return-Path: <kasan-dev+bncBAABBPPS46SQMGQELWPLAAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id EEA4475BCBC
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jul 2023 05:19:26 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id 46e09a7af769-6b9d320d986sf2978740a34.2
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jul 2023 20:19:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689909565; cv=pass;
        d=google.com; s=arc-20160816;
        b=DBhDOj3dOk4fHyTd5cW01cJ4ZR1GHH5aai/WGd3+kbMrTCVxxB6HxjptMo2LqSDfd5
         UkJjCankHOuhYb7gFDOG/zDxII4fWA0lRR2dkNzdjRytGSfVreZ8CscEQYlvk9xlHw1i
         GMwUmkEpe/+Qeo8ZDS2UJoPDc2NMKHLlr0/G/bEz4SwWP3a6GjgYLhlr4Vi8zSzUyUvG
         vP/SkPMPFgbJYr+0FOBfb91Y+OmuUQDqqTafVRtUCr9poEvh/cpLcDxqxcKRuDI0NncA
         SLo/zNnuSgSOAthxWjBRD7t0bIt5rzVueFlqWQJlQ3L8y58icbmB16yYkyUKkR79LVnm
         NHIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=NK9v7clQNy/KRbsEsqX62Awq5UVjx/bGkALtVfxYqt4=;
        fh=sy4SP3vkEn2BvwOVbcJ42LyDgXjWTkePGWUGK7C0j7Y=;
        b=sFumOJxxaMptogBS+3NU8fGumlL7DR+zpvnahKZ2npmB4ZYOiGsaFVLz8Md/ZkFRnY
         6JeGMYrMaludaxEtm2/QC+Se1sNQYHyB84TybS0CkDn8kfJH8Q57q1KFcehY5/0wb8GZ
         oMyBaYlLu5N73kEnbMWhEQRyOIyGZHRnyaGPhDG1WN4yVwHuSM+hyLGHBgzwaB/e4bgi
         WAyN+lei3NPq1PsJvaCi+TZqajg57cgw33qbPUyt7V2mAl+LO9w/NO5HEanxrFS6/I60
         u8+wRSaiKusp4ee6WGZQqwvdsWRd6xRdHb0GQ1CIG15YG1hEQ7VKjSXz+MNJQeApJRGl
         S8Pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rJMBGazv;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689909565; x=1690514365;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NK9v7clQNy/KRbsEsqX62Awq5UVjx/bGkALtVfxYqt4=;
        b=X6Jpti+7Uql5YIIIdg7xymHsNoWtYCtx4p3xFLMDHA1vtFs4fZkJ+J90p7uBk2t2am
         qDh6On74C/2hffvznRicdgOBhfzUtCS6Y0S3Llis7xGqanVfr51jJ+pM1bARP2VldMH6
         gh1pAD4vVnfeTvcMb9MNe1GjvWHf7ansJzHogOKV/TcrrdtxQcz2pN1Z2nkOwwrZS8hr
         rj4EiPyxFjsV47TDX4MAldypKotwvoag17CWY/wlN5AwZynj8BCHGtMe4LRGZ3ytl8Pm
         xEIGZgcVfWLZ8juEzGFfqQjyp752ambi+BoMJ7Tb1vpyX68qvhjQiIcnxVaN4tnM7OZ4
         IVWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689909565; x=1690514365;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=NK9v7clQNy/KRbsEsqX62Awq5UVjx/bGkALtVfxYqt4=;
        b=ZXJZUcpXOs5rX79PAKMF2Ho58ji2pyRa4amsezcnLdlZIh2OxD9R/fxdfALDdNtnUg
         peJ0ZctwHD/8fxaFIpHjWg08UgQSAd43cJ0QML/kOscxPH1Zxlj2L/71Rsd5+TnMz1Co
         XMx79MWgvf8SrG9ltig/vppEWKaZlMtOvX00Ig7ZlLniuutVm3BUDHyRSEXWHILoJUlR
         vGCOUqCZRf5EWoh8HZhfI4h1X4a8IWaA8gxiNDFOzygxYlfGUx+yChgwGzm4TMxBdPgB
         JU/m4lhG6UJ/EMaGkIwlDji/C9lxgcr0TIAUyWbQUEAtZDMr5YShckVYjzXzr1m2x8Mr
         jGdQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLYPDaehRHQOKLmbrBkifOSrSiNorDfvNeGMeyX/gmob2cyBwrto
	vN5+ew0lKPFK03g6XCWLmII=
X-Google-Smtp-Source: APBJJlGsUJONwathH+hzpK7TzONivXT1FzUYfBx8rmcMvQA/kHr0WRoZeI9iB+zaTfjqSxpo94OaZA==
X-Received: by 2002:a05:6870:b6a9:b0:177:ad57:cb36 with SMTP id cy41-20020a056870b6a900b00177ad57cb36mr823925oab.27.1689909565553;
        Thu, 20 Jul 2023 20:19:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:eca8:b0:1b3:98f0:abf1 with SMTP id
 eo40-20020a056870eca800b001b398f0abf1ls941968oab.2.-pod-prod-03-us; Thu, 20
 Jul 2023 20:19:25 -0700 (PDT)
X-Received: by 2002:a05:6871:54c:b0:1ad:3647:1fd0 with SMTP id t12-20020a056871054c00b001ad36471fd0mr787863oal.22.1689909564997;
        Thu, 20 Jul 2023 20:19:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689909564; cv=none;
        d=google.com; s=arc-20160816;
        b=vFMIBykieFpf/BtVPrRgLufi26azAfrmPryJ090GCHu4AZvZXZ3ZxMEWTus+idwUAx
         hetcM5/pvv13fWJG+JVf8sX+jNuxH8/6lVr4tJWiYXL9w5y9lCTE/IQop4hfi+4Ol+Pe
         nlD/xFyLgxMSRHFyDCQi1OYg7tbckSq3RQoGG/Sax/mKCYcLAVWmg74EnQsRdrWmAJPF
         TlJHlAT/+WAaZy1hSjS/PauSGZSE4MMrxUb6NXWwjs+jtIHKoA581QmlkCNtYuvt/Cwu
         uPBc0alfOYVZsSwHawmTnYO97XGfYwclXaw/2qnmX92CH/1tRQEhUgQWVxlpF14JPiEP
         b2Aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=hBkaesJwVREKeZL4yZtB8GU3JN9BxPcUY+gMay0RI6s=;
        fh=sy4SP3vkEn2BvwOVbcJ42LyDgXjWTkePGWUGK7C0j7Y=;
        b=N1y9MQlreACtkOmjLnE4vAh51LbFH7jYDC+8Gd8NRK6kcQc8hcWFyNCKiizA+VUS++
         VBc2ygsQx1mZaE1yCpS1XjXj5V0Sqv+2g98QvDZEnp8n+bBRYe1J7j6+cpgpnZxqhQox
         inxm23yUqfB+tl0tNiWGlSIp0N7pN60ypqaFmd2Ki2JUPBHTK/yK9jUVCoqg9KnIsL7T
         /lN35iV97TmG62R0977j26wMh6yrIqTGRnElQwJ0RL9MRrRqXO4x0fEdxGK4D3/CfDVs
         LYZD/OuAQvWBbNWs0C79xmkN3t5BviWJeA7usfL4rRBqiUm39GOviKm/DKcoZFUEBtjT
         xs+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rJMBGazv;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id j10-20020a056830270a00b006b9ea5121c2si270449otu.0.2023.07.20.20.19.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 20 Jul 2023 20:19:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id B3F2A61CE8
	for <kasan-dev@googlegroups.com>; Fri, 21 Jul 2023 03:19:24 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 27E47C433CC
	for <kasan-dev@googlegroups.com>; Fri, 21 Jul 2023 03:19:24 +0000 (UTC)
Received: by mail-ed1-f50.google.com with SMTP id 4fb4d7f45d1cf-51e28b299adso2040586a12.2
        for <kasan-dev@googlegroups.com>; Thu, 20 Jul 2023 20:19:24 -0700 (PDT)
X-Received: by 2002:aa7:dcc7:0:b0:515:1e50:5498 with SMTP id
 w7-20020aa7dcc7000000b005151e505498mr505713edu.15.1689909562263; Thu, 20 Jul
 2023 20:19:22 -0700 (PDT)
MIME-Version: 1.0
References: <20230719082732.2189747-1-lienze@kylinos.cn> <20230719082732.2189747-5-lienze@kylinos.cn>
 <CAAhV-H71sv+VeLfNzuiqitYcuB4rHnho=dRYQftwo1__3bLZSQ@mail.gmail.com> <87lefaez31.fsf@kylinos.cn>
In-Reply-To: <87lefaez31.fsf@kylinos.cn>
From: Huacai Chen <chenhuacai@kernel.org>
Date: Fri, 21 Jul 2023 11:19:10 +0800
X-Gmail-Original-Message-ID: <CAAhV-H6FoC1v9f9Vkq9rzk=0j88RczLgiYTiBUBNDwx3B=3tYA@mail.gmail.com>
Message-ID: <CAAhV-H6FoC1v9f9Vkq9rzk=0j88RczLgiYTiBUBNDwx3B=3tYA@mail.gmail.com>
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
 header.i=@kernel.org header.s=k20201202 header.b=rJMBGazv;       spf=pass
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

On Fri, Jul 21, 2023 at 11:14=E2=80=AFAM Enze Li <lienze@kylinos.cn> wrote:
>
> On Wed, Jul 19 2023 at 11:27:50 PM +0800, Huacai Chen wrote:
>
> > Hi, Enze,
> >
> > On Wed, Jul 19, 2023 at 4:34=E2=80=AFPM Enze Li <lienze@kylinos.cn> wro=
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
> >> Tested this patch by using the testcases and all passed.
> >>
> >> [1] https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-=
EN.html#virtual-address-space-and-address-translation-mode
> >>
> >> Signed-off-by: Enze Li <lienze@kylinos.cn>
> >> ---
> >>  arch/loongarch/Kconfig               |  1 +
> >>  arch/loongarch/include/asm/kfence.h  | 62 +++++++++++++++++++++++++++=
+
> >>  arch/loongarch/include/asm/pgtable.h |  6 +++
> >>  arch/loongarch/mm/fault.c            | 22 ++++++----
> >>  4 files changed, 83 insertions(+), 8 deletions(-)
> >>  create mode 100644 arch/loongarch/include/asm/kfence.h
> >>
> >> diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
> >> index 5411e3a4eb88..db27729003d3 100644
> >> --- a/arch/loongarch/Kconfig
> >> +++ b/arch/loongarch/Kconfig
> >> @@ -93,6 +93,7 @@ config LOONGARCH
> >>         select HAVE_ARCH_JUMP_LABEL
> >>         select HAVE_ARCH_JUMP_LABEL_RELATIVE
> >>         select HAVE_ARCH_KASAN
> >> +       select HAVE_ARCH_KFENCE if 64BIT
> > "if 64BIT" can be dropped here.
> >
>
> Fixed.
>
> >>         select HAVE_ARCH_MMAP_RND_BITS if MMU
> >>         select HAVE_ARCH_SECCOMP_FILTER
> >>         select HAVE_ARCH_TRACEHOOK
> >> diff --git a/arch/loongarch/include/asm/kfence.h b/arch/loongarch/incl=
ude/asm/kfence.h
> >> new file mode 100644
> >> index 000000000000..2a85acc2bc70
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
> >> +static inline char *arch_kfence_init_pool(void)
> >> +{
> >> +       char *__kfence_pool_orig =3D __kfence_pool;
> > I prefer kfence_pool than __kfence_pool_orig here.
> >
>
> Fixed.
>
> >> +       struct vm_struct *area;
> >> +       int err;
> >> +
> >> +       area =3D __get_vm_area_caller(KFENCE_POOL_SIZE, VM_IOREMAP,
> >> +                                   KFENCE_AREA_START, KFENCE_AREA_END=
,
> >> +                                   __builtin_return_address(0));
> >> +       if (!area)
> >> +               return NULL;
> >> +
> >> +       __kfence_pool =3D (char *)area->addr;
> >> +       err =3D ioremap_page_range((unsigned long)__kfence_pool,
> >> +                                (unsigned long)__kfence_pool + KFENCE=
_POOL_SIZE,
> >> +                                virt_to_phys((void *)__kfence_pool_or=
ig),
> >> +                                PAGE_KERNEL);
> >> +       if (err) {
> >> +               free_vm_area(area);
> >> +               return NULL;
> >> +       }
> >> +
> >> +       return __kfence_pool;
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
> >> index 0fc074b8bd48..5a9c81298fe3 100644
> >> --- a/arch/loongarch/include/asm/pgtable.h
> >> +++ b/arch/loongarch/include/asm/pgtable.h
> >> @@ -85,7 +85,13 @@ extern unsigned long zero_page_mask;
> >>  #define MODULES_VADDR  (vm_map_base + PCI_IOSIZE + (2 * PAGE_SIZE))
> >>  #define MODULES_END    (MODULES_VADDR + SZ_256M)
> >>
> >> +#ifdef CONFIG_KFENCE
> >> +#define KFENCE_AREA_START      MODULES_END
> >> +#define KFENCE_AREA_END                (KFENCE_AREA_START + SZ_512M)
> > Why you choose 512M here?
> >
>
> One day I noticed that 512M can hold 16K (default 255) KFENCE objects,
> which should be more than enough and I think this should be appropriate.
>
> As far as I see, KFENCE system does not have the upper limit of this
> value(CONFIG_KFENCE_NUM_OBJECTS), which could theoretically be any
> number.  There's another way, how about setting this value to be
> determined by the configuration, like this,
>
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>  +#define KFENCE_AREA_END \
>  + (KFENCE_AREA_START + (CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_SIZE)
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
How does other archs configure the size?

>
> >> +#define VMALLOC_START          KFENCE_AREA_END
> >> +#else
> >>  #define VMALLOC_START  MODULES_END
> >> +#endif
> > I don't like to put KFENCE_AREA between module and vmalloc range (it
> > may cause some problems), can we put it after vmemmap?
>
> I found that there is not enough space after vmemmap and that these
> spaces are affected by KASAN. As follows,
>
> Without KASAN
> ###### module 0xffff800002008000~0xffff800012008000
> ###### malloc 0xffff800032008000~0xfffffefffe000000
> ###### vmemmap 0xffffff0000000000~0xffffffffffffffff
>
> With KASAN
> ###### module 0xffff800002008000~0xffff800012008000
> ###### malloc 0xffff800032008000~0xffffbefffe000000
> ###### vmemmap 0xffffbf0000000000~0xffffbfffffffffff
>
> What about put it before MODULES_START?
I temporarily drop KASAN in linux-next for you. You can update a new
patch version without KASAN (still, put KFENCE after vmemmap), and
then we can improve further.

Huacai
>
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D
> --- a/arch/loongarch/include/asm/pgtable.h
> +++ b/arch/loongarch/include/asm/pgtable.h
> @@ -82,7 +82,14 @@ extern unsigned long zero_page_mask;
>   * Avoid the first couple of pages so NULL pointer dereferences will
>   * still reliably trap.
>   */
> +#ifdef CONFIG_KFENCE
> +#define KFENCE_AREA_START      (vm_map_base + PCI_IOSIZE + (2 * PAGE_SIZ=
E))
> +#define KFENCE_AREA_END        \
> +       (KFENCE_AREA_START + (CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_S=
IZE)
> +#define MODULES_VADDR  KFENCE_AREA_END
> +#else
>  #define MODULES_VADDR  (vm_map_base + PCI_IOSIZE + (2 * PAGE_SIZE))
> +#endif
>  #define MODULES_END    (MODULES_VADDR + SZ_256M)
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D
>
> Best Regards,
> Enze
>
> >>
> >>  #ifndef CONFIG_KASAN
> >>  #define VMALLOC_END    \
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
kasan-dev/CAAhV-H6FoC1v9f9Vkq9rzk%3D0j88RczLgiYTiBUBNDwx3B%3D3tYA%40mail.gm=
ail.com.
