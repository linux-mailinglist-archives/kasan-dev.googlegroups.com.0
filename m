Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE4Y3GCAMGQEBZB22AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 85ABB3770AA
	for <lists+kasan-dev@lfdr.de>; Sat,  8 May 2021 10:30:13 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id mq6-20020a17090b3806b029015c12a293efsf3109444pjb.1
        for <lists+kasan-dev@lfdr.de>; Sat, 08 May 2021 01:30:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620462612; cv=pass;
        d=google.com; s=arc-20160816;
        b=bsde2S5xQ8pqfShW5dzswFfHpi4Q+DJXqRiEkwJBPqVQbOMSUWl98CX3w901ktR7a+
         1EHu0gRnlXwyhZ3M+kWye5urfSNQM+I3cjhvLAggzoDa5Dgq45b9G49MP1pC2LTD7wvg
         6EAv28VLOYdrmIWiX+mgac6GUUCFJQYWaJ6ngt1sYJDGIpdU0tZcVdov9fo/UloNM8ow
         dw8HRXvAvk919dCq9qbLMH8aRLZle7jc7z75kTHoZhamT2/cu7oT6k7VQrFLBa2D9Kyq
         kxesZqtfdxAAk8bRmgOQgFb4zF6Si7MaE5/uGl8IMUpN2dbbNrms14+3g4WNJgMFTgO9
         Ri7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Nqw3LhFQGVeqUut1Eunzt/HENVCTJMQTSBWBC9h1nLg=;
        b=vaBgLQ5IGK1kECEFiHymAX6C/VN2Y+WD0PH8XsNG7jaJBYPp4qip9NAZAlvl1WzT/m
         E0isyzWUyLrJ3og7LnYdlzdbq9j8vzL8/TGae8vraKFEalBgXeYslsMQzBp1X83udbEU
         3a95BevZ6U2CHBpEmfKdFmc8AbV1pA6S0qKRiMmkmSGxrwe1LkK28UV3Znj5erCFdnOz
         eTczcqtftwgUMPPMOUNvdpHlMWZW3uyKXAGiopdhTd0aOmo//CJuzQOlMkXRlDrvjCVE
         qsKdzTknbywMm5bVWYkd51gCFbGYrfpPbCIO+u3ZCJbgM5oSle2cN7ju6HHZgAp33KDU
         coiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dZdBMLYg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Nqw3LhFQGVeqUut1Eunzt/HENVCTJMQTSBWBC9h1nLg=;
        b=lSPnAHMkYszguPcaAMO1mqdAmddmuZypA/XAHnlrbDdEAl7AFEWdW6G3+f3asoudsL
         rBHo0uaPKsQo12+lx3INo4AuL/4tGSewFIv7GxNlyabeTyOK7KP8KttoISQEsLJlxVUQ
         ix8LEpQBbzPJmT9X+drpYStzymStPnot1QUtVwZ06xlzYTiNBEkC1capFVuSAfHJgqN+
         94YEnf9Ir4JVwka5RamDIMNomCMZz/hUajoWFy5K2IXOuwUzybCCkA156xgbhJqXNlst
         Bid9UoxXnEP2IBKIwFBTQN2l5hAVYn6uO1i99S6hxrIt+Har5CPmkY5S8ODBXsNxV+br
         GSxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Nqw3LhFQGVeqUut1Eunzt/HENVCTJMQTSBWBC9h1nLg=;
        b=JSnFQi+F+0spe4uUPLL5LkL1wHkfz0U8lQjAxO9dt1C3Bpq+skbhspOl1VVyi3NSYk
         NsHRjIjU7Fvl7P38chP6lFP7FqQ814ADjXL7UNHd5MKn2rSUPZy9eLbsvrK0l4gNmUyI
         Awdhx5jVh26NYeA20qabfDtGKZMBVWtW8H0lX8a8jr+qm3q9jVZq4HJYUAc08StXUt0k
         3tMRONclwkoNd3OKxAUUBIA1wcnH+wW/J1fe5Rvg53eaPhuYShp2G8Bk2nxleDhGyk/T
         3sA1FYoJNDt+azxytEPPk0W88YXb3FWYLl69MDmB0jNT43l4oPkRV6IRlRIn1n08RqzD
         EWsQ==
X-Gm-Message-State: AOAM5304fH9zIC/KqpIArx6o/L+JDFNOhrjDlzIqPL0P1WOYqxJHncmS
	G4H1oIaKVstrmGS9IhSF8oc=
X-Google-Smtp-Source: ABdhPJxPbZDFMxhxLwlSy/OiXuG1HYyFoLUY8JwDJKEFB/oZjtr/eBDDi0oOFLF+/eWtf23fql3YcA==
X-Received: by 2002:aa7:98de:0:b029:28d:f7e0:ac3a with SMTP id e30-20020aa798de0000b029028df7e0ac3amr14633005pfm.26.1620462612007;
        Sat, 08 May 2021 01:30:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:7e1c:: with SMTP id z28ls3850957pgc.3.gmail; Sat, 08 May
 2021 01:30:09 -0700 (PDT)
X-Received: by 2002:a65:590a:: with SMTP id f10mr14589364pgu.358.1620462609606;
        Sat, 08 May 2021 01:30:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620462609; cv=none;
        d=google.com; s=arc-20160816;
        b=1FcApd2g/y1ZUaONY3h6c39Dt15PSJtFi8JZty9/QhnabifNJOMvXG5Odd+7M2U44p
         t+4ElpDiwnHS8sr0FzIOwjXXFG1xt02HzRtizm28YitGDnQMfnIf9y/TCaXl5NxjNKmM
         iKwKZ/ogeGTxi41AVseCvSiqB8oAIV0WZvh0bxOsSRmnKyVGkZsgeyJ2S8uchamCzLDy
         wXE2ebb8PCJx/mzPY0Ojrb20r25rY+sFMiVHOd1by6BimL7zquZuyyroLUMzWuJXM162
         ZBc/7jxXPbAxElZQmnWnkYJ6bzp+rswxLTeDM3sHAR8l3FoekMmo6Y4QfcGxmcY6bXMx
         qBoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QHWD9J6ofLEJEBPQ1owqvKysj/6TUwLubW0zYntQWn4=;
        b=PMfhHtIaHdwquSgrVXFR+sBBPnws9vmrcku6kO67N1nrhosB/zXmZc9XQX8mT5DtGg
         C7MyANufP4V/QnmklCopqGcqrIVNRCO+u4aVSVbgPwsSFwmTmbfTiZ9pvT0psuU81ReC
         Cv7fVKbZ9g9vkR0A3kdPmIWI1ke0Ol8Nf7nCO5hL2B/kC4mIlIp4pUxLxAn4PRb8lLOv
         Jl4dv7HLPCHfQLLGPdSAYOjqJL7Z07q9RZwWioIEapDjcFrDHyH3mhkIPQp9e62iclxi
         7BkioV/3pIetknv2DYw58hLezDTgLMU6nNyrSEvBo3NfKz9vEYhnjvF3pCrAmzqCvTrZ
         9LWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dZdBMLYg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32a.google.com (mail-ot1-x32a.google.com. [2607:f8b0:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id x9si1847410pjr.2.2021.05.08.01.30.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 08 May 2021 01:30:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) client-ip=2607:f8b0:4864:20::32a;
Received: by mail-ot1-x32a.google.com with SMTP id g15-20020a9d128f0000b02902a7d7a7bb6eso9990449otg.9
        for <kasan-dev@googlegroups.com>; Sat, 08 May 2021 01:30:09 -0700 (PDT)
X-Received: by 2002:a9d:1ea9:: with SMTP id n38mr12276751otn.233.1620462608813;
 Sat, 08 May 2021 01:30:08 -0700 (PDT)
MIME-Version: 1.0
References: <20210508032912.2693212-1-liushixin2@huawei.com>
In-Reply-To: <20210508032912.2693212-1-liushixin2@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 8 May 2021 10:29:56 +0200
Message-ID: <CANpmjNP_ybX6eK=AqGNCBfVSLtOxzihQpNGL95s8itOS=eCdfQ@mail.gmail.com>
Subject: Re: [RFC] riscv: Enable KFENCE for riscv64
To: Liu Shixin <liushixin2@huawei.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, linux-riscv@lists.infradead.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dZdBMLYg;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Sat, 8 May 2021 at 04:56, Liu Shixin <liushixin2@huawei.com> wrote:
>
> Add architecture specific implementation details for KFENCE and enable
> KFENCE for the riscv64 architecture. In particular, this implements the
> required interface in <asm/kfence.h>.

Nice to see KFENCE on more architectures.

> KFENCE requires that attributes for pages from its memory pool can
> individually be set. Therefore, force the kfence pool to be mapped at
> page granularity.
>
> I tested this patch using the testcases in kfence_test.c and all passed.
>
> Signed-off-by: Liu Shixin <liushixin2@huawei.com>
[...]
> diff --git a/arch/riscv/include/asm/kfence.h b/arch/riscv/include/asm/kfence.h
> new file mode 100644
> index 000000000000..590c5b7e3514
> --- /dev/null
> +++ b/arch/riscv/include/asm/kfence.h
> @@ -0,0 +1,51 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +
> +#ifndef _ASM_RISCV_KFENCE_H
> +#define _ASM_RISCV_KFENCE_H
> +
> +#include <linux/pfn.h>
> +#include <linux/slab.h>
> +#include <linux/kfence.h>
> +#include <asm/pgtable.h>
> +
> +static inline bool arch_kfence_init_pool(void)
> +{
> +       int i;
> +       unsigned long addr;
> +       pte_t *pte;
> +       pmd_t *pmd;
> +
> +       for (addr = (unsigned long)__kfence_pool; is_kfence_address((void *)addr);
> +            addr += PAGE_SIZE) {
> +               pte = virt_to_kpte(addr);
> +               pmd = pmd_off_k(addr);
> +
> +               if (!pmd_leaf(*pmd) && pte_present(*pte))
> +                       continue;
> +
> +               pte = kmalloc(PAGE_SIZE, GFP_ATOMIC);

Using kmalloc() to allocate pte looks weird. Does riscv have helpers
for allocating pte? Otherwise, __get_free_page() perhaps?

> +               for (i = 0; i < PTRS_PER_PTE; i++)
> +                       set_pte(pte + i, pfn_pte(PFN_DOWN(__pa((addr & PMD_MASK) + i * PAGE_SIZE)), PAGE_KERNEL));
> +
> +               set_pmd(pmd, pfn_pmd(PFN_DOWN(__pa(pte)), PAGE_TABLE));
> +               flush_tlb_kernel_range(addr, addr + PMD_SIZE);
> +       }
> +
> +       return true;
> +}
> +
> +static inline bool kfence_protect_page(unsigned long addr, bool protect)
> +{
> +       pte_t *pte = virt_to_kpte(addr);
> +
> +       if (protect)
> +               set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
> +       else
> +               set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
> +
> +       flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
> +
> +       return true;
> +}
[...]

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP_ybX6eK%3DAqGNCBfVSLtOxzihQpNGL95s8itOS%3DeCdfQ%40mail.gmail.com.
