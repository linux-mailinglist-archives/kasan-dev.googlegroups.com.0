Return-Path: <kasan-dev+bncBCMIZB7QWENRB56CT2PAMGQE2Q73DLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 08C9B671519
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Jan 2023 08:36:24 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id z22-20020a05600c0a1600b003db00dc4b69sf791355wmp.5
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Jan 2023 23:36:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674027383; cv=pass;
        d=google.com; s=arc-20160816;
        b=nyGRhl03u/3NEQIwFwd2PXRTSYZkNnMWjtR4uoUduychKdcAIpetKn7xbI8k9ezrui
         WN+hEDZAkYVVwp6zmLjcDuTnWdKAAa3CwK60w2GXCpKOtD2yxQszBw0jhTpENQ5DtjbC
         lly3cg412m9/h/hiw3vOdIOFeL2F++rUG3q9Se6eJbUgPFfPMb0f7r4KcGemb1AMAPI6
         TK+gTKLzeiVWr1G94GuZ4QDJ9mDgOY74RlCSy7T7RNIHE9DlE85HUuhCYjgcUksbhsHo
         iqU8tVv4HZUW7QCVIKTDT+IdB3ZrcbdRhDhaAKN9TEPQ/PwcFr1bxXrknmwGtKCl7aJQ
         FRZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=lL35jsDH4VzQ75or+Hf6qurHbU7Cyj3TP/GhULe4m10=;
        b=KYjV4c9O7lxWYZi9bAcR6ZA7xn6tsTfxF1vzkurHi3WY+fPpVp3Hm2vFMaI5xA1xx6
         l2eG9FNbU/X8nOnybFBoCr1SlTz4fJFPIhcPzva0h7aU+aYXxolmS4DrNakbZBqrx4vw
         CxSLYwCLG0pJxvTG32l8R9nYhmILha/88YKO7meQB5eng6OgNKRq7BYeysBbBlTS9Wbt
         QR3VLFW7mDmcS8tUW5rrtzZjO16s1eiTm9nabMrxdZug85dXcr9YSsbtQwxfEWctTabd
         IfOiI/t+ahAQrSyvfqJVisogsxmoaWHoESpXyaKBWEnc1P6SVb2OAXsiWsTuv5jmufUU
         O6pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Y1PYitAE;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lL35jsDH4VzQ75or+Hf6qurHbU7Cyj3TP/GhULe4m10=;
        b=HSpbF8b0Kdbv8vD2RY3HEH7VRky7zDRHpnXaXkNhiIxDu0rNOwzI7ZBIHX28B2X8jG
         MDY4hJzKOD8lYUGIyVOCMYZNnx7UgMgeo/MxgbyVsyI8b+Pv/9Ojw6fJvIaHX5nl7zcL
         5mZnzht4SWeRcvcAlv3siSbBNdljtbApXjZIFQHJnaC5yR+plxc4Jc9WbNbgfXXU1t3G
         6DnKupa32PZO56XGaiwQNnZMCn344YutWBYXpufzOrweUjeVdR/FX8jtJpjruYfRd5j1
         juvNpCD+Hz1iFe583r//ZAb8gU1YYUui40LxDy5GLOMwIWgxMVohR3c7YmYr5Mc5uamW
         ulhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=lL35jsDH4VzQ75or+Hf6qurHbU7Cyj3TP/GhULe4m10=;
        b=lR3IBbaXrlnMc9izKiutFuC63Si5lfO9puy0aqxP3QmN0FkIxSeBVLsktxn6v2InLG
         8oJappaMYTxrDmX47EQopRCeDsoIFJ9f89N6ZPV4XWl73WRMYCsEp6KPICcxuWW5Innf
         MI+R/ulcr1OZlRcBJ4UuS7KErPW11I1MVZVMe+3NZcqCv38pksyE2GX9gazoPDUVaVSK
         +or45wWOFoeCi8JOBNS2wzWiC7ZYy7Xi/HzH3HO2/0FKpHibxjNcjm5Xg430IabqGc3S
         2rvs79ulMJmMLfGoQNCqfVduuyBvAjRdfm/NOKnjQCEx52AdrF9uw7sFpT/WP3zcpbLI
         Br8Q==
X-Gm-Message-State: AFqh2kqbZTr4q6D44WsrR64dftoBn14p+TINcW9vrRwDa7hOctIeWBNy
	dGSbW1c1LFln6I2YBvBv2kE=
X-Google-Smtp-Source: AMrXdXtJQS2fL1I1M0gI0dOkaX0ygZb9h+Uavqy4eDyGC7GhB6EoaP/lu3EZ689SeMFZXhyU7FU5ig==
X-Received: by 2002:a05:600c:3217:b0:3d9:f14e:d140 with SMTP id r23-20020a05600c321700b003d9f14ed140mr393317wmp.46.1674027383639;
        Tue, 17 Jan 2023 23:36:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:f70d:0:b0:3d9:bb72:6814 with SMTP id v13-20020a1cf70d000000b003d9bb726814ls345862wmh.3.-pod-control-gmail;
 Tue, 17 Jan 2023 23:36:22 -0800 (PST)
X-Received: by 2002:a05:600c:17c6:b0:3da:f672:b0e7 with SMTP id y6-20020a05600c17c600b003daf672b0e7mr5584634wmo.26.1674027382544;
        Tue, 17 Jan 2023 23:36:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674027382; cv=none;
        d=google.com; s=arc-20160816;
        b=dyBeMQNnCaZJKXITcKBJMJh60uelF7ZCCBFSALAKyAOOVoB+hx8ucozM/aaU0BWys9
         hnchDG4zOFhIonIcci9V7uuZKpoPSiP4O7SpobWx1GI7CkAZAx08UkJeZLPFPFSYXVPk
         EEg/keiajkMS2GV9bJWjbglcn3Qy4efo/C1ByTiHcjlrl1A5nx5XhF0sEOUKhbGapPI5
         7zNjpoGIhsrM1ITsBl+GoLC7m7V6L9mB2zXgSR0j5MB6vitL9xPjzw2AX0RtImugx2Wr
         tz+AC5uFbGqM1PYEKdm7DgggFhi0c4uiWl4FmcWsuEIoTsXxqixaCRsU9x7cLUvLv2NE
         nWKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tXJS6O96pqUrAn6JTjfwzdlxbTr5MxmXpgvppk1+ZUI=;
        b=mqCDsC9i1SV10pmnclDHncCrB333kBy1tI7jyJ4VAbSr3cRCNDV0Ka07uDBIR3OKzr
         C4Xwnit/UCxucchliY/NSmnaV4ay7y/HwWY/I3/9VDqGJBBPVIm5ZEWHMcVNBScvMJjW
         /B7naneFb19IwjBJxYlewmweL8psxZTgZK7BbxdUtfpHiaXQBKrcVB3LpEDlYtIpV9g2
         L+g5ny/tWwxfh+OVVflvc0L61l4tHJOpLBmBz1fu7DzbGY2gz1tTx1PdUJwGJ8VcQjSr
         jDCQbiJVf+rkMvMCdaEkG+YlkFu62p2YnCiK+SABU6lnHS1/Z0HbfpCZX/5xYlquznRE
         ueyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Y1PYitAE;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x132.google.com (mail-lf1-x132.google.com. [2a00:1450:4864:20::132])
        by gmr-mx.google.com with ESMTPS id s4-20020a05600c384400b003d9c774d43fsi49620wmr.2.2023.01.17.23.36.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Jan 2023 23:36:22 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::132 as permitted sender) client-ip=2a00:1450:4864:20::132;
Received: by mail-lf1-x132.google.com with SMTP id g13so50502539lfv.7
        for <kasan-dev@googlegroups.com>; Tue, 17 Jan 2023 23:36:22 -0800 (PST)
X-Received: by 2002:ac2:4bd0:0:b0:4c5:32a4:6f88 with SMTP id
 o16-20020ac24bd0000000b004c532a46f88mr410419lfq.6.1674027381894; Tue, 17 Jan
 2023 23:36:21 -0800 (PST)
MIME-Version: 1.0
References: <20230117163543.1049025-1-jannh@google.com>
In-Reply-To: <20230117163543.1049025-1-jannh@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 Jan 2023 08:36:09 +0100
Message-ID: <CACT4Y+aQUeoWnWmbDG3O2_P75f=2u=VDRA1PjuTtbJsp5Xw2VA@mail.gmail.com>
Subject: Re: [PATCH] fork, vmalloc: KASAN-poison backing pages of vmapped stacks
To: Jann Horn <jannh@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	Uladzislau Rezki <urezki@gmail.com>, Christoph Hellwig <hch@infradead.org>, Andy Lutomirski <luto@kernel.org>, 
	linux-kernel@vger.kernel.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Y1PYitAE;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::132
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, 17 Jan 2023 at 17:35, Jann Horn <jannh@google.com> wrote:
>
> KASAN (except in HW_TAGS mode) tracks memory state based on virtual
> addresses. The mappings of kernel stack pages in the linear mapping are
> currently marked as fully accessible.

Hi Jann,

To confirm my understanding, this is not just KASAN (except in HW_TAGS
mode), but also CONFIG_VMAP_STACK is required, right?

> Since stack corruption issues can cause some very gnarly errors, let's be
> extra careful and tell KASAN to forbid accesses to stack memory through the
> linear mapping.
>
> Signed-off-by: Jann Horn <jannh@google.com>
> ---
> I wrote this after seeing
> https://lore.kernel.org/all/Y8W5rjKdZ9erIF14@casper.infradead.org/
> and wondering about possible ways that this kind of stack corruption
> could be sneaking past KASAN.
> That's proooobably not the explanation, but still...

I think catching any silent corruptions is still very useful. Besides
confusing reports, sometimes they lead to an explosion of random
reports all over the kernel.

>  include/linux/vmalloc.h |  6 ++++++
>  kernel/fork.c           | 10 ++++++++++
>  mm/vmalloc.c            | 24 ++++++++++++++++++++++++
>  3 files changed, 40 insertions(+)
>
> diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
> index 096d48aa3437..bfb50178e5e3 100644
> --- a/include/linux/vmalloc.h
> +++ b/include/linux/vmalloc.h
> @@ -297,4 +297,10 @@ bool vmalloc_dump_obj(void *object);
>  static inline bool vmalloc_dump_obj(void *object) { return false; }
>  #endif
>
> +#if defined(CONFIG_MMU) && (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS))
> +void vmalloc_poison_backing_pages(const void *addr);
> +#else
> +static inline void vmalloc_poison_backing_pages(const void *addr) {}
> +#endif

I think this should be in kasan headers and prefixed with kasan_.
There are also kmsan/kcsan that may poison memory and hw poisoning
(MADV_HWPOISON), so it's a somewhat overloaded term on its own.

Can/should this be extended to all vmalloc-ed memory? Or some of it
can be accessed via both addresses?

Also, should we mprotect it instead while it's allocated as the stack?
If it works, it looks like a reasonable improvement for
CONFIG_VMAP_STACK in general. Would also catch non-instrumented
accesses.

>  #endif /* _LINUX_VMALLOC_H */
> diff --git a/kernel/fork.c b/kernel/fork.c
> index 9f7fe3541897..5c8c103a3597 100644
> --- a/kernel/fork.c
> +++ b/kernel/fork.c
> @@ -321,6 +321,16 @@ static int alloc_thread_stack_node(struct task_struct *tsk, int node)
>                 vfree(stack);
>                 return -ENOMEM;
>         }
> +
> +       /*
> +        * A virtually-allocated stack's memory should only be accessed through
> +        * the vmalloc area, not through the linear mapping.
> +        * Inform KASAN that all accesses through the linear mapping should be
> +        * reported (instead of permitting all accesses through the linear
> +        * mapping).
> +        */
> +       vmalloc_poison_backing_pages(stack);
> +
>         /*
>          * We can't call find_vm_area() in interrupt context, and
>          * free_thread_stack() can be called in interrupt context,
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index ca71de7c9d77..10c79c53cf5c 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -4042,6 +4042,30 @@ void pcpu_free_vm_areas(struct vm_struct **vms, int nr_vms)
>  }
>  #endif /* CONFIG_SMP */
>
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
> +/*
> + * Poison the KASAN shadow for the linear mapping of the pages used as stack
> + * memory.
> + * NOTE: This makes no sense in HW_TAGS mode because HW_TAGS marks physical
> + * memory, not virtual memory.
> + */
> +void vmalloc_poison_backing_pages(const void *addr)
> +{
> +       struct vm_struct *area;
> +       int i;
> +
> +       if (WARN(!PAGE_ALIGNED(addr), "bad address (%p)\n", addr))
> +               return;
> +
> +       area = find_vm_area(addr);
> +       if (WARN(!area, "nonexistent vm area (%p)\n", addr))
> +               return;
> +
> +       for (i = 0; i < area->nr_pages; i++)
> +               kasan_poison_pages(area->pages[i], 0, false);
> +}
> +#endif
> +
>  #ifdef CONFIG_PRINTK
>  bool vmalloc_dump_obj(void *object)
>  {
>
> base-commit: 5dc4c995db9eb45f6373a956eb1f69460e69e6d4
> --
> 2.39.0.314.g84b9a713c41-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaQUeoWnWmbDG3O2_P75f%3D2u%3DVDRA1PjuTtbJsp5Xw2VA%40mail.gmail.com.
