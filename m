Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRWKT2VQMGQESJ2CWGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8472E7FE168
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 21:55:35 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-67a1d33ab22sf2502406d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 12:55:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701291334; cv=pass;
        d=google.com; s=arc-20160816;
        b=a/q9DvimDAWdogokfWI4dKPYPrOQFL1m6x24Az9JaHMzrakjMgIZZCAR6bKoVEB1Sc
         R3pMFbpSqrg8U0SZMdTQe4qbgN3bRrJrjitJmzSnUkiMQoYrz1Qwv2Ho+IDy7hwmJDBc
         Lvy7D+FfD8J2rRblERuLhh0VsX7ilUrTXiTGQn4omKCXeLFtnFHeLwf5VzQE0ELXLQGq
         nyFb9NzZgOzA62yNYOJgNYruSfPAyx90cowizCR41KhJO8IrbcJDteRzBvwZclg96krS
         u/O3Msd5GP1bULum4/FdwzfPGKcOmqCHVrui7okFbKLXJcKsLHmmHyw4zimRs+F1P0+i
         cNdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wbVhULYxxdX/atR0VhSkeJZOiTodp1oZloFrBmIxxwU=;
        fh=tsIHYQd+95QiwZEAV54eWstSQej7ClBaiAjrSoM77lA=;
        b=PK1v8nDIcLdO3B8JmEppcgDBeoxIcqL3FHmjudcp2Ys1S42DOHjoaG/pxAdYNcWjNg
         m0fk7DpDRogbW8mJTSThxDpk7uT9oNi+WMtf3i+8SOJWNPUQfZpV/N6AYnwBx6EwHpcB
         kqIFfAWAmP/Z1Knu9VJzKJO2X5pLsmwyRwnwH/0QXVKMuXm+85sTtzB7Fk5Yhpw7yFLR
         3OF1vBXNDDSfIxv6FTnTJKoCigCM7YLipnqmBXsHdA+TcxBrIUX32fnkVwdyQ3kAAerb
         3qRraIJVlVKXeMhx542ew36+mUldA95WBHX+1cOdTkSc2O54MF+p5pmvczVd/7/QLCFs
         QeZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=fpqcQSg5;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701291334; x=1701896134; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wbVhULYxxdX/atR0VhSkeJZOiTodp1oZloFrBmIxxwU=;
        b=uZTFSUXV7Ee929DT8ACNdk1TEdcxH6IRsqOserpxNwnECmTvinTSqjkRDl+XXx+bbM
         l0+/GKToI6HkOpqFT5oENVmqwg5yiHCLtMXvog1LAAufqBWI4oGSwaLZ6M6hmGbvR/Jh
         aBRGUGPjuV6GHjjJU5lm0Wbyn+H1/pLRYsj2su9kMcTlopSuiEilZjFkutBi40NkAvu9
         QYNLrSiF0ONJmzXf2xvcDMFgr6yQbBbaZkDWubqBn9Znga35QJ+l0dHZWUkkjTPUdH2q
         +kB3vfiuE14+MiuD0AMYvs0WEtH+jfxfYqjsJZN2CjJIRjIl5Ago4YJ/CuAt7qaXrN7c
         0fWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701291334; x=1701896134;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wbVhULYxxdX/atR0VhSkeJZOiTodp1oZloFrBmIxxwU=;
        b=Fkb3Wi0K6nqo4HANDkA6+/EC8LabJhWggrofvuvp1PPtXI/u+6+cr1AfaqpTLWxbj1
         GXs8nZwIYmON5CwQ9lqoCnDA8N8qTFOXrmdVpjw3hF0xXrAo4uZsbzMP2EglAzXFSa+d
         uDEXB5z08cjHTXG+5ceuIdTo8inm7Q8J/FWmvTpQIedRYop4IArs7QGhqXrf2ITXEDN6
         nHK24uE4t5muXnuErGhBRW/11ItMzYgNLUzsXuxIQXV08H6ymW1JpE8qHjBuRVeJ4xsC
         6a59QmI95T/ht9REtgGCCab5NEOgh3SKJynUTL42JO8UvKOwGT7FU1N5XtyKJlwcRmaU
         6d6w==
X-Gm-Message-State: AOJu0YxiNQzPSHZsCvckOmrNJPSnT1nwKd7YRxBYoLBZ4THW/Tz5+xNj
	qc6LIaPTDwB+R08GtLZpLyU=
X-Google-Smtp-Source: AGHT+IH3At0uaVdk3n0M6Gvtcb1LVbG6pvYjFRcUpJKPieSQdMZ0+jEHOzUfHRrxk0ifaTrCEzN3bw==
X-Received: by 2002:a05:6214:2a84:b0:67a:261b:ef98 with SMTP id jr4-20020a0562142a8400b0067a261bef98mr19014271qvb.24.1701291334149;
        Wed, 29 Nov 2023 12:55:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:ff2b:0:b0:679:fa52:346a with SMTP id x11-20020a0cff2b000000b00679fa52346als243006qvt.0.-pod-prod-09-us;
 Wed, 29 Nov 2023 12:55:33 -0800 (PST)
X-Received: by 2002:a05:6122:8d4:b0:4ac:c52d:70f9 with SMTP id 20-20020a05612208d400b004acc52d70f9mr24323957vkg.10.1701291333403;
        Wed, 29 Nov 2023 12:55:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701291333; cv=none;
        d=google.com; s=arc-20160816;
        b=Ci1b5MzXYoaNzuLOfPUmLd2KFEOI4aTvtL+S9ayY+eSUBJQbAyKrF1Il41Q76Axu+U
         7mzCXrlY9aD2fLsx6ghWxM4FUMN9M3K7LQTL62LT1dFsLPsm4Sw5md+u8BsALGPOvCm8
         wb7At+LsB+MBK7YhIrbnnr0AF7oMCx6p8n+yqQHYgdQZ+XcaVTS1VtRaFc3fIezfEayF
         XkO3D1wAiA+0yplJJhIf2N5kULrGc1JdC9LhigvWRcHfieezFfzjHpps9NXK0OXTVcT4
         SaDo1cfJ9diYQgO1U4NUQtobCYUCoKPhnArW1KZ5K4CdeK/y3OGbLDtvAmvdiJRYYISQ
         FDsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mh8mfkKmbZyezogReiTmoJ2/ZEYTC/jfxX54yQ12YVc=;
        fh=tsIHYQd+95QiwZEAV54eWstSQej7ClBaiAjrSoM77lA=;
        b=eudp/uFSnbBXQHoDMf1ASRcYeVTF8W2xd96n/C1HPNgiszdcjYqDMEM0wmCL7CJwH2
         5HrzCu5cF51Q+k6R9S/s131XvuvW9CQZ0re8T1WADfgMvVL9OtVCDfPkhhz9DZgGsKxb
         6oA8tbkdv7ol0jt4yHcW/Gu93dEbql+fI3eVNihrBh74julTvAx2M0fTapbdcu4V0hmh
         gr2haKLR9VILGiODSUkpYyJHUfauytkI7ykj/BWk00bwXWvDnKx7fUnVoFj6EFQJlKyY
         Dy1cVb9OzL6bhNlgLa1cdF+Z8oT3q8pLBNcJYq61n+zl5+oIzSiBAwf306+9uCbq/Pje
         mafQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=fpqcQSg5;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2c.google.com (mail-vs1-xe2c.google.com. [2607:f8b0:4864:20::e2c])
        by gmr-mx.google.com with ESMTPS id ge31-20020a0561224e1f00b004abd0f58a5esi1856322vkb.2.2023.11.29.12.55.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Nov 2023 12:55:33 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2c as permitted sender) client-ip=2607:f8b0:4864:20::e2c;
Received: by mail-vs1-xe2c.google.com with SMTP id ada2fe7eead31-464434e7804so46207137.2
        for <kasan-dev@googlegroups.com>; Wed, 29 Nov 2023 12:55:33 -0800 (PST)
X-Received: by 2002:a05:6102:244f:b0:464:4d97:2c01 with SMTP id
 g15-20020a056102244f00b004644d972c01mr2523133vss.31.1701291332997; Wed, 29
 Nov 2023 12:55:32 -0800 (PST)
MIME-Version: 1.0
References: <20231127234946.2514120-1-swboyd@chromium.org> <202311291219.A6E3E58@keescook>
 <CAE-0n53x8AXUPaq5_TaqF6PN5u5J6g5RYoNWALN-MnEJBa5syA@mail.gmail.com>
In-Reply-To: <CAE-0n53x8AXUPaq5_TaqF6PN5u5J6g5RYoNWALN-MnEJBa5syA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 29 Nov 2023 21:54:54 +0100
Message-ID: <CANpmjNP9Koro2FKS9xG5LDvOvyRKrQBFkyKhJVSsqFJdEE+peA@mail.gmail.com>
Subject: Re: [PATCH] lkdtm: Add kfence read after free crash type
To: Stephen Boyd <swboyd@chromium.org>
Cc: Kees Cook <keescook@chromium.org>, linux-kernel@vger.kernel.org, 
	patches@lists.linux.dev, Arnd Bergmann <arnd@arndb.de>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=fpqcQSg5;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2c as
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

On Wed, 29 Nov 2023 at 21:42, Stephen Boyd <swboyd@chromium.org> wrote:
>
> Adding kfence folks (will add on v2).
>
> Quoting Kees Cook (2023-11-29 12:22:27)
> > On Mon, Nov 27, 2023 at 03:49:45PM -0800, Stephen Boyd wrote:
> > > Add the ability to allocate memory from kfence and trigger a read after
> > > free on that memory to validate that kfence is working properly. This is
> > > used by ChromeOS integration tests to validate that kfence errors can be
> > > collected on user devices and parsed properly.
> >
> > This looks really good; thanks for adding this!
> >
> > >
> > > Signed-off-by: Stephen Boyd <swboyd@chromium.org>
> > > ---
> > >  drivers/misc/lkdtm/heap.c | 64 +++++++++++++++++++++++++++++++++++++++
> > >  1 file changed, 64 insertions(+)
> > >
> > > diff --git a/drivers/misc/lkdtm/heap.c b/drivers/misc/lkdtm/heap.c
> > > index 0ce4cbf6abda..608872bcc7e0 100644
> > > --- a/drivers/misc/lkdtm/heap.c
> > > +++ b/drivers/misc/lkdtm/heap.c
> > > @@ -4,6 +4,7 @@
> > >   * page allocation and slab allocations.
> > >   */
> > >  #include "lkdtm.h"
> > > +#include <linux/kfence.h>
> > >  #include <linux/slab.h>
> > >  #include <linux/vmalloc.h>
> > >  #include <linux/sched.h>
> > > @@ -132,6 +133,66 @@ static void lkdtm_READ_AFTER_FREE(void)
> > >       kfree(val);
> > >  }
> > >
> > > +#if IS_ENABLED(CONFIG_KFENCE)
> >
> > I really try hard to avoid having tests disappear depending on configs,
> > and instead report the expected failure case (as you have). Can this be
> > built without the IS_ENABLED() tests?
> >
>
> We need IS_ENABLED() for the kfence_sample_interval variable. I suppose
> if the config isn't set that variable can be assumed as zero and then
> the timeout would hit immediately. We can either define the name
> 'kfence_sample_interval' as 0 in the header, or put an ifdef in the
> function.

I think it's fair to put it in the kfence header, so you don't need
the #ifdefs in the test code.

We didn't think anyone should depend on kfence_sample_interval outside
KFENCE code, but probably only tests would anyway.

> ---8<---
> diff --git a/drivers/misc/lkdtm/heap.c b/drivers/misc/lkdtm/heap.c
> index 4f467d3972a6..574d0aa726dc 100644
> --- a/drivers/misc/lkdtm/heap.c
> +++ b/drivers/misc/lkdtm/heap.c
> @@ -138,6 +138,14 @@ static void lkdtm_KFENCE_READ_AFTER_FREE(void)
>         int *base, val, saw;
>         unsigned long timeout, resched_after;
>         size_t len = 1024;
> +       unsigned long interval;
> +
> +#ifdef CONFIG_KFENCE
> +       interval = kfence_sample_interval;
> +#else
> +       interval = 0;
> +#endif
> +
>         /*
>          * The slub allocator will use the either the first word or
>          * the middle of the allocation to store the free pointer,
> @@ -150,13 +158,13 @@ static void lkdtm_KFENCE_READ_AFTER_FREE(void)
>          * 100x the sample interval should be more than enough to ensure we get
>          * a KFENCE allocation eventually.
>          */
> -       timeout = jiffies + msecs_to_jiffies(100 * kfence_sample_interval);
> +       timeout = jiffies + msecs_to_jiffies(100 * interval);
>         /*
>          * Especially for non-preemption kernels, ensure the allocation-gate
>          * timer can catch up: after @resched_after, every failed allocation
>          * attempt yields, to ensure the allocation-gate timer is scheduled.
>          */
> -       resched_after = jiffies + msecs_to_jiffies(kfence_sample_interval);
> +       resched_after = jiffies + msecs_to_jiffies(interval);
>         do {
>                 base = kmalloc(len, GFP_KERNEL);
>                 if (!base) {
>
> ---8<----
> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> index 401af4757514..88100cc9caba 100644
> --- a/include/linux/kfence.h
> +++ b/include/linux/kfence.h
> @@ -223,6 +223,8 @@ bool __kfence_obj_info(struct kmem_obj_info *kpp,
> void *object, struct slab *sla
>
>  #else /* CONFIG_KFENCE */
>
> +#define kfence_sample_interval (0)
> +
>  static inline bool is_kfence_address(const void *addr) { return false; }
>  static inline void kfence_alloc_pool_and_metadata(void) { }
>  static inline void kfence_init(void) { }

Acked-by: Marco Elver <elver@google.com>

FWIW, I've occasionally been using repeatedly invoked READ_AFTER_FREE
to test if KFENCE is working. Having a dedicated test like this seems
more reliable though.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP9Koro2FKS9xG5LDvOvyRKrQBFkyKhJVSsqFJdEE%2BpeA%40mail.gmail.com.
