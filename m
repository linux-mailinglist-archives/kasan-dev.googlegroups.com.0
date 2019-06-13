Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEUGRHUAKGQEQADUDWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 74E1F435F4
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 14:35:31 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id s195sf13757452pgs.13
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 05:35:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560429330; cv=pass;
        d=google.com; s=arc-20160816;
        b=0Da+5dVEONIAFxPrNlQuaZOBFvPGjJBa+Mf07BHQLd3nW5Y3gi0pAL2Uqonyju2s4m
         StHmyLbvZNsnostELCIOpjWlIrOI4smBLenrCIQ0xGB2jADKuYHuHKEiszviB84Rir4M
         wZ79re5UNQEtv0Z2OW0qXGM+HLA4MVbImAVRr7HNhSBHlZE/IHBJGPww/KFU9J27w8oX
         P9JfGaxZYnS/nHUC2LGycaKz9Gs57SaHpfmY0DVqMppHa4nGDTdt72TvcYARytdRhaLn
         BhjqfcReichaOAZrz/FVp0s3s8i9NSGj/Wbs3gcGvDVRzop/kBg5OwelI+03s3xJajWs
         msQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=MCz1faEzoP//byETPIvdgq6Hm5WFRHu/f9qTlxjxkvQ=;
        b=DRklebVOC8BQe8kvYhCweyuSNTQfrT1vKWumtk8fFpRiRoDXHV7jGmoe8dR29Yawps
         sryb79P87Lyfh14YSvTp7jPkdzfhyroZhHsk0y1gZ07EdTWg9zdPZ0vG/KwVWYWP02zj
         aksvdr4agN5eJzcBupTPoXYlF/Oz8G5LgH13EtR0TPkITDE54Tgjn/pJnsnHPUpTa6EH
         Xdrv9pUiHlPBg2nRLrJi4JU9nlsVfDO9ed19V9exknhiyLaettRNSB8VipSHylvFc0BX
         IWC3FNAGMQU0HMtdYLpo3l9crUA/Hba6ZxzWjesh6ekxrUeoezVvBdpPofIz7fB8SIRE
         nx7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bHlwS3VP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MCz1faEzoP//byETPIvdgq6Hm5WFRHu/f9qTlxjxkvQ=;
        b=EOX9RSIho7UDL3qoxuwhPii82Vkot9S7HlJOVjioqh+tIyHvV+8RCuwiOIDHOKC9yQ
         AalT3NUwYrOCtH7oDM7xhPWG1jMAYH1GWxWjArqYTpc54UWIdzYzCtPsg5zNwIPt+zi5
         /bv63Ps4UkidgiOmxrYljC2Dp9fnAL2hbEi0udo808mN9V01Dk9LGTphuUWIi3G2OROY
         bXMORicoHvabX09VTN3ai0EcqyBIroDBGBjx+47BLfoxRQcbE/Fob+P+NCV7c8STRtPL
         ifaJBAOUnc+XJNupAfAStExrHa6iflKXfRYmmiz9alOJkSfPh7mrRxfkdXuxwvwH6bRj
         EXug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MCz1faEzoP//byETPIvdgq6Hm5WFRHu/f9qTlxjxkvQ=;
        b=fwlemAhgpxlWWtk4w347tCfG0CLjRtD6J8TxTWiwP+56tGP2PS0AqdFrVauVlfyy7h
         W10AIKq0Og+HduRguXsQlFCpq7J71y3jMEIx44WcZ0/W4eIxKeNNKSjmew1V/ug+nhk1
         qqhSSlQUdZ3SJ1xYJTjHSZYLmbqPZnTNveheUMTrPpH9mw+kh0OIyrRYTXIpuJNiu8+m
         m6OPILAHghl3tbpE282UiAG+P+LCUQsqs16ca2hVjnZ0c/XtiG4szDJBJhpVGOB9YT8X
         VIA16CzjDcdGJUUBbLtU+dpbLJq6aUXboZZLfCV6VITBInxJupAaSMniFM3riBFoKSVe
         81fA==
X-Gm-Message-State: APjAAAVyy6GTGZovMLE4Na4nfj9LDpb1yXsQIlly5aTjxncMeGLmpYiZ
	vOzi5yMcgzjZP5JIs5V3djI=
X-Google-Smtp-Source: APXvYqyz5XzCVfhpzwajFCw3jf1Utew5ZVDxTdV6W4OPOe7YfwoWQvKTWChs+wR/QGuvE06PNxoEfA==
X-Received: by 2002:a17:902:a506:: with SMTP id s6mr13085716plq.87.1560429330138;
        Thu, 13 Jun 2019 05:35:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:cc0e:: with SMTP id x14ls1238773pgf.6.gmail; Thu, 13 Jun
 2019 05:35:29 -0700 (PDT)
X-Received: by 2002:aa7:86c6:: with SMTP id h6mr56131149pfo.51.1560429329783;
        Thu, 13 Jun 2019 05:35:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560429329; cv=none;
        d=google.com; s=arc-20160816;
        b=yNMpu2UXiRWy4z6dEtej2cufyZOD/eVLJJkSRYXEfnbbQb+rQqgI6gM3EYED9ZGDT+
         e6HmuqGrcyveb+NAhICez1kUH5ynLMHRE4UQ/3DzaGCl6ucKGNlNbXyxhU8vXymT6eSo
         Sl4FAHSKX29H/GW6GbvnFWeVNv3KqMG9BRSaMhT02nPUgPoyK7RwSrPxZGXL+tM/WKhZ
         3EF37dYwdbX6SqyVlvh161AFIO+xJRi+rtOCNiL7cOicG5qc//Ll7WhaI1KLkshsfZLq
         RqCNgBg/9tYStEPB/0wwQIhmK+fVkAzQTKIoDJEeiGTokeIKV5YWFAfAnVnh68nolKT0
         egjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=odgDtuS4Pz09+zc7wgiVUlzZ7gbjNw0joU36SILLNfo=;
        b=PomAoxaFe5QwzEgspgs0Orja8Vy6xvdNI9KhKT+HrRSOtmCUIPJCDPpQDq3hZyHOnw
         PJxlNj7bLfjngfP3gcjva7+KizA7NG0a6BEABnZpE0kaq/2tZlOJRkJ7xq4d7DtZUB/d
         2DI0/VyI3hIQOLiu0lYGm+hEGws7jmehK8rnNwy7J0NoNOZbsIw0072bY1VJpqPzZC6m
         5sc/2XJVjn7Gpc2hlcvy8iJAn1emrY0uU67VfdYkBtHmfLp9b8fBcqz6skBRA3ZjLkuQ
         xX47pMSY8DW65bN0WimaxSdD3/sBgKLhtX9AUPVM6EU/yq6FyDTusTm0bv2yPG1G3YkC
         qSdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bHlwS3VP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id s125si170280pgs.1.2019.06.13.05.35.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2019 05:35:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id m206so14251205oib.12
        for <kasan-dev@googlegroups.com>; Thu, 13 Jun 2019 05:35:29 -0700 (PDT)
X-Received: by 2002:aca:530f:: with SMTP id h15mr2627831oib.155.1560429328714;
 Thu, 13 Jun 2019 05:35:28 -0700 (PDT)
MIME-Version: 1.0
References: <20190531150828.157832-1-elver@google.com> <20190531150828.157832-2-elver@google.com>
 <5c35bc08-749f-dbc4-09d0-fcf14b1da1b3@virtuozzo.com>
In-Reply-To: <5c35bc08-749f-dbc4-09d0-fcf14b1da1b3@virtuozzo.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 13 Jun 2019 14:35:17 +0200
Message-ID: <CANpmjNNz8-dfnSXGouHQJqg+zBHJWVPmCM9Ggxj_LAb4VeOocg@mail.gmail.com>
Subject: Re: [PATCH v3 1/3] lib/test_kasan: Add bitops tests
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, "H. Peter Anvin" <hpa@zytor.com>, Jonathan Corbet <corbet@lwn.net>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"the arch/x86 maintainers" <x86@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Josh Poimboeuf <jpoimboe@redhat.com>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	linux-arch <linux-arch@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bHlwS3VP;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
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

Thanks, I've sent v4.

On Thu, 13 Jun 2019 at 12:49, Andrey Ryabinin <aryabinin@virtuozzo.com> wrote:
>
>
>
> On 5/31/19 6:08 PM, Marco Elver wrote:
> > This adds bitops tests to the test_kasan module. In a follow-up patch,
> > support for bitops instrumentation will be added.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> > Changes in v3:
> > * Use kzalloc instead of kmalloc.
> > * Use sizeof(*bits).
> >
> > Changes in v2:
> > * Use BITS_PER_LONG.
> > * Use heap allocated memory for test, as newer compilers (correctly)
> >   warn on OOB stack access.
> > ---
> >  lib/test_kasan.c | 75 ++++++++++++++++++++++++++++++++++++++++++++++--
> >  1 file changed, 72 insertions(+), 3 deletions(-)
> >
> > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > index 7de2702621dc..1ef9702327d2 100644
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -11,16 +11,17 @@
> >
> >  #define pr_fmt(fmt) "kasan test: %s " fmt, __func__
> >
> > +#include <linux/bitops.h>
> >  #include <linux/delay.h>
> > +#include <linux/kasan.h>
> >  #include <linux/kernel.h>
> > -#include <linux/mman.h>
> >  #include <linux/mm.h>
> > +#include <linux/mman.h>
> > +#include <linux/module.h>
> >  #include <linux/printk.h>
> >  #include <linux/slab.h>
> >  #include <linux/string.h>
> >  #include <linux/uaccess.h>
> > -#include <linux/module.h>
> > -#include <linux/kasan.h>
> >
> >  /*
> >   * Note: test functions are marked noinline so that their names appear in
> > @@ -623,6 +624,73 @@ static noinline void __init kasan_strings(void)
> >       strnlen(ptr, 1);
> >  }
> >
> > +static noinline void __init kasan_bitops(void)
> > +{
> > +     long *bits = kzalloc(sizeof(*bits), GFP_KERNEL);
>
> It would be safer to do kzalloc(sizeof(*bits) + 1, GFP_KERNEL) and change tests accordingly to: set_bit(BITS_PER_LONG + 1, bits) ...
> kmalloc will internally round up allocation to 16-bytes, so we won't be actually corrupting someone elses memory.
>
>
> > +     if (!bits)
> > +             return;
> > +
> > +     pr_info("within-bounds in set_bit");
> > +     set_bit(0, bits);
> > +
> > +     pr_info("within-bounds in set_bit");
> > +     set_bit(BITS_PER_LONG - 1, bits);
>
>
> I'd remove these two. There are plenty of within bounds set_bit() in the kernel so they are well tested already.
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To post to this group, send email to kasan-dev@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5c35bc08-749f-dbc4-09d0-fcf14b1da1b3%40virtuozzo.com.
> For more options, visit https://groups.google.com/d/optout.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNz8-dfnSXGouHQJqg%2BzBHJWVPmCM9Ggxj_LAb4VeOocg%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
