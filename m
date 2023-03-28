Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMNQROQQMGQEEHGWO5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1139.google.com (mail-yw1-x1139.google.com [IPv6:2607:f8b0:4864:20::1139])
	by mail.lfdr.de (Postfix) with ESMTPS id 490546CBE8F
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 14:06:11 +0200 (CEST)
Received: by mail-yw1-x1139.google.com with SMTP id 00721157ae682-54161af1984sf116353987b3.3
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 05:06:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680005170; cv=pass;
        d=google.com; s=arc-20160816;
        b=AXk1vFknp7WTG0zH5Zlwp6J2OjgC2DkG9VQY5D73vzTnRbHuVTYMH8e0IloSsYh+3N
         nSGPRNShOYgHakMa4fzQjY5Sdv84P86N/FXQvfYKKn9oH8SeyUnGbC0yRBMLtxDWwJg3
         KC1rAYDZ1FQXQ+4Rm+a1p5Z5m9uBwkhJnsTAzhV1nE9DxDD6Pc363lJXYz3vHka0Ifgd
         2WuY+HupbNSEHiF8yz5Cjbqzusjs6ZUPiPShCZ8fX779vI6QzkToAi9DO8+4o+KfLt6D
         5KfeNWn5ehehLmVZocb0jluCldUdGldfb84qF4J1p5tfVLQLege9DeIFM8yyJdABUgXs
         Ea/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=U5xLIFEPRCC8WICblfNyvZLeACdMebyTXZfHtaBHvBM=;
        b=jodi0zAgtyOg5eT/OcrocQBPt8JKGwVQQ4qYqrWJR+2qKZ12jp+oJR1h15nWQvFwW1
         VuXziIusQCuUXSynZf8Fvwewmkijk26ULI/d2+LNyKH6oMCsvLb8lvo6JZy8z9E2tG6y
         o48CVx0TDYMGi54x5tTawJalIJiZUy7m/USvW43EVD8Rh70wIAanZBOgpLR6iCoSPmla
         F3sxVWrx2GkpaNzphtjFh/NuG/GMwLWjar1oCkBOeAKKPTiNJtideMRhp54ZQLMSA+h2
         jlcYq+O2AZWZobYXej+1KAvCSFCKcjV3LBuKTb+f54kKLMRjbtIZXzAexCxXdJcUYTdE
         G9Iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tZa3WmFV;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680005170;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=U5xLIFEPRCC8WICblfNyvZLeACdMebyTXZfHtaBHvBM=;
        b=pb4KzdsJasMQlfHIq6iULASuFbThqpIeQhSXskF5Dcckya9ZMLmSS9To+3eiXhf3oj
         WTNKqz4/t5XLQ1BaK6GvDeFP8EcMqwNZItADv1TDaFLHY0VnyeT5fFHfQF73Hs4Imt9L
         f95eUnABRH1evPj5yBqXijVAnAxfkcqVvKwcWgApwM+I3BaRpw3OQOQZ3EEJpTO0tHXJ
         k2BDdgoWsNCR4Iu1A2thjOX+VVjMAGdWJpDSrON7ymnxQWoKF1jW7jr/G19S5/pmolt2
         qDS7a09Ha0t9NzkKQjkj4ogEYKFfjpxCc1HWaGb52L6uIoZzauCdWMk8dmJksMHJtjAb
         8fiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680005170;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=U5xLIFEPRCC8WICblfNyvZLeACdMebyTXZfHtaBHvBM=;
        b=JiZzH7E9ThK0aWmaF2ZOkk+DAHojy0aZ25qxRiH4yqbYADEw6md7v4tloOBX1aHI+Z
         GKOi2Br1Ivh1bvx3s8lLi7poQjNINvQf4DLu9bbdP4VxpG/jeLd8UJKymGPl9QSUwuOb
         tXIW2Vis4qtsxmFxDAxRtof4my0gIH8WPoCdRAJfWPfi/uNwQMYe3CogF1QXolXJKn8k
         nvvul2eP6eir4y9/BsukDmeJIxQj96IaVkQ+NP4ae/K+CxEiEHyR39zTTwPeKyl5as/J
         cF3NccivCjHAqKNeaJwi994M4i1hXkHkYHJMO9vWEr1skrG+LCEf94gRsqEQwybx7fAm
         eIrQ==
X-Gm-Message-State: AAQBX9elHFXpZsgxUVon8+yV8t9OBhNUb/o3M5tlUaXXFtjVl8bHTBUG
	LM3PK2LpOV7a4AarYW667bg=
X-Google-Smtp-Source: AKy350aMnH33+0wAIwRzPXhLc951z4AE4YcGLAWJa9gyzah747PzBLiBXeT976Qbii29EApF1bFEmQ==
X-Received: by 2002:a05:6902:168d:b0:b6d:1483:bc18 with SMTP id bx13-20020a056902168d00b00b6d1483bc18mr9450619ybb.7.1680005170187;
        Tue, 28 Mar 2023 05:06:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:180b:b0:b68:9d7b:e159 with SMTP id
 cf11-20020a056902180b00b00b689d7be159ls7628364ybb.4.-pod-prod-gmail; Tue, 28
 Mar 2023 05:06:09 -0700 (PDT)
X-Received: by 2002:a25:3416:0:b0:a5c:9509:8cea with SMTP id b22-20020a253416000000b00a5c95098ceamr12845950yba.28.1680005169394;
        Tue, 28 Mar 2023 05:06:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680005169; cv=none;
        d=google.com; s=arc-20160816;
        b=HC19xCk1W0vxF8WUVDLp48RPH3iAUOh5L7RMh8E/HrdkaANQZCnQ/Oc9bdk/NJjjyI
         yRmizL2kusgusVgQb3rrOSOsVkOMnAMcAK0+GQ3lFbZObN3MWuXi9z9+3V/BrPoHJ9gY
         wxXxVRWlOWeuCl1KWgTK0pUc8aprycb+dGQmP+PvAL4uVJSwm0uEvt8Jy8UmYqVG/sRJ
         mDFdvxxgvzw63zlnvGOUofuqLIqy8RPHOFJsGqWe0jW07fbjEgXNYqsD1Nbt+zid0dpo
         GkS+0VkTknaXw49INr2TpOo7G4twel1KAeBFpuurxxTGWN/ZTTKISiWIfy+7vTRRx0il
         xZ/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3nAcSUy1w+Q3o4Q/OHStFI724GxYk97V8A1XUu2jF9g=;
        b=fLCBxkkkAiICtyM4PoXkWOVjZ3+/Ts5gxt2OUvN7T0puDTmd5rxVUuBrOq0805xOwh
         nb0V2woJd1phVDGuEnj03qPwjir3HHONP+j63ZfK8pzRjiLZVpKyXdXh5BN61CXhCoxE
         ypJkYPkIIRMCmLwSkh/G/2g+7xM7i/q58XnTzf1B+uBQeyTkc9YNad3Itqfhl+Bs874g
         5nI6PeBeveDAmo0SQlbLpdlSm/XdGOYZXRxczwGyIOIeMvuDuhWao4T+7lkI5tLOCW4V
         DckNpYWCNtfBEBNo3nxFoVEEL5y2Gl9kGDUEG4SuhVfvCEG2qs9bpcxte984Jjr1rqXN
         WX3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tZa3WmFV;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id u92-20020a25ab65000000b00898c1f86550si1053658ybi.4.2023.03.28.05.06.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Mar 2023 05:06:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id i6so14691647ybu.8
        for <kasan-dev@googlegroups.com>; Tue, 28 Mar 2023 05:06:09 -0700 (PDT)
X-Received: by 2002:a25:5d7:0:b0:b67:8ad6:7529 with SMTP id
 206-20020a2505d7000000b00b678ad67529mr14054216ybf.65.1680005168914; Tue, 28
 Mar 2023 05:06:08 -0700 (PDT)
MIME-Version: 1.0
References: <20230328095807.7014-1-songmuchun@bytedance.com>
 <20230328095807.7014-2-songmuchun@bytedance.com> <CANpmjNP+nLfMKLj-4L4wXBfQpO5N0Y6q_TEkxjM+Z0WXxPvVxg@mail.gmail.com>
In-Reply-To: <CANpmjNP+nLfMKLj-4L4wXBfQpO5N0Y6q_TEkxjM+Z0WXxPvVxg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Mar 2023 14:05:32 +0200
Message-ID: <CANpmjNNXDHZGr_r6aZi1bv5itc5KvGhRNnq_CSQRrmB6Wwx+Dg@mail.gmail.com>
Subject: Re: [PATCH 1/6] mm: kfence: simplify kfence pool initialization
To: Muchun Song <songmuchun@bytedance.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	jannh@google.com, sjpark@amazon.de, muchun.song@linux.dev, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=tZa3WmFV;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as
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

On Tue, 28 Mar 2023 at 13:55, Marco Elver <elver@google.com> wrote:
>
> On Tue, 28 Mar 2023 at 11:58, Muchun Song <songmuchun@bytedance.com> wrote:
> >
> > There are three similar loops to initialize kfence pool, we could merge
> > all of them into one loop to simplify the code and make code more
> > efficient.
> >
> > Signed-off-by: Muchun Song <songmuchun@bytedance.com>
>
> Reviewed-by: Marco Elver <elver@google.com>
>
> > ---
> >  mm/kfence/core.c | 47 ++++++-----------------------------------------
> >  1 file changed, 6 insertions(+), 41 deletions(-)
> >
> > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > index 7d01a2c76e80..de62a84d4830 100644
> > --- a/mm/kfence/core.c
> > +++ b/mm/kfence/core.c
> > @@ -539,35 +539,10 @@ static void rcu_guarded_free(struct rcu_head *h)
> >  static unsigned long kfence_init_pool(void)
> >  {
> >         unsigned long addr = (unsigned long)__kfence_pool;
> > -       struct page *pages;
> >         int i;
> >
> >         if (!arch_kfence_init_pool())
> >                 return addr;
> > -
> > -       pages = virt_to_page(__kfence_pool);
> > -
> > -       /*
> > -        * Set up object pages: they must have PG_slab set, to avoid freeing
> > -        * these as real pages.
> > -        *
> > -        * We also want to avoid inserting kfence_free() in the kfree()
> > -        * fast-path in SLUB, and therefore need to ensure kfree() correctly
> > -        * enters __slab_free() slow-path.
> > -        */

Actually: can you retain this comment somewhere?

> > -       for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
> > -               struct slab *slab = page_slab(nth_page(pages, i));
> > -
> > -               if (!i || (i % 2))
> > -                       continue;
> > -
> > -               __folio_set_slab(slab_folio(slab));
> > -#ifdef CONFIG_MEMCG
> > -               slab->memcg_data = (unsigned long)&kfence_metadata[i / 2 - 1].objcg |
> > -                                  MEMCG_DATA_OBJCGS;
> > -#endif
> > -       }
> > -
> >         /*
> >          * Protect the first 2 pages. The first page is mostly unnecessary, and
> >          * merely serves as an extended guard page. However, adding one
> > @@ -581,8 +556,9 @@ static unsigned long kfence_init_pool(void)
> >                 addr += PAGE_SIZE;
> >         }
> >
> > -       for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
> > +       for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++, addr += 2 * PAGE_SIZE) {
> >                 struct kfence_metadata *meta = &kfence_metadata[i];
> > +               struct slab *slab = page_slab(virt_to_page(addr));
> >
> >                 /* Initialize metadata. */
> >                 INIT_LIST_HEAD(&meta->list);
> > @@ -593,26 +569,15 @@ static unsigned long kfence_init_pool(void)
> >
> >                 /* Protect the right redzone. */
> >                 if (unlikely(!kfence_protect(addr + PAGE_SIZE)))
> > -                       goto reset_slab;
> > -
> > -               addr += 2 * PAGE_SIZE;
> > -       }
> > -
> > -       return 0;
> > -
> > -reset_slab:
> > -       for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
> > -               struct slab *slab = page_slab(nth_page(pages, i));
> > +                       return addr;
> >
> > -               if (!i || (i % 2))
> > -                       continue;
> > +               __folio_set_slab(slab_folio(slab));
> >  #ifdef CONFIG_MEMCG
> > -               slab->memcg_data = 0;
> > +               slab->memcg_data = (unsigned long)&meta->objcg | MEMCG_DATA_OBJCGS;
> >  #endif
> > -               __folio_clear_slab(slab_folio(slab));
> >         }
> >
> > -       return addr;
> > +       return 0;
> >  }
> >
> >  static bool __init kfence_init_pool_early(void)
> > --
> > 2.11.0
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNXDHZGr_r6aZi1bv5itc5KvGhRNnq_CSQRrmB6Wwx%2BDg%40mail.gmail.com.
