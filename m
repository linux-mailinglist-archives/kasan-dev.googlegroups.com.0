Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEHMROQQMGQEKJGBUDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C1796CC1C5
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 16:13:38 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id ie7-20020a17090b400700b0023f06808981sf3332040pjb.8
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 07:13:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680012817; cv=pass;
        d=google.com; s=arc-20160816;
        b=u339HZx/Wa85rIwzvhhKk3i1lL8CNj0m0+y+zGOgE/c+VVS+x0nGVZpANL5ixK9u6v
         sfPm+bd57p+PMwQWeMwOAh3x9n9pVW03bM0JGWes2TdExzWeFMZ2zEvSvvr2EYG/YAkG
         J6xby+A3BCaABNUR6MwT1nOleO3RWgWB5nl5q4ZZSF3pnXMNYuCBd/zp2NEFfTtrxYde
         fmkHLzZA7VQS/JHL4do/NR+0fqolr9DfNmBe7NeU91osFi3twqBUsRMbaLO13rVp3aDv
         j9A7+qXjWleGgi0bgvvFSAqLxxj8fu0l6/SrRKz54Ybtbf7lqH7JMwAEDdnpfLNwBcQ3
         94eg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ghPFubvZA3U+79NcJzm3mIu6yqMPtOpO8nN90Sy5IQ4=;
        b=QTzu522fsVxOV/Tv2o/kqzLuMR8tdGkUfSshf5GPq3wqMOUV8f8EaZgo6m7aBDPR9h
         AETpLjSMB+xjjWVx3cze/ctywdpVddCpN9Axu92ef7+9naxPbDGGsRi1AubTCpragMXp
         YnVXcL7OIgEdEbTSb4++zdo1bxNAJhoVjqJmSkDjsmEB9tjfO8m0Wr/8eGKomXVa2KtT
         2PKe+wuHNYlF6UAAsZ4MRqY86uOYWHwIPpOaWcxnPHF4G1im04J+dDOJ5ncPwG5zPwA7
         5ZrKwCck8/7/AvxfacaWgT7oRuMkzK1FKyf/2MHAyZHKz+yWEbVUuV5BcFmb1s2yN+Vr
         2tLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZxRNUzUx;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680012817;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ghPFubvZA3U+79NcJzm3mIu6yqMPtOpO8nN90Sy5IQ4=;
        b=sE9Sqlm1Ekvp2mM6PdgU1xmXxNYJIgVHpTah+XM5cj6ESRxOeBpkXULKMnqMKHZTOG
         roHiCpruO2hqPMMNbpS+H+3GlIlLVthN8m25qBwKNiUPrTNCu1FRo43N7UY0bK4A0a2I
         7wb5i0laRhLwG+SEIL1qwHrLA3GUw56QR0MuI422JwrzsbBYD0bTv55nO0PGXn8yyHRz
         0qiLrlD7R+ozB8JtJcWMiJIY3kS7bpyiu5VgN5j8YD68Oba1q2ZD8bSbxiLFTRHBenXX
         5mr7giEC6gDSp5inhJ1jHFY7S4/XQwwLHvOYVMatecOz2iyqx1CfEYj8i6OF+8NJMYMJ
         b4NQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680012817;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=ghPFubvZA3U+79NcJzm3mIu6yqMPtOpO8nN90Sy5IQ4=;
        b=W7D/qfL2x3NAay8vYm8x8uTqKYVaGbJVtyLCaj7StOX9tGJ8BxqPS3Jpporbb/PwlU
         26o6QAVgUP6hWv57ioaPwhrS2VehJsx0/L/EuGmnIMkuZRRVJemUnT3fPxtulsiigpgD
         e2sdpGCrnaaFcrPmXFhCxzP4U/E5raxLuUjkapuKXL4RMGG8BHKFtVZmFHlyOO3IWHVo
         X/Zbr2s8zpksKyWAG4Yp6A2aTrcFLS0a5HigJI0X8+opb/CTkDeHqePXyDMjZt7kYtKM
         ZqsUhMghBpHkUEppiO3h3gi1cy7H94q1MZichuuW7MsKk4vZaZ/GgMn6ez4l+4YTeRo8
         b7mg==
X-Gm-Message-State: AAQBX9dxTciOPlPorBVCYg4tqxzTi8L0wHzblS5XgJk17TQ6abMLLPqa
	EW1E0Gtj2Sy3NftUN8YHTWg=
X-Google-Smtp-Source: AKy350bhImAijjSF21eKgsJprfhGv3eloY7IBKDDUtE7fjZNHdzq+BFOHXOvW76uGeDEXz7jhp5+rg==
X-Received: by 2002:a05:6a00:188f:b0:624:3ff:db10 with SMTP id x15-20020a056a00188f00b0062403ffdb10mr8344542pfh.5.1680012816917;
        Tue, 28 Mar 2023 07:13:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3c05:b0:23c:1f9b:df20 with SMTP id
 pb5-20020a17090b3c0500b0023c1f9bdf20ls10505952pjb.1.-pod-control-gmail; Tue,
 28 Mar 2023 07:13:36 -0700 (PDT)
X-Received: by 2002:a17:90a:1953:b0:240:973d:b431 with SMTP id 19-20020a17090a195300b00240973db431mr4481804pjh.42.1680012815959;
        Tue, 28 Mar 2023 07:13:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680012815; cv=none;
        d=google.com; s=arc-20160816;
        b=h8czy8yN/7OM8CXQkHy1k0h7aGxTkKqqA2kiRfQggrQJVegtRAMc3DB+6ZC9qtBYpX
         OIxOsE0LO9oXpQeTqRlwNMuDd7gE1VQvIzCm+qR3xM4aj8e9flMt8v+R+NarAkZYafp1
         OomX/sSCQQIhjpNmRHWYESVjmb7x2qmIKZfQxit5ITV4q4WK/mkDw8R/JwXktDpIv+pn
         /FyrGLHXhFbnc9xJUxU8nRVMRjnq/gUXq9WPoaQ1pxjqjVyh7dF8PCD4KBGDGu1u4tz7
         5WXODd9dJhR+VDGuj94EyRjYL0OC+Wm162JSWypv9tlAhnyEf4dzkC2+MKTl2bnKatbf
         +Z8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jzWLbAObXvnp3yLVMyDVLp9e3kaBgXUsN1mJJacdlX8=;
        b=toXq4ql0QUy3CXFpsSfeVlZ98KmFPqvlGIexEzy6Of9VM2vxo3J6NRMPurpEsYQco4
         fRJ4cPnKwsEvhfL1NEUDpnfVqeylDwTW9ozZA5PVC7WtqJGcC4ejV4nnGM+sw40855Bg
         CFMBd3RuAbwMPlxK3s3iywxw4Coh1JH9HTsnOizzt7oqb8+8e214mliVo3AShvpZvuDV
         nwHxQCkfV37yhWERadw9iTk2+qetNEBziuXF5ihfoYRx8zJheGSkE9QUm6FKI1dR1otn
         S40oSqz+RRJ+YnNX9Zt+wb/OxrePAhFByBdzgzCInhmsrPovd36yoVD7V+O4iKewXgkl
         ULFw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZxRNUzUx;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb30.google.com (mail-yb1-xb30.google.com. [2607:f8b0:4864:20::b30])
        by gmr-mx.google.com with ESMTPS id l9-20020a17090a4d4900b0023f6b97e8cdsi571091pjh.3.2023.03.28.07.13.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Mar 2023 07:13:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) client-ip=2607:f8b0:4864:20::b30;
Received: by mail-yb1-xb30.google.com with SMTP id p15so15191546ybl.9
        for <kasan-dev@googlegroups.com>; Tue, 28 Mar 2023 07:13:35 -0700 (PDT)
X-Received: by 2002:a25:1fc2:0:b0:b59:172a:eafa with SMTP id
 f185-20020a251fc2000000b00b59172aeafamr12664636ybf.17.1680012815308; Tue, 28
 Mar 2023 07:13:35 -0700 (PDT)
MIME-Version: 1.0
References: <20230328095807.7014-1-songmuchun@bytedance.com>
 <20230328095807.7014-6-songmuchun@bytedance.com> <CANpmjNPZxDYPYzEjr55ONydwH1FZF_Eh_gu7XKg=4-+HK6vL9Q@mail.gmail.com>
 <291FB0BF-F824-4ED9-B836-DA7773BFDA48@linux.dev>
In-Reply-To: <291FB0BF-F824-4ED9-B836-DA7773BFDA48@linux.dev>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Mar 2023 16:12:58 +0200
Message-ID: <CANpmjNOkf66ORysVrSZRXbRxoDQSg7kky6o0W+p0Jj_g10bJKQ@mail.gmail.com>
Subject: Re: [PATCH 5/6] mm: kfence: change kfence pool page layout
To: Muchun Song <muchun.song@linux.dev>
Cc: Muchun Song <songmuchun@bytedance.com>, glider@google.com, dvyukov@google.com, 
	akpm@linux-foundation.org, jannh@google.com, sjpark@amazon.de, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ZxRNUzUx;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b30 as
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

On Tue, 28 Mar 2023 at 15:33, Muchun Song <muchun.song@linux.dev> wrote:
>
>
>
> > On Mar 28, 2023, at 20:59, Marco Elver <elver@google.com> wrote:
> >
> > On Tue, 28 Mar 2023 at 11:58, 'Muchun Song' via kasan-dev
> > <kasan-dev@googlegroups.com> wrote:
> >>
> >> The original kfence pool layout (Given a layout with 2 objects):
> >>
> >> +------------+------------+------------+------------+------------+------------+
> >> | guard page | guard page |   object   | guard page |   object   | guard page |
> >> +------------+------------+------------+------------+------------+------------+
> >>                           |                         | |
> >>                           +----kfence_metadata[0]---+----kfence_metadata[1]---+
> >>
> >> The comment says "the additional page in the beginning gives us an even
> >> number of pages, which simplifies the mapping of address to metadata index".
> >>
> >> However, removing the additional page does not complicate any mapping
> >> calculations. So changing it to the new layout to save a page. And remmove
> >> the KFENCE_ERROR_INVALID test since we cannot test this case easily.
> >>
> >> The new kfence pool layout (Given a layout with 2 objects):
> >>
> >> +------------+------------+------------+------------+------------+
> >> | guard page |   object   | guard page |   object   | guard page |
> >> +------------+------------+------------+------------+------------+
> >> |                         |                         |
> >> +----kfence_metadata[0]---+----kfence_metadata[1]---+
> >>
> >> Signed-off-by: Muchun Song <songmuchun@bytedance.com>
> >> ---
> >> include/linux/kfence.h  |  8 ++------
> >> mm/kfence/core.c        | 40 ++++++++--------------------------------
> >> mm/kfence/kfence.h      |  2 +-
> >> mm/kfence/kfence_test.c | 14 --------------
> >> 4 files changed, 11 insertions(+), 53 deletions(-)
> >>
> >> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> >> index 726857a4b680..25b13a892717 100644
> >> --- a/include/linux/kfence.h
> >> +++ b/include/linux/kfence.h
> >> @@ -19,12 +19,8 @@
> >>
> >> extern unsigned long kfence_sample_interval;
> >>
> >> -/*
> >> - * We allocate an even number of pages, as it simplifies calculations to map
> >> - * address to metadata indices; effectively, the very first page serves as an
> >> - * extended guard page, but otherwise has no special purpose.
> >> - */
> >> -#define KFENCE_POOL_SIZE ((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_SIZE)
> >> +/* The last page serves as an extended guard page. */
> >
> > The last page is just a normal guard page? I.e. the last 2 pages are:
> > <object page> | <guard page>
>
> Right.
>
> The new kfence pool layout (Given a layout with 2 objects):
>
> +------------+------------+------------+------------+------------+
> | guard page |   object   | guard page |   object   | guard page |
> +------------+------------+------------+------------+------------+
> |                         |                         |     ^
> +----kfence_metadata[0]---+----kfence_metadata[1]---+     |
>                                                           |
>                                                           |
>                                                      the last page
>
> >
> > Or did I misunderstand?
> >
> >> +#define KFENCE_POOL_SIZE       ((CONFIG_KFENCE_NUM_OBJECTS * 2 + 1) * PAGE_SIZE)
> >> extern char *__kfence_pool;
> >>
> >> DECLARE_STATIC_KEY_FALSE(kfence_allocation_key);
> >> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> >> index 41befcb3b069..f205b860f460 100644
> >> --- a/mm/kfence/core.c
> >> +++ b/mm/kfence/core.c
> >> @@ -240,24 +240,7 @@ static inline void kfence_unprotect(unsigned long addr)
> >>
> >> static inline unsigned long metadata_to_pageaddr(const struct kfence_metadata *meta)
> >> {
> >> -       unsigned long offset = (meta - kfence_metadata + 1) * PAGE_SIZE * 2;
> >> -       unsigned long pageaddr = (unsigned long)&__kfence_pool[offset];
> >> -
> >> -       /* The checks do not affect performance; only called from slow-paths. */
> >> -
> >> -       /* Only call with a pointer into kfence_metadata. */
> >> -       if (KFENCE_WARN_ON(meta < kfence_metadata ||
> >> -                          meta >= kfence_metadata + CONFIG_KFENCE_NUM_OBJECTS))
> >> -               return 0;
> >
> > Could we retain this WARN_ON? Or just get rid of
> > metadata_to_pageaddr() altogether, because there's only 1 use left and
> > the function would now just be a simple ALIGN_DOWN() anyway.
>
> I'll inline this function to its caller since the warning is unlikely.
>
> >
> >> -       /*
> >> -        * This metadata object only ever maps to 1 page; verify that the stored
> >> -        * address is in the expected range.
> >> -        */
> >> -       if (KFENCE_WARN_ON(ALIGN_DOWN(meta->addr, PAGE_SIZE) != pageaddr))
> >> -               return 0;
> >> -
> >> -       return pageaddr;
> >> +       return ALIGN_DOWN(meta->addr, PAGE_SIZE);
> >> }
> >>
> >> /*
> >> @@ -535,34 +518,27 @@ static void kfence_init_pool(void)
> >>        unsigned long addr = (unsigned long)__kfence_pool;
> >>        int i;
> >>
> >> -       /*
> >> -        * Protect the first 2 pages. The first page is mostly unnecessary, and
> >> -        * merely serves as an extended guard page. However, adding one
> >> -        * additional page in the beginning gives us an even number of pages,
> >> -        * which simplifies the mapping of address to metadata index.
> >> -        */
> >> -       for (i = 0; i < 2; i++, addr += PAGE_SIZE)
> >> -               kfence_protect(addr);
> >> -
> >>        for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++, addr += 2 * PAGE_SIZE) {
> >>                struct kfence_metadata *meta = &kfence_metadata[i];
> >> -               struct slab *slab = page_slab(virt_to_page(addr));
> >> +               struct slab *slab = page_slab(virt_to_page(addr + PAGE_SIZE));
> >>
> >>                /* Initialize metadata. */
> >>                INIT_LIST_HEAD(&meta->list);
> >>                raw_spin_lock_init(&meta->lock);
> >>                meta->state = KFENCE_OBJECT_UNUSED;
> >> -               meta->addr = addr; /* Initialize for validation in metadata_to_pageaddr(). */
> >> +               meta->addr = addr + PAGE_SIZE;
> >>                list_add_tail(&meta->list, &kfence_freelist);
> >>
> >> -               /* Protect the right redzone. */
> >> -               kfence_protect(addr + PAGE_SIZE);
> >> +               /* Protect the left redzone. */
> >> +               kfence_protect(addr);
> >>
> >>                __folio_set_slab(slab_folio(slab));
> >> #ifdef CONFIG_MEMCG
> >>                slab->memcg_data = (unsigned long)&meta->objcg | MEMCG_DATA_OBJCGS;
> >> #endif
> >>        }
> >> +
> >> +       kfence_protect(addr);
> >> }
> >>
> >> static bool __init kfence_init_pool_early(void)
> >> @@ -1043,7 +1019,7 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
> >>
> >>        atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);
> >>
> >> -       if (page_index % 2) {
> >> +       if (page_index % 2 == 0) {
> >>                /* This is a redzone, report a buffer overflow. */
> >>                struct kfence_metadata *meta;
> >>                int distance = 0;
> >> diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
> >> index 600f2e2431d6..249d420100a7 100644
> >> --- a/mm/kfence/kfence.h
> >> +++ b/mm/kfence/kfence.h
> >> @@ -110,7 +110,7 @@ static inline struct kfence_metadata *addr_to_metadata(unsigned long addr)
> >>         * __kfence_pool, in which case we would report an "invalid access"
> >>         * error.
> >>         */
> >> -       index = (addr - (unsigned long)__kfence_pool) / (PAGE_SIZE * 2) - 1;
> >> +       index = (addr - (unsigned long)__kfence_pool) / (PAGE_SIZE * 2);
> >>        if (index < 0 || index >= CONFIG_KFENCE_NUM_OBJECTS)
> >>                return NULL;
> >
> > Assume there is a right OOB that hit the last guard page. In this case
> >
> >  addr >= __kfence_pool + (NUM_OBJECTS * 2 * PAGE_SIZE) && addr <
> > __kfence_pool + POOL_SIZE
> >
> > therefore
> >
> >  index >= (NUM_OBJECTS * 2 * PAGE_SIZE) / (PAGE_SIZE * 2) && index <
> > POOL_SIZE / (PAGE_SIZE * 2)
> >  index == NUM_OBJECTS
> >
> > And according to the above comparison, this will return NULL and
> > report KFENCE_ERROR_INVALID, which is wrong.
>
> Look at kfence_handle_page_fault(), which first look up "addr - PAGE_SIZE" (passed
> to addr_to_metadata()) and then look up "addr + PAGE_SIZE", the former will not
> return NULL, the latter will return NULL. So kfence will report KFENCE_ERROR_OOB
> in this case, right? Or what I missed here?

Yes, you're right.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOkf66ORysVrSZRXbRxoDQSg7kky6o0W%2Bp0Jj_g10bJKQ%40mail.gmail.com.
