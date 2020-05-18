Return-Path: <kasan-dev+bncBDGPTM5BQUDRBQESRL3AKGQEHSPDU5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 8386F1D795C
	for <lists+kasan-dev@lfdr.de>; Mon, 18 May 2020 15:10:25 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id s8sf11332980ybj.9
        for <lists+kasan-dev@lfdr.de>; Mon, 18 May 2020 06:10:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589807424; cv=pass;
        d=google.com; s=arc-20160816;
        b=vNU6hDlQVuujBKh6tkvbgEY5Tzfc2VrPWpQEzWJKBUEtPwu2gREjIUQBL31nU7oTqT
         1b3OmiHk5kSrjeNR8DalI1DwBPr1KgK/2ryuaCiX5zvzxD1NVD4OXOmK18w6bdkr9hfs
         8R9J6Kmxa/D9QEYjSTNOk77LrzlK4GmFMEgZlgvLgZ/+E6n71o4vGfZRqDcAeYPrBgk0
         aDDm0ers6Z8fFZNl6mt3AhQ7T21vJscPzaTe24/uKEhspyAW3clgn3TejBwSs4waoXqF
         dlI7jLeRXX/p+zTK0vWv3AP94FCByN9fKjXCRDfNgxPyKjDm9woDaKC7/yK9oi11AWdk
         4gqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=bbhzphyCVcCUpyPevNP+GBGfy+PhQNrK/7EXfhQst6U=;
        b=MJwlyeyHWWis4PutWFWrymH25fLQZlwnDgLLrbRhhGGE+6X1N7q5hJoORzYbL9Z1wC
         puR4ZpSI5hNAsxnIsWP5gict7HVhhLY9knOpYE/zGjSNaR1PzTvcwTpYzB61PNEFUpnt
         vWuu8/yfpcYQVPWZHyGyTslzhUDbQPNkA5GKNRMUzx1Aysij812L9o+eTmfY8+frfEMt
         d/9+8HeJmyB/H3xn6T8ogtV84ehRsSRMWcHUjG8d/kgIzWdgmwBaMde58dNDc2sHD4lu
         aRRLBJSMb+q/xgDENHx0yTYsOjdmbU6p56hBp2cLAeNOS78P/pYjxmB/Ku7gRqMFgu1N
         PP2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=nazVbV5F;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bbhzphyCVcCUpyPevNP+GBGfy+PhQNrK/7EXfhQst6U=;
        b=KwadcMLoob5OCiHT36UTn21zQTLhq+v9hRS2lpQrKzchRWGe6PQRi0SN/gEEcf6QnU
         W5szs8xAwUvwlV6LKS8N5pmPVYGP3JoAbKmo429l4Dy0oS9EJiVi3fQVawpjWBiy2+jt
         FGr2+6y69OXbAuzTV8awksdKc/5gOfxEopgcSqZyHitPXDg6FYVhJkuhm1B2hC/eT8Qy
         M8EzWu0ZhzdQuiyEZwCk2vFIvWyMqZY0Hcr8DUoR3oaJZVA4nFjijoG2Xg9A3coZ/nT/
         R3Yop5sNfgu8IIjtI6t+Ihaou8Lcw1aEIRNPB3FtHLA4ZR6IzZ+Bs/AFagj/vkbdIkWR
         t1lw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bbhzphyCVcCUpyPevNP+GBGfy+PhQNrK/7EXfhQst6U=;
        b=q1F0+W4BemtgdYkldZLGbmxiOsLDrSQNxhZRp8TJLzNpKwREzwokENsSI521vdLD0e
         2SnU/LkCkEjVMhxEAotf8npE3J2EMy1r785Z7UhlAVN4NwRGtSSAfEkDU5I8aqNiYpsg
         azdKXY9UEam/tqaNZHgtM8AKE2mbwfrUpWSDTbKz2ZXkL0P1QsC6rINfH+gomNItqIp5
         Sd8d2zylqyBo/Eg9vJIPOmsjVZaf6deteMGe1JIoZJAQB3Q2YBN9xYsXCnCRWxArjhpq
         B2VbaeQtbp0pjNU4YwaohBQocvanxA3WB4lqFpts7M1d8audnDV24mFVGQqixrTYoHbY
         UnYA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530hN9pJvTB2wiJg6ReispIvgOwcExq6r/j4TZ3F9G59SiRvj0Ne
	J1bcqgk8w8fLULV3d7zIQOE=
X-Google-Smtp-Source: ABdhPJwBqFL5FHuujaefbIy5/Kee83xVL8OtkB0fqbgkzeEbR+RZ0Gyd+iDlh2mv4xso3kFCKnTINw==
X-Received: by 2002:a25:ce08:: with SMTP id x8mr24238740ybe.495.1589807424200;
        Mon, 18 May 2020 06:10:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:824a:: with SMTP id d10ls3558095ybn.10.gmail; Mon, 18
 May 2020 06:10:23 -0700 (PDT)
X-Received: by 2002:a25:4455:: with SMTP id r82mr26943023yba.213.1589807423723;
        Mon, 18 May 2020 06:10:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589807423; cv=none;
        d=google.com; s=arc-20160816;
        b=mcTsbyLpccr41KBVuvoqLmKvtF3O/oMZCHaE/Xo6Ls3jK+qVarQq/eedxLJQjrK2fO
         gvdDziQSF4e5nA7NyaU3NWw1eqXhiQ3/wAcuOqiDNcHVCuDidiVW8K5fU2u3rQ7SAo+/
         JvankelkSsCxjA2dOfmkr5b41UF+uA5frHk4P4jGZQxWOFmMBnXFTbl30F4fY3wLGFEy
         H345XVUZ+Ur/1lEDHA2uorJTe44n6jXKU6w7xSy9IgU6paG5PeCQKM2H3dl2fTvETts9
         c1AxVh+bzBUcGoL7mO2EPgDmOBU+NgFD+VVyLDi8R+zu2lIjxWaBZ6hNVxuy3ckzw7Fo
         eung==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=NW+oKNdt91ijVvJ9s3UwA40pv/oGY7fZyF/xj9NBb9w=;
        b=rW7+9SCjBYD6VHZJeZ1xLXXjgGNgvLt1M4KYXi1JtC80eqowXkXuKmauYUOPlx658e
         jzgryKkkgBIvErfew8QdGw9E4Kio+lk++NpfnJDJstSds3+p98nt7ptkNKw0Wau5PGdv
         30e4cQGPVdbWNREVqQH8T+rCCOAzfeqG8Qi2GNzTNpfE7c00p6l4jYMEgdJbx8AnGT2q
         4k+DJyhWFCWGSPkZZ+SAuU/4/ZElwLvkN2/sbnta0JrBOOaIGWKZ5Du20nLQqPmvHLXn
         V1z6MQOvlK+i22cMwYzjCj/IaZYUM2LkLPXyCujmmM46Lq3ojangHrfNfCeMyDf0qgQ9
         TVYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=nazVbV5F;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id a83si453147yba.1.2020.05.18.06.10.21
        for <kasan-dev@googlegroups.com>;
        Mon, 18 May 2020 06:10:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 78cbdd3fd21d4a3b99d00954036d1df4-20200518
X-UUID: 78cbdd3fd21d4a3b99d00954036d1df4-20200518
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1463277731; Mon, 18 May 2020 21:10:17 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 18 May 2020 21:10:12 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 18 May 2020 21:10:12 +0800
Message-ID: <1589807413.16436.21.camel@mtksdccf07>
Subject: Re: [PATCH v3 2/4] kasan: record and print the free track
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, kasan-dev
	<kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, LKML
	<linux-kernel@vger.kernel.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>
Date: Mon, 18 May 2020 21:10:13 +0800
In-Reply-To: <1589801235.16436.12.camel@mtksdccf07>
References: <20200518062730.4665-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+YVF2cLdg6qaK+3NcU3kLz2Pys6NWxLAYfity5n5cjirA@mail.gmail.com>
	 <1589801235.16436.12.camel@mtksdccf07>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: F824AAD9ABEE6A42A165D6B8C07B30E91472DB191E4C6F015040541E8A42C3D72000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=nazVbV5F;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Mon, 2020-05-18 at 19:27 +0800, Walter Wu wrote:
> On Mon, 2020-05-18 at 12:18 +0200, Dmitry Vyukov wrote:
> > On Mon, May 18, 2020 at 8:27 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > >
> > > Move free track from slub alloc meta-data to slub free meta-data in
> > > order to make struct kasan_free_meta size is 16 bytes. It is a good
> > > size because it is the minimal redzone size and a good number of
> > > alignment.
> > >
> > > For free track in generic KASAN, we do the modification in struct
> > > kasan_alloc_meta and kasan_free_meta:
> > > - remove free track from kasan_alloc_meta.
> > > - add free track into kasan_free_meta.
> > >
> > > [1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
> > >
> > > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> > > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > > Cc: Dmitry Vyukov <dvyukov@google.com>
> > > Cc: Alexander Potapenko <glider@google.com>
> > > ---
> > >  mm/kasan/common.c  | 33 ++++++++++-----------------------
> > >  mm/kasan/generic.c | 18 ++++++++++++++++++
> > >  mm/kasan/kasan.h   |  7 +++++++
> > >  mm/kasan/report.c  | 20 --------------------
> > >  mm/kasan/tags.c    | 37 +++++++++++++++++++++++++++++++++++++
> > >  5 files changed, 72 insertions(+), 43 deletions(-)
> > >
> > > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > > index 8bc618289bb1..6500bc2bb70c 100644
> > > --- a/mm/kasan/common.c
> > > +++ b/mm/kasan/common.c
> > > @@ -51,7 +51,7 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags)
> > >         return stack_depot_save(entries, nr_entries, flags);
> > >  }
> > >
> > > -static inline void set_track(struct kasan_track *track, gfp_t flags)
> > > +void kasan_set_track(struct kasan_track *track, gfp_t flags)
> > >  {
> > >         track->pid = current->pid;
> > >         track->stack = kasan_save_stack(flags);
> > > @@ -249,9 +249,7 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> > >         *size += sizeof(struct kasan_alloc_meta);
> > >
> > >         /* Add free meta. */
> > > -       if (IS_ENABLED(CONFIG_KASAN_GENERIC) &&
> > > -           (cache->flags & SLAB_TYPESAFE_BY_RCU || cache->ctor ||
> > > -            cache->object_size < sizeof(struct kasan_free_meta))) {
> > > +       if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> > 
> > Why do we need to increase object size unconditionally?
> > We only store info in free track when the object is free, so I would
> > assume we still can generally overlap free track and the object
> > itself. We store free track at the same time we use the quarantine
> > link, and the quarantine link was overlapped with the object just
> > fine.
> > With this change we indeed increase object size, which we do not want
> > in general.
> > 
> 
> If it doesn't add free meta, but we always store free track into the
> object, Is it safe?
> 
> > 
> > >                 cache->kasan_info.free_meta_offset = *size;
> > >                 *size += sizeof(struct kasan_free_meta);
> > >         }
> > > @@ -299,24 +297,6 @@ struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
> > >         return (void *)object + cache->kasan_info.free_meta_offset;
> > >  }
> > >
> > > -
> > > -static void kasan_set_free_info(struct kmem_cache *cache,
> > > -               void *object, u8 tag)
> > > -{
> > > -       struct kasan_alloc_meta *alloc_meta;
> > > -       u8 idx = 0;
> > > -
> > > -       alloc_meta = get_alloc_info(cache, object);
> > > -
> > > -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > > -       idx = alloc_meta->free_track_idx;
> > > -       alloc_meta->free_pointer_tag[idx] = tag;
> > > -       alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
> > > -#endif
> > > -
> > > -       set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
> > > -}
> > > -
> > >  void kasan_poison_slab(struct page *page)
> > >  {
> > >         unsigned long i;
> > > @@ -396,6 +376,13 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
> > >         alloc_info = get_alloc_info(cache, object);
> > >         __memset(alloc_info, 0, sizeof(*alloc_info));
> > >
> > > +       if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> > > +               struct kasan_free_meta *free_info;
> > > +
> > > +               free_info = get_free_info(cache, object);
> > > +               __memset(free_info, 0, sizeof(*free_info));
> > 
> > If we overlap free track with object, this will not be needed as well, right?
> > 

I thought about it, I think you are right, because the free track must
be stored when object is free, so even don't clean this meta data. It
doesn't matter.

Thanks for your review. If there are no other problems, I will send next
patch. 

Thanks.


> 
> Should we not consider those objects which have adding free meta? If
> they exist, then we should init their meta data when object re-allocate.
> 
> struct kasan_free_meta {
>     struct qlist_node quarantine_link;
>     struct kasan_track free_track;
> };
> 
> 
> > > +       }
> > > +
> > >         if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> > >                 object = set_tag(object,
> > >                                 assign_tag(cache, object, true, false));
> > > @@ -492,7 +479,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
> > >                 KASAN_KMALLOC_REDZONE);
> > >
> > >         if (cache->flags & SLAB_KASAN)
> > > -               set_track(&get_alloc_info(cache, object)->alloc_track, flags);
> > > +               kasan_set_track(&get_alloc_info(cache, object)->alloc_track, flags);
> > >
> > >         return set_tag(object, tag);
> > >  }
> > > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > > index 78d8e0a75a8a..988bc095b738 100644
> > > --- a/mm/kasan/generic.c
> > > +++ b/mm/kasan/generic.c
> > > @@ -345,3 +345,21 @@ void kasan_record_aux_stack(void *addr)
> > >                 alloc_info->rcu_stack[1] = alloc_info->rcu_stack[0];
> > >         alloc_info->rcu_stack[0] = kasan_save_stack(GFP_NOWAIT);
> > >  }
> > > +
> > > +void kasan_set_free_info(struct kmem_cache *cache,
> > > +                               void *object, u8 tag)
> > > +{
> > > +       struct kasan_free_meta *free_meta;
> > > +
> > > +       free_meta = get_free_info(cache, object);
> > > +       kasan_set_track(&free_meta->free_track, GFP_NOWAIT);
> > > +}
> > > +
> > > +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > > +                               void *object, u8 tag)
> > > +{
> > > +       struct kasan_free_meta *free_meta;
> > > +
> > > +       free_meta = get_free_info(cache, object);
> > > +       return &free_meta->free_track;
> > > +}
> > > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > > index 870c5dd07756..87ee3626b8b0 100644
> > > --- a/mm/kasan/kasan.h
> > > +++ b/mm/kasan/kasan.h
> > > @@ -127,6 +127,9 @@ struct kasan_free_meta {
> > >          * Otherwise it might be used for the allocator freelist.
> > >          */
> > >         struct qlist_node quarantine_link;
> > > +#ifdef CONFIG_KASAN_GENERIC
> > > +       struct kasan_track free_track;
> > > +#endif
> > >  };
> > >
> > >  struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
> > > @@ -168,6 +171,10 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
> > >  struct page *kasan_addr_to_page(const void *addr);
> > >
> > >  depot_stack_handle_t kasan_save_stack(gfp_t flags);
> > > +void kasan_set_track(struct kasan_track *track, gfp_t flags);
> > > +void kasan_set_free_info(struct kmem_cache *cache, void *object, u8 tag);
> > > +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > > +                               void *object, u8 tag);
> > >
> > >  #if defined(CONFIG_KASAN_GENERIC) && \
> > >         (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
> > > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > > index 5ee66cf7e27c..7e9f9f6d5e85 100644
> > > --- a/mm/kasan/report.c
> > > +++ b/mm/kasan/report.c
> > > @@ -159,26 +159,6 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
> > >                 (void *)(object_addr + cache->object_size));
> > >  }
> > >
> > > -static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > > -               void *object, u8 tag)
> > > -{
> > > -       struct kasan_alloc_meta *alloc_meta;
> > > -       int i = 0;
> > > -
> > > -       alloc_meta = get_alloc_info(cache, object);
> > > -
> > > -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > > -       for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
> > > -               if (alloc_meta->free_pointer_tag[i] == tag)
> > > -                       break;
> > > -       }
> > > -       if (i == KASAN_NR_FREE_STACKS)
> > > -               i = alloc_meta->free_track_idx;
> > > -#endif
> > > -
> > > -       return &alloc_meta->free_track[i];
> > > -}
> > > -
> > >  #ifdef CONFIG_KASAN_GENERIC
> > >  static void print_stack(depot_stack_handle_t stack)
> > >  {
> > > diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> > > index 25b7734e7013..201dee5d6ae0 100644
> > > --- a/mm/kasan/tags.c
> > > +++ b/mm/kasan/tags.c
> > > @@ -162,3 +162,40 @@ void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size)
> > >         kasan_poison_shadow((void *)addr, size, tag);
> > >  }
> > >  EXPORT_SYMBOL(__hwasan_tag_memory);
> > > +
> > > +void kasan_set_free_info(struct kmem_cache *cache,
> > > +                               void *object, u8 tag)
> > > +{
> > > +       struct kasan_alloc_meta *alloc_meta;
> > > +       u8 idx = 0;
> > > +
> > > +       alloc_meta = get_alloc_info(cache, object);
> > > +
> > > +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > > +       idx = alloc_meta->free_track_idx;
> > > +       alloc_meta->free_pointer_tag[idx] = tag;
> > > +       alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
> > > +#endif
> > > +
> > > +       kasan_set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
> > > +}
> > > +
> > > +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > > +                               void *object, u8 tag)
> > > +{
> > > +       struct kasan_alloc_meta *alloc_meta;
> > > +       int i = 0;
> > > +
> > > +       alloc_meta = get_alloc_info(cache, object);
> > > +
> > > +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > > +       for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
> > > +               if (alloc_meta->free_pointer_tag[i] == tag)
> > > +                       break;
> > > +       }
> > > +       if (i == KASAN_NR_FREE_STACKS)
> > > +               i = alloc_meta->free_track_idx;
> > > +#endif
> > > +
> > > +       return &alloc_meta->free_track[i];
> > > +}
> > > --
> > > 2.18.0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1589807413.16436.21.camel%40mtksdccf07.
