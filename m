Return-Path: <kasan-dev+bncBDGPTM5BQUDRBUMXSP3AKGQEIBNAA3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 44B871DAA7E
	for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 08:18:58 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id g20sf2387948qkl.11
        for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 23:18:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589955537; cv=pass;
        d=google.com; s=arc-20160816;
        b=FE2OVvGBd7so0diJ/hIoEf9UipdErmLiGF7Zba7boPrEr36i/Z3ELfJo3VswNYgH6P
         lcrrzaVfazCKdBHAtEfG7o6AfvcBzY0vx6PMjXFu6pmPZrlyuscBclsveZcXN7wMIP4N
         dvBDghuaAld0Z6dS8/KAwcg4UShKYHEho6N/Xd/rlfX2qXJC//5pOUL8GEy4FRJUkYk4
         9EQu+a/0868L2Zo22M/gGRcMy7Lr0MnM2PTRagpV6KZipthLDo9XBg8rNIPX8ddnnzpu
         y3TMINnQrjS4sr2A0yejuWgReHb/qESFus4vjgKmbbcCzUsbUxsEZ4YbihFs2wFkgkza
         oWfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=aRbDQ6qHpY2MmfgS19cuuxuettp9rvwxM2uXQ3+EXe4=;
        b=x6F3ft4iDBMUUfcAmKez+3VnI8vFSBDghDTwpZr/zUe0nRzHX4M5WaoGkDxgEmG/Tp
         bc1YyBUvDnfgAZMAatZLZ4jKm739Yhl0KnFlynCbRHCwhJFP3tkEsiRexmB0nG+lam45
         n9fB4noiJqvDzTdk6Kg3eo0iNAIPkPFm1uaymKK8ujIIdoXjqzHeHFtJ51u5EnDk7ehX
         8XfoGiJMPfBr36Sv092L8wBL6ZFIUbcfuk+BeCYCUUtSCm497PJHmTrlWZZ+hmixaNa1
         nTzQ+bHyTeqGKGNtugBj02oNULq8/FMMglZVXpU3Ey28yebaCwpNu6Tun8AW5sWgUzEQ
         AznQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=Rk8vYAVK;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aRbDQ6qHpY2MmfgS19cuuxuettp9rvwxM2uXQ3+EXe4=;
        b=mtt76nr8VO3PbRBa0daqxvOOSKCAt6CiRRyl7tCIOYEptcstSE9ritdkshFUqAHw0H
         Mp1SOhZ0xhAYewbgYlCmCcIpWVcM6RL47CdCcQfFAd7FUA4iPqgE589DSvhUNkPn7okr
         0GPQ7Lcn1N7VUP+DFD0VNtA4v2YPtxLgz0RvoHLd63a0O3ot4zYC5zQjxXmtezokZzbv
         DpVCSOiXB0Xsxzo6O87cwha70PgdC8RmCtiyRbP+8DRDS99y4jIxClrSEjQ0UO5cj2QH
         tfI4eIon7bA0BUfqrSdGHTDpFsH3xkd9k2zC0+KlvAIr9a9xHQWA8aiuJh4s+wHU8KHg
         DFLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aRbDQ6qHpY2MmfgS19cuuxuettp9rvwxM2uXQ3+EXe4=;
        b=Fk5LJas6Fk60Kq+K98o3nd+sphLn2415RdBgsHCveUeN+7PGDBvWKRt4cau4L+uB9E
         riJAQyOlwfVkKbeH5tRTTz5dGzewLjuJj9ktNi4MUvLnBJXdeg/0rLFeWtitKFUof0rG
         JWDzsXR8nKHDo73oNLowaoAhvdQ58RK69PRRHrZMHlaDlGAsCQZHbLo9NqDY3Z/6VGWh
         U8AXwehpZ3qJxObkpcsokXqAY8jYOCBqD4EA8yxo0vm1ELpaI2ZvwsIl4+rLCv8kFy/E
         ywhjhfcONIl3IF5GIofKFa4u6yyKYngcf93H6XJBqlBApqv3OLr6ZJl8GnJO2J6LtaJv
         o/Jw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Cn5Ojcn6WOCyiNzjmJGhjpZHe0iX6vgMPiO2SqFGGJExUMG02
	0jZ2+ISf6De/JiY6L3k08kE=
X-Google-Smtp-Source: ABdhPJxSHC9abhLQJXM4UzEK+/5k0TmO7FWefV2dMRTUpgJ9rNCC5pKuwU3Lrqb+l+JSvF2NbSBvWg==
X-Received: by 2002:a37:6fc3:: with SMTP id k186mr261524qkc.419.1589955537287;
        Tue, 19 May 2020 23:18:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:655:: with SMTP id 82ls1126168qkg.2.gmail; Tue, 19 May
 2020 23:18:56 -0700 (PDT)
X-Received: by 2002:a37:4f55:: with SMTP id d82mr2967661qkb.219.1589955536909;
        Tue, 19 May 2020 23:18:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589955536; cv=none;
        d=google.com; s=arc-20160816;
        b=Z1gbcYd5rtHyTzAndMO3y5zLzPIRfd9od5dLAB0SUhQE9ycLYHH0JdklRwFg2tPeh1
         qDgfou/3951hRtFVK4wuZlcg3jUXNFfRzxmkXfNA3nMIyQLG3LGz3br7dhXW/U2wvaaW
         yAS5UYx9Yil4Kh1mnaoSJQXKd1TNYRGrSYRBVPi0GXqftrx7FAz/ILZ3DD9Aglfsr8gu
         7kUKZu/uGqBR96aKDqBMUhiJY8JOB/RNDU2Xp+RHGmWP7LgvY/irs7b7uLmPoGXcc7Yr
         xoKpZyXNw0vINa+ps8Ix/oCASE7c/98O0J1PAgTtu02hfNBdMOKS0Y7cZ8svOAI4B5nD
         b4CA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=uOnq9kfvK+d9CkgmYag+3mwJ8va1DCoKvWDnB5YAL+s=;
        b=eJtNd7v5PHT7KND+QExPt/8/c2gGKUbhbNlZsg2uZGoi2L6Uq3KmFSFFDxf0fQhpsJ
         cSATQqRTytkvuwMRpDXDGTaU/ZNGO8pelQZaOhyhiomk7Za7P5mXMrHKKJJli1mDh7dn
         4s+7ZrMRrwNp1Xk3QdQxaO35Klrf9epWSIeXt/LFx6tANOfbdidB2bZvVIm4uNkIikg/
         n1YxbqUFjItE9PihY58SDC8G/kUbuRfCPtoDSa61N+RfLaml/ywVVdvGCLRYNuujeOGm
         l5t9L66B2jRLTgkWKI60a3V3tziJm/VjPdgCTX/fZtf6CNKMnSz7H94OzOJ1AUAr2BTc
         Qusw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=Rk8vYAVK;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id p187si155421qke.1.2020.05.19.23.18.55
        for <kasan-dev@googlegroups.com>;
        Tue, 19 May 2020 23:18:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: c3e21d5d87f0452393ac16419f339368-20200520
X-UUID: c3e21d5d87f0452393ac16419f339368-20200520
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1043113502; Wed, 20 May 2020 14:18:52 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 20 May 2020 14:18:45 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 20 May 2020 14:18:45 +0800
Message-ID: <1589955526.4440.22.camel@mtksdccf07>
Subject: Re: [PATCH v4 2/4] kasan: record and print the free track
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, Linux-MM
	<linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>
Date: Wed, 20 May 2020 14:18:46 +0800
In-Reply-To: <1589951659.4440.4.camel@mtksdccf07>
References: <20200519022517.24182-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+aJDO+2kSgNpcvHksfn+bZaFWPoGj3-55-dyjLHcHbFUg@mail.gmail.com>
	 <1589947387.29577.35.camel@mtksdccf07>
	 <CACT4Y+Zy0O3brZRvN5jbdXMosBv+aFgRGSubbhCwzOSUftGoeA@mail.gmail.com>
	 <1589951659.4440.4.camel@mtksdccf07>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=Rk8vYAVK;       spf=pass
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

On Wed, 2020-05-20 at 13:14 +0800, Walter Wu wrote:
> > On Wed, May 20, 2020 at 6:03 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > >
> > > > On Tue, May 19, 2020 at 4:25 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > > >
> > > > > Move free track from slub alloc meta-data to slub free meta-data in
> > > > > order to make struct kasan_free_meta size is 16 bytes. It is a good
> > > > > size because it is the minimal redzone size and a good number of
> > > > > alignment.
> > > > >
> > > > > For free track in generic KASAN, we do the modification in struct
> > > > > kasan_alloc_meta and kasan_free_meta:
> > > > > - remove free track from kasan_alloc_meta.
> > > > > - add free track into kasan_free_meta.
> > > > >
> > > > > [1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
> > > > >
> > > > > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > > > Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> > > > > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > > > > Cc: Dmitry Vyukov <dvyukov@google.com>
> > > > > Cc: Alexander Potapenko <glider@google.com>
> > > > > ---
> > > > >  mm/kasan/common.c  | 22 ++--------------------
> > > > >  mm/kasan/generic.c | 18 ++++++++++++++++++
> > > > >  mm/kasan/kasan.h   |  7 +++++++
> > > > >  mm/kasan/report.c  | 20 --------------------
> > > > >  mm/kasan/tags.c    | 37 +++++++++++++++++++++++++++++++++++++
> > > > >  5 files changed, 64 insertions(+), 40 deletions(-)
> > > > >
> > > > > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > > > > index 8bc618289bb1..47b53912f322 100644
> > > > > --- a/mm/kasan/common.c
> > > > > +++ b/mm/kasan/common.c
> > > > > @@ -51,7 +51,7 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags)
> > > > >         return stack_depot_save(entries, nr_entries, flags);
> > > > >  }
> > > > >
> > > > > -static inline void set_track(struct kasan_track *track, gfp_t flags)
> > > > > +void kasan_set_track(struct kasan_track *track, gfp_t flags)
> > > > >  {
> > > > >         track->pid = current->pid;
> > > > >         track->stack = kasan_save_stack(flags);
> > > > > @@ -299,24 +299,6 @@ struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
> > > > >         return (void *)object + cache->kasan_info.free_meta_offset;
> > > > >  }
> > > > >
> > > > > -
> > > > > -static void kasan_set_free_info(struct kmem_cache *cache,
> > > > > -               void *object, u8 tag)
> > > > > -{
> > > > > -       struct kasan_alloc_meta *alloc_meta;
> > > > > -       u8 idx = 0;
> > > > > -
> > > > > -       alloc_meta = get_alloc_info(cache, object);
> > > > > -
> > > > > -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > > > > -       idx = alloc_meta->free_track_idx;
> > > > > -       alloc_meta->free_pointer_tag[idx] = tag;
> > > > > -       alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
> > > > > -#endif
> > > > > -
> > > > > -       set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
> > > > > -}
> > > > > -
> > > > >  void kasan_poison_slab(struct page *page)
> > > > >  {
> > > > >         unsigned long i;
> > > > > @@ -492,7 +474,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
> > > > >                 KASAN_KMALLOC_REDZONE);
> > > > >
> > > > >         if (cache->flags & SLAB_KASAN)
> > > > > -               set_track(&get_alloc_info(cache, object)->alloc_track, flags);
> > > > > +               kasan_set_track(&get_alloc_info(cache, object)->alloc_track, flags);
> > > > >
> > > > >         return set_tag(object, tag);
> > > > >  }
> > > > > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > > > > index 3372bdcaf92a..763d8a13e0ac 100644
> > > > > --- a/mm/kasan/generic.c
> > > > > +++ b/mm/kasan/generic.c
> > > > > @@ -344,3 +344,21 @@ void kasan_record_aux_stack(void *addr)
> > > > >         alloc_info->aux_stack[1] = alloc_info->aux_stack[0];
> > > > >         alloc_info->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
> > > > >  }
> > > > > +
> > > > > +void kasan_set_free_info(struct kmem_cache *cache,
> > > > > +                               void *object, u8 tag)
> > > > > +{
> > > > > +       struct kasan_free_meta *free_meta;
> > > > > +
> > > > > +       free_meta = get_free_info(cache, object);
> > > > > +       kasan_set_track(&free_meta->free_track, GFP_NOWAIT);
> > > > > +}
> > > > > +
> > > > > +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > > > > +                               void *object, u8 tag)
> > > > > +{
> > > > > +       struct kasan_free_meta *free_meta;
> > > > > +
> > > > > +       free_meta = get_free_info(cache, object);
> > > > > +       return &free_meta->free_track;
> > > > > +}
> > > > > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > > > > index a7391bc83070..ad897ec36545 100644
> > > > > --- a/mm/kasan/kasan.h
> > > > > +++ b/mm/kasan/kasan.h
> > > > > @@ -127,6 +127,9 @@ struct kasan_free_meta {
> > > > >          * Otherwise it might be used for the allocator freelist.
> > > > >          */
> > > > >         struct qlist_node quarantine_link;
> > > > > +#ifdef CONFIG_KASAN_GENERIC
> > > > > +       struct kasan_track free_track;
> > > > > +#endif
> > > > >  };
> > > > >
> > > > >  struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
> > > > > @@ -168,6 +171,10 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
> > > > >  struct page *kasan_addr_to_page(const void *addr);
> > > > >
> > > > >  depot_stack_handle_t kasan_save_stack(gfp_t flags);
> > > > > +void kasan_set_track(struct kasan_track *track, gfp_t flags);
> > > > > +void kasan_set_free_info(struct kmem_cache *cache, void *object, u8 tag);
> > > > > +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > > > > +                               void *object, u8 tag);
> > > > >
> > > > >  #if defined(CONFIG_KASAN_GENERIC) && \
> > > > >         (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
> > > > > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > > > > index 6f8f2bf8f53b..96d2657fe70f 100644
> > > > > --- a/mm/kasan/report.c
> > > > > +++ b/mm/kasan/report.c
> > > > > @@ -159,26 +159,6 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
> > > > >                 (void *)(object_addr + cache->object_size));
> > > > >  }
> > > > >
> > > > > -static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > > > > -               void *object, u8 tag)
> > > > > -{
> > > > > -       struct kasan_alloc_meta *alloc_meta;
> > > > > -       int i = 0;
> > > > > -
> > > > > -       alloc_meta = get_alloc_info(cache, object);
> > > > > -
> > > > > -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > > > > -       for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
> > > > > -               if (alloc_meta->free_pointer_tag[i] == tag)
> > > > > -                       break;
> > > > > -       }
> > > > > -       if (i == KASAN_NR_FREE_STACKS)
> > > > > -               i = alloc_meta->free_track_idx;
> > > > > -#endif
> > > > > -
> > > > > -       return &alloc_meta->free_track[i];
> > > > > -}
> > > > > -
> > > > >  #ifdef CONFIG_KASAN_GENERIC
> > > > >  static void print_stack(depot_stack_handle_t stack)
> > > > >  {
> > > > > diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> > > > > index 25b7734e7013..201dee5d6ae0 100644
> > > > > --- a/mm/kasan/tags.c
> > > > > +++ b/mm/kasan/tags.c
> > > > > @@ -162,3 +162,40 @@ void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size)
> > > > >         kasan_poison_shadow((void *)addr, size, tag);
> > > > >  }
> > > > >  EXPORT_SYMBOL(__hwasan_tag_memory);
> > > > > +
> > > > > +void kasan_set_free_info(struct kmem_cache *cache,
> > > > > +                               void *object, u8 tag)
> > > > > +{
> > > > > +       struct kasan_alloc_meta *alloc_meta;
> > > > > +       u8 idx = 0;
> > > > > +
> > > > > +       alloc_meta = get_alloc_info(cache, object);
> > > > > +
> > > > > +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > > > > +       idx = alloc_meta->free_track_idx;
> > > > > +       alloc_meta->free_pointer_tag[idx] = tag;
> > > > > +       alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
> > > > > +#endif
> > > > > +
> > > > > +       kasan_set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
> > > > > +}
> > > > > +
> > > > > +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > > > > +                               void *object, u8 tag)
> > > > > +{
> > > > > +       struct kasan_alloc_meta *alloc_meta;
> > > > > +       int i = 0;
> > > > > +
> > > > > +       alloc_meta = get_alloc_info(cache, object);
> > > > > +
> > > > > +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > > > > +       for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
> > > > > +               if (alloc_meta->free_pointer_tag[i] == tag)
> > > > > +                       break;
> > > > > +       }
> > > > > +       if (i == KASAN_NR_FREE_STACKS)
> > > > > +               i = alloc_meta->free_track_idx;
> > > > > +#endif
> > > > > +
> > > > > +       return &alloc_meta->free_track[i];
> > > > > +}
> > > >
> > > > Hi Walter,
> > > >
> > > > FTR I've uploaded this for review purposes here:
> > > > https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/2458
> > > >
> > > > Diff from the previous version is available as:
> > > > https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/2458/1..2
> > > >
> > > > I've tested this locally and with syzkaller. This is :
> > > >
> > > > [   80.583021][    C3] Freed by task 0:
> > > > [   80.583480][    C3]  kasan_save_stack+0x1b/0x40 mm/kasan/common.c:49
> > > > [   80.584056][    C3]  kasan_set_track+0x1c/0x30 mm/kasan/common.c:57
> > > > [   80.584617][    C3]  kasan_set_free_info+0x1b/0x30 mm/kasan/generic.c:354
> > > > [   80.585221][    C3]  __kasan_slab_free+0xd8/0x120 mm/kasan/common.c:438
> > > > [   80.585814][    C3]  __cache_free mm/slab.c:3426 [inline]
> > > > [   80.585814][    C3]  kfree+0x10b/0x2b0 mm/slab.c:3757
> > > > [   80.586291][    C3]  kasan_rcu_reclaim+0x16/0x43 [test_kasan]
> > > > [   80.587009][    C3]  rcu_do_batch kernel/rcu/tree.c:2207 [inline]
> > > > [   80.587009][    C3]  rcu_core+0x59f/0x1370 kernel/rcu/tree.c:2434
> > > > [   80.587537][    C3]  __do_softirq+0x26c/0x9fa kernel/softirq.c:292
> > > > [   80.588085][    C3]
> > > > [   80.588367][    C3] Last one call_rcu() call stack:
> > > > [   80.589052][    C3]  kasan_save_stack+0x1b/0x40 mm/kasan/common.c:49
> > > > [   80.589622][    C3]  kasan_record_aux_stack+0x82/0xb0 mm/kasan/generic.c:345
> > > > [   80.590254][    C3]  __call_rcu kernel/rcu/tree.c:2672 [inline]
> > > > [   80.590254][    C3]  call_rcu+0x14f/0x7f0 kernel/rcu/tree.c:2746
> > > > [   80.590782][    C3]  kasan_rcu_uaf+0xe4/0xeb [test_kasan]
> > > > [   80.591697][    C3]  kmalloc_tests_init+0xbc/0x1097 [test_kasan]
> > > > [   80.592900][    C3]  do_one_initcall+0x10a/0x7d0 init/main.c:1196
> > > > [   80.593494][    C3]  do_init_module+0x1e6/0x6d0 kernel/module.c:3539
> > > > [   80.594066][    C3]  load_module+0x7464/0x9450 kernel/module.c:3890
> > > > [   80.594626][    C3]  __do_sys_init_module+0x1e3/0x220 kernel/module.c:3953
> > > > [   80.595265][    C3]  do_syscall_64+0xf6/0x7d0 arch/x86/entry/common.c:295
> > > > [   80.595822][    C3]  entry_SYSCALL_64_after_hwframe+0x49/0xb3
> > > >
> > > >
> > > > Overall this looks very good to me.
> > > > But there is one aspect that bothers me. In the previous patch you had
> > > > code that returned NULL from kasan_get_free_track() if the object is
> > > > live (which means free meta is not available, it's occupied by object
> > > > data). Now you dropped that code, but I think we still need it.
> > > > Otherwise we cast user object data to free meta and print the free
> > > > stack/pid from whatever garbage is there. This may lead to very
> > > > confusing output and potentially to crashes in stackdepot.
> > > >
> > >
> > > Yes, I totally agree with you. In the previous email I thought that
> > > there is a problem with free track, but I did not point it out. Thank
> > > you for pointing this problem. As you mentioned, we should fix it.
> > >
> > > > What do you think about this patch on top of your patches?
> > > > https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/2478
> > > > This way we very precisely mark the period of time when the object has
> > > > free track live and set.
> > > > If it looks good to you, feel free to incorporate it into your series.
> > > >
> > >
> > > Thank you for providing good idea solution.
> > >
> > > I saw this patch, that is a great patch. I think it can fix the issue
> > > which has garbage stack. it should work as described below.
> > >
> > > 1). When object is live, then don't print free stack.
> > > 2). When object is NOT alive, after free object:
> > > 2a). when object is in quarantine, then it can print free stack
> > > 2b). when object is NOT in quarantine, then it can NOT print free stack.
> > >
> > > I have a question about 2), why we don't directly use
> > > KASAN_KMALLOC_FREE? if we directly use it, then 2b) can print free
> > > stack? 2b) may has use-after-free? so that it may need free stack.
> > 

About 2b), I see another question. When do qlink_free(), it will be
written KASAN_KMALLOC_FREE from KASAN_KMALLOC_FREETRACK? if we don't
write shadow memory, it is still KASAN_KMALLOC_FREETRACK, then 2b) will
have free stack? Because I see you add KASAN_KMALLOC_FREETRACK to get
use-after-free in get_shadow_bug_type(). so should it not write
KASAN_KMALLOC_FREE?

> > 
> > We can't use KASAN_KMALLOC_FREE because of this part:
> > 
> > static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
> >                   unsigned long ip, bool quarantine)
> > {
> > ...
> >     kasan_poison_shadow(object, rounded_up_size, KASAN_KMALLOC_FREE);
> > 
> >     if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
> >             unlikely(!(cache->flags & SLAB_KASAN)))
> >         return false;
> > 
> >     kasan_set_free_info(cache, object, tag);
> > ...
> > 
> 
> Ok, I see. When return false, then the shadow memory content has
> KASAN_KMALLOC_FREE, but it doesn't set free stack, so that we need to
> avoid this situation. Thank for you reminder.
> 
> > 
> > We may set KASAN_KMALLOC_FREE, but not set the track (or even have
> > memory for the track!).
> > The object may not have free meta allocated at all, e.g. very large
> > object with ctor (no place to store meta), or it may be in a mempool:
> > https://elixir.bootlin.com/linux/v5.7-rc6/source/mm/mempool.c#L109
> > and mempool may be using the object memory itself (for its own next
> > link or something).
> > 
> > KASAN_KMALLOC_FREETRACK very explicitly tracks the exact condition we
> > want: we have meta info live now and we have free track set.
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1589955526.4440.22.camel%40mtksdccf07.
