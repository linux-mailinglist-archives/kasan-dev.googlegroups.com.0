Return-Path: <kasan-dev+bncBDGPTM5BQUDRBGXCRH3AKGQEYM23PNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BE3C1D7704
	for <lists+kasan-dev@lfdr.de>; Mon, 18 May 2020 13:27:23 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id v87sf9433716ill.23
        for <lists+kasan-dev@lfdr.de>; Mon, 18 May 2020 04:27:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589801242; cv=pass;
        d=google.com; s=arc-20160816;
        b=a7nIftNGl4pG7wpG3QXVPwlVeyI5KQOjYMqLkTlUFiYCflSuDF+kVYEwL2avYLc3NP
         NIEiB3OT/K6yhQfc74jphZyUwSgdeOgizHQhXj7ztg/Ibv4V9wPWXI5hg2/qhoiuA7Jd
         Wqivoa2P+vfbblomTKsfzANrLeLjbHivCsCwhMZlT1SdFvH2vP836uGlwocJGGFq7ID8
         2xddvA3/TGLfxUuKJMyCvcShBVycfggTB9y6Ju2NK0ylicS8w7OgmYr7oqqAKkfFP0AG
         yuNFi+3S9utIJd1woL6Cfhv/NTGWw6QOvwuN7naUAHnKMp6AoTgYMf3hVuELWiH9SvIS
         8ZtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=+CEx4ZzApiR23MwHToNAKzTn5QCW3ZRrvJHuK7++KqY=;
        b=TYvY3Nlw0wh1YP6GEWyL6xAbvPMjJhvUE8fD6mr6CICxlrIqnGp7GWGoneMUduamks
         FOkMH1tXca4PSpqC/cu4jI/5M2JK8QSKv9mMITcbivnFaTPEM1luH1SONtdu1ERkzpAA
         gPD2OE68lvoJDRVDdZc0La/LZycWrexYzK9adPw58SGyopcJAKv+kodCi5Kri7Tt68fC
         feWk5Yhb+17In+Q1UVfPIbgaDbknKf181Ai7BQEcS+qbHPElkymTw6ms775Q9jkqYlg0
         PSAirANsKaz5KbSquDowOjzzs5WwKN+Bh92v2QVI88ZZkQjZbp+8Gc8ee3UBSZP1R6is
         6NBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=fDQS7ETM;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+CEx4ZzApiR23MwHToNAKzTn5QCW3ZRrvJHuK7++KqY=;
        b=JeKZ0evYA1rMIAYElQxnqVrr01sqUOhsdSU/I/BgGSAdvnigSC4ec72Xv2wQmeeDjz
         5pZA2aBIK7foDcesRYVrNP0RSieLKvEFoWaSQAhTLWH9nav6C92kjc6+BPtAN8ggr28x
         bKUCYk36O3PnxPJ8NhTYS5Iw7EMjdz0TGFmptsSTmQasAVn/aDHQAouT1sFdkQ7BgzuJ
         aQaTdAZS8ydXIAPLYStxpjhorjTnvDdmd+F3KekLKqco0GBtaeHfhKRdDyuBgrO0j+nv
         vTII2kDfwn/ZhK8/lHF/G9hxIzw03EQ8dhB4mX+abSl2+x6r0j5BH/u/dw4ZXeSwpvn/
         5jPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+CEx4ZzApiR23MwHToNAKzTn5QCW3ZRrvJHuK7++KqY=;
        b=qO28yZtZagxajWdPntMXqIeeZgYtYNtW9IZU22QTN+pe88SwW65u1dRoo4zrQUvHti
         hP1fa34PttOo0d5RWeJICHHZ9omMl/Qll/iyz38K7ELTo3TgDQYuGKiw9ujEYSyJTGli
         UkIPmPf+ju4tSmoAtFMl1iHTWHcSpKfGhLJ/HCpBL88u96ZTHsU3qESVIJcqfY4++uJl
         /u2H/UKVpg9A5udj9v3NFyJcGdS9ODwLNGH07EwKPM9zxU4+U3gPhg1npG+XIGVf3NRD
         XPEoXr65xiqNM7z9JjtH6lTdT5Imm8db/vMtEK5pP80D2hzuys9+wPKRTS4n7+JgKaxY
         +NQA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Uthm+Xm9FkAkfEen43mFoRkVHggru4xqU1AQD58OsaACPQ45L
	yz/DRVf3LFozpUuwZYrGRUk=
X-Google-Smtp-Source: ABdhPJy4KODYqUrnubC/XhOvKve5PG+geivmjruxGCi8IvvqdTtmQIPweFMd051DhWQgC2fkXFnUYQ==
X-Received: by 2002:a5d:8ad8:: with SMTP id e24mr13714110iot.41.1589801242295;
        Mon, 18 May 2020 04:27:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d68a:: with SMTP id p10ls2402979iln.1.gmail; Mon, 18 May
 2020 04:27:21 -0700 (PDT)
X-Received: by 2002:a05:6e02:973:: with SMTP id q19mr15955736ilt.164.1589801241905;
        Mon, 18 May 2020 04:27:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589801241; cv=none;
        d=google.com; s=arc-20160816;
        b=D0t0ZSR6F3yam8U+LUyHj8kzKsh9eZTdeE9fIIIB5KqqWZumJ1vurGNZFbbxJjEl34
         sPTI7cNlaHQAqzcGbYTi2vqo8YDiFtJGBW1UA23+6xJYCgJr80uK38BIR+vzN4JwLuEE
         nBXf78S0OtCggm54Ubc50xgVV4VyxxHkpp89ACsWr61a1l6G8IF3s0KXtmvtUDHjsA1C
         1UZc3HHnNolla1OWsMAZIgCChluq4dRLdCLic4eIinZP6/qb2We6JYKTJD28kSTsdCY3
         Vn6SRDHKOKwzKjwjh+F5iqGatCgaHLsQhOtIxPjbFc9qBLlauIfdmYWqedTmV+EGecbx
         381Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=2rbiAR21QY5qjKzRX1l4eX3iPWNuIOneYTZsVaQMP9s=;
        b=wHKSWJSn9N7kxcewCXU/to7if5IWOBepIcDwlAmNwFXmCV/65UqHsMHelZD31J8tym
         B5OF0mEqHNkQk0R5DnnwMNmrKNdD4+eNLtFxUeqQ3uTxC4Yeao+J80TVE2uYtofRB8xr
         gKsOKfyzAY3WgSr27H6GthVOvPbvThoXIoVMyJu4cQ3V71ADx0Arn1A9JcUKjlhUIzQb
         nHnXPR5/mHlZkWypaPQlFZtWEGb5wdD+Cv0m2eRSHj+zrQUOHCcgfPXy5HcSR8rECTy0
         YvEI258F7rPTOI7P/IEkENy+yem5x1jhGTnGgfNKRPyBM7DiClmG5Mn7E6l6HYa1KM7R
         L+rQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=fDQS7ETM;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id m17si601436ioc.2.2020.05.18.04.27.20
        for <kasan-dev@googlegroups.com>;
        Mon, 18 May 2020 04:27:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 6e3ea54b60ae48c399f5650b22425cd5-20200518
X-UUID: 6e3ea54b60ae48c399f5650b22425cd5-20200518
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1845183124; Mon, 18 May 2020 19:27:16 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 18 May 2020 19:27:14 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 18 May 2020 19:27:13 +0800
Message-ID: <1589801235.16436.12.camel@mtksdccf07>
Subject: Re: [PATCH v3 2/4] kasan: record and print the free track
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, kasan-dev
	<kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, LKML
	<linux-kernel@vger.kernel.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>
Date: Mon, 18 May 2020 19:27:15 +0800
In-Reply-To: <CACT4Y+YVF2cLdg6qaK+3NcU3kLz2Pys6NWxLAYfity5n5cjirA@mail.gmail.com>
References: <20200518062730.4665-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+YVF2cLdg6qaK+3NcU3kLz2Pys6NWxLAYfity5n5cjirA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=fDQS7ETM;       spf=pass
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

On Mon, 2020-05-18 at 12:18 +0200, Dmitry Vyukov wrote:
> On Mon, May 18, 2020 at 8:27 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > Move free track from slub alloc meta-data to slub free meta-data in
> > order to make struct kasan_free_meta size is 16 bytes. It is a good
> > size because it is the minimal redzone size and a good number of
> > alignment.
> >
> > For free track in generic KASAN, we do the modification in struct
> > kasan_alloc_meta and kasan_free_meta:
> > - remove free track from kasan_alloc_meta.
> > - add free track into kasan_free_meta.
> >
> > [1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
> >
> > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > ---
> >  mm/kasan/common.c  | 33 ++++++++++-----------------------
> >  mm/kasan/generic.c | 18 ++++++++++++++++++
> >  mm/kasan/kasan.h   |  7 +++++++
> >  mm/kasan/report.c  | 20 --------------------
> >  mm/kasan/tags.c    | 37 +++++++++++++++++++++++++++++++++++++
> >  5 files changed, 72 insertions(+), 43 deletions(-)
> >
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 8bc618289bb1..6500bc2bb70c 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -51,7 +51,7 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags)
> >         return stack_depot_save(entries, nr_entries, flags);
> >  }
> >
> > -static inline void set_track(struct kasan_track *track, gfp_t flags)
> > +void kasan_set_track(struct kasan_track *track, gfp_t flags)
> >  {
> >         track->pid = current->pid;
> >         track->stack = kasan_save_stack(flags);
> > @@ -249,9 +249,7 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> >         *size += sizeof(struct kasan_alloc_meta);
> >
> >         /* Add free meta. */
> > -       if (IS_ENABLED(CONFIG_KASAN_GENERIC) &&
> > -           (cache->flags & SLAB_TYPESAFE_BY_RCU || cache->ctor ||
> > -            cache->object_size < sizeof(struct kasan_free_meta))) {
> > +       if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> 
> Why do we need to increase object size unconditionally?
> We only store info in free track when the object is free, so I would
> assume we still can generally overlap free track and the object
> itself. We store free track at the same time we use the quarantine
> link, and the quarantine link was overlapped with the object just
> fine.
> With this change we indeed increase object size, which we do not want
> in general.
> 

If it doesn't add free meta, but we always store free track into the
object, Is it safe?

> 
> >                 cache->kasan_info.free_meta_offset = *size;
> >                 *size += sizeof(struct kasan_free_meta);
> >         }
> > @@ -299,24 +297,6 @@ struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
> >         return (void *)object + cache->kasan_info.free_meta_offset;
> >  }
> >
> > -
> > -static void kasan_set_free_info(struct kmem_cache *cache,
> > -               void *object, u8 tag)
> > -{
> > -       struct kasan_alloc_meta *alloc_meta;
> > -       u8 idx = 0;
> > -
> > -       alloc_meta = get_alloc_info(cache, object);
> > -
> > -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > -       idx = alloc_meta->free_track_idx;
> > -       alloc_meta->free_pointer_tag[idx] = tag;
> > -       alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
> > -#endif
> > -
> > -       set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
> > -}
> > -
> >  void kasan_poison_slab(struct page *page)
> >  {
> >         unsigned long i;
> > @@ -396,6 +376,13 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
> >         alloc_info = get_alloc_info(cache, object);
> >         __memset(alloc_info, 0, sizeof(*alloc_info));
> >
> > +       if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> > +               struct kasan_free_meta *free_info;
> > +
> > +               free_info = get_free_info(cache, object);
> > +               __memset(free_info, 0, sizeof(*free_info));
> 
> If we overlap free track with object, this will not be needed as well, right?
> 

Should we not consider those objects which have adding free meta? If
they exist, then we should init their meta data when object re-allocate.

struct kasan_free_meta {
    struct qlist_node quarantine_link;
    struct kasan_track free_track;
};


> > +       }
> > +
> >         if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> >                 object = set_tag(object,
> >                                 assign_tag(cache, object, true, false));
> > @@ -492,7 +479,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
> >                 KASAN_KMALLOC_REDZONE);
> >
> >         if (cache->flags & SLAB_KASAN)
> > -               set_track(&get_alloc_info(cache, object)->alloc_track, flags);
> > +               kasan_set_track(&get_alloc_info(cache, object)->alloc_track, flags);
> >
> >         return set_tag(object, tag);
> >  }
> > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > index 78d8e0a75a8a..988bc095b738 100644
> > --- a/mm/kasan/generic.c
> > +++ b/mm/kasan/generic.c
> > @@ -345,3 +345,21 @@ void kasan_record_aux_stack(void *addr)
> >                 alloc_info->rcu_stack[1] = alloc_info->rcu_stack[0];
> >         alloc_info->rcu_stack[0] = kasan_save_stack(GFP_NOWAIT);
> >  }
> > +
> > +void kasan_set_free_info(struct kmem_cache *cache,
> > +                               void *object, u8 tag)
> > +{
> > +       struct kasan_free_meta *free_meta;
> > +
> > +       free_meta = get_free_info(cache, object);
> > +       kasan_set_track(&free_meta->free_track, GFP_NOWAIT);
> > +}
> > +
> > +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > +                               void *object, u8 tag)
> > +{
> > +       struct kasan_free_meta *free_meta;
> > +
> > +       free_meta = get_free_info(cache, object);
> > +       return &free_meta->free_track;
> > +}
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index 870c5dd07756..87ee3626b8b0 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -127,6 +127,9 @@ struct kasan_free_meta {
> >          * Otherwise it might be used for the allocator freelist.
> >          */
> >         struct qlist_node quarantine_link;
> > +#ifdef CONFIG_KASAN_GENERIC
> > +       struct kasan_track free_track;
> > +#endif
> >  };
> >
> >  struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
> > @@ -168,6 +171,10 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
> >  struct page *kasan_addr_to_page(const void *addr);
> >
> >  depot_stack_handle_t kasan_save_stack(gfp_t flags);
> > +void kasan_set_track(struct kasan_track *track, gfp_t flags);
> > +void kasan_set_free_info(struct kmem_cache *cache, void *object, u8 tag);
> > +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > +                               void *object, u8 tag);
> >
> >  #if defined(CONFIG_KASAN_GENERIC) && \
> >         (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index 5ee66cf7e27c..7e9f9f6d5e85 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -159,26 +159,6 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
> >                 (void *)(object_addr + cache->object_size));
> >  }
> >
> > -static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > -               void *object, u8 tag)
> > -{
> > -       struct kasan_alloc_meta *alloc_meta;
> > -       int i = 0;
> > -
> > -       alloc_meta = get_alloc_info(cache, object);
> > -
> > -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > -       for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
> > -               if (alloc_meta->free_pointer_tag[i] == tag)
> > -                       break;
> > -       }
> > -       if (i == KASAN_NR_FREE_STACKS)
> > -               i = alloc_meta->free_track_idx;
> > -#endif
> > -
> > -       return &alloc_meta->free_track[i];
> > -}
> > -
> >  #ifdef CONFIG_KASAN_GENERIC
> >  static void print_stack(depot_stack_handle_t stack)
> >  {
> > diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> > index 25b7734e7013..201dee5d6ae0 100644
> > --- a/mm/kasan/tags.c
> > +++ b/mm/kasan/tags.c
> > @@ -162,3 +162,40 @@ void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size)
> >         kasan_poison_shadow((void *)addr, size, tag);
> >  }
> >  EXPORT_SYMBOL(__hwasan_tag_memory);
> > +
> > +void kasan_set_free_info(struct kmem_cache *cache,
> > +                               void *object, u8 tag)
> > +{
> > +       struct kasan_alloc_meta *alloc_meta;
> > +       u8 idx = 0;
> > +
> > +       alloc_meta = get_alloc_info(cache, object);
> > +
> > +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > +       idx = alloc_meta->free_track_idx;
> > +       alloc_meta->free_pointer_tag[idx] = tag;
> > +       alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
> > +#endif
> > +
> > +       kasan_set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
> > +}
> > +
> > +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > +                               void *object, u8 tag)
> > +{
> > +       struct kasan_alloc_meta *alloc_meta;
> > +       int i = 0;
> > +
> > +       alloc_meta = get_alloc_info(cache, object);
> > +
> > +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > +       for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
> > +               if (alloc_meta->free_pointer_tag[i] == tag)
> > +                       break;
> > +       }
> > +       if (i == KASAN_NR_FREE_STACKS)
> > +               i = alloc_meta->free_track_idx;
> > +#endif
> > +
> > +       return &alloc_meta->free_track[i];
> > +}
> > --
> > 2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1589801235.16436.12.camel%40mtksdccf07.
