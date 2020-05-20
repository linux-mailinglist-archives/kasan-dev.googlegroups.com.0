Return-Path: <kasan-dev+bncBDGPTM5BQUDRBKUGSP3AKGQE77CYPPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 82D171DAA05
	for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 07:42:03 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id x3sf1654715pgl.2
        for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 22:42:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589953322; cv=pass;
        d=google.com; s=arc-20160816;
        b=UZK3o2MoABleFH2KAr+ZK4zboLdFIYaaWP3irpNP2PxL7zEUNE+hjod1OHG8dEIIaH
         6y8hWXHe8Q0ATCl5DVxO7CZ5/veLSwPOWlnetiiXabpTCZRW0M0sdqGpGQjv2gsO/pbg
         HnGPIT2Gp8RwiQTEHDXvaXNH284Fhm+NJfw7NNTd/FhGVu70+OhUJfPbCYk9OxvVXB/m
         ol/lwt3A108E0ER0F/ZpfKAdiivEN4ULJawvemSJAhtL5N5XnuvLzv/02FZEFfi1qG1f
         VWjL6sP7PgRlG8WDdxoTwQ/WLb4RwISJATHGFesvRTsYrog0D0HJJqCZwUTvdVpQI/my
         LXDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=DMTVDYQtON4T9mnXPI6mSuAMpP1iASKKnC3TR+mQVzg=;
        b=xqWzszrz+pQV+xyv6G1cKbfjV6dif5SxpWfKTyQtHG91uWmyf3wUO10nxsdJANUFQf
         1EITsQQO2J7Whv4YJdouxslIRmnZgo+iv2gKLxLniClkxqiFJYrdNPB8CgkRe0CIj4jo
         KRHEhSYmT8oB/Bxx2K2+AIYdmbmJVCmOqQnt8YiDrbRkp1zjPmXT94PXXqwZClWPRewP
         d/IMcLBNs/mIey677ORMAHwHFYcmiU4aqI6FWoaWJxBLNv/SqJeJKaTckWcwOcyHfzAe
         IwZJ2gOynyzsSj7nd17fGj0aObfbkWvugUZF3pQlXnT56bYlXthk//2bSOCqqQVmr1yT
         2vrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=f8ggBDvz;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DMTVDYQtON4T9mnXPI6mSuAMpP1iASKKnC3TR+mQVzg=;
        b=RLHExOhJ5UhmVNqRehu45B7wc/S9nJWz5/feL5em+qurXTwQh+CfLMH/IFmLbv5NY3
         czmrxJBHq/oq6M5c/SI3ffNqmXZCf2FSjt2O4vLojZHFcnwrKwp9DLkEudNpiKtXvt5n
         ZNODLgnFO5UZBrXEPgzRMmkaGuIYtzk42Emuvzy2QENXAsy82HzagTYDeSn8md+VPChy
         cURM5S9y2FYxxEHMItRgDSpjIAUA+XJpKIXZfPH8FDTeoZFdI5sZp/Z0qxFQMGDaKbpy
         Hn8LtkeL+BDW0evk3j2KdlL1hVX6DhSsEljXxMWOJ+8Bf6YGkfmfccZPxr9siNN1t/xl
         jtHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DMTVDYQtON4T9mnXPI6mSuAMpP1iASKKnC3TR+mQVzg=;
        b=RgkicYhhNurljprXFAlizHFZ5g2JG2w8+jY5qEey7tvr3DmLdjScbALtvf0TVZniIl
         5tNguhlRJSZmaEcP+Ml7mkOK+0JxddnSOylsAfXGpS+rqhB/AgJcmsoDI6AYofAF9/xY
         R+fAvXyEW7W1iMjGyU1NpQR+Y5MBHZnGH/UH2BL11Xs+iVXioTihRPvY9xPitjFfCFeC
         eJh6rvlni7OFOgczmXVbqSHeBJ9RdZWNd88eEn4w8TsFfN36XvOauEzwFVZCHgbbjJ8W
         vT/o0pOqPG1GypKDELyPpCtxupdWHcU3TAoOTd73JrrVDvJWfB/C7Negzd3EbDCTWRRN
         B/EQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531gBt3Nh0LYWCqPVnmXP8r4vQB+owTmh2Sv8wO/6WB7SM3b7hRK
	HTzdEpWS9YZ8dGBV+mRy5fA=
X-Google-Smtp-Source: ABdhPJxrxrHRxFA5VovmBpPIj0IIDLe6VbMcnrlNat0nJodbNolcH6Dx24tFRHSkNoZCvrjHr99d1Q==
X-Received: by 2002:a65:40c3:: with SMTP id u3mr2617227pgp.305.1589953322161;
        Tue, 19 May 2020 22:42:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8d95:: with SMTP id v21ls652862plo.3.gmail; Tue, 19
 May 2020 22:42:01 -0700 (PDT)
X-Received: by 2002:a17:90a:20ae:: with SMTP id f43mr3506305pjg.29.1589953321645;
        Tue, 19 May 2020 22:42:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589953321; cv=none;
        d=google.com; s=arc-20160816;
        b=oVlmlJLMI7lF4ye2AOQK1oorcFCUk5IbFp9gBQv4PVPEGxpaOev1Q2qKumH9/0jLoy
         tHoLnDXLjgTLfK00HTEuQFAQLuOunJxb/QSyBzpfmUV7dtvv7IELhexoIrdRE3yc/zwk
         Ow/HZo1PjIztaaz+kQKSD2IMfaLQUy54pjC2t91tpGtl0zuUVqOzI3tDgjuho9mOQlvu
         /jPtnaOEnvC5z87daICgAIONcukTQlGhJucATzeHLQf8VNxn07EN06/2LAblPfOa8nTa
         alnFVnY2bZYSgA7oaJ5ieyzKopAnMcmTme+PPI5l9ZuQkXGOHlmb8G0kbFx4a6pqBY08
         nt4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=6ku49MVZehHebxn7YC/x7xrDcgFDAo+wGqmHwQzj280=;
        b=UDSFch7KWzG56oIjWM9m68lXZJ7jP3rVDcpcBxSUhwOECowFMgs87wjp2A9zMey4x3
         m/L1NZvlW+5t18Rp9PnzgQgYiG5R8ZUd2qVS4JEkzYP7gU39IiCTF3Pu3+t6w3L6pjTX
         AEwDCeOq1RN7mMNxxRi1yeKUp8colTq+MIOT5ZsCvfEdYQa53buGPbe/3cftNtzB26Ti
         swPT55m5mx8xHyHsLInuZiWnjx1y9aZEcDv99Uvl0VdhHycBgVRF+PmERuu8gxV6o93T
         +Sj+x5dxSIA7H7VThANGWS+WmVqPgjJBJU1bfQcIojYkwucDzlzIixkZkiOdslAkR0Ah
         t6wg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=f8ggBDvz;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id l22si132556pgt.3.2020.05.19.22.42.01
        for <kasan-dev@googlegroups.com>;
        Tue, 19 May 2020 22:42:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 33757d0f7d274cb196be9cd59a80459f-20200520
X-UUID: 33757d0f7d274cb196be9cd59a80459f-20200520
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1326968308; Wed, 20 May 2020 13:41:57 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 20 May 2020 13:41:55 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 20 May 2020 13:41:54 +0800
Message-ID: <1589953316.4440.12.camel@mtksdccf07>
Subject: Re: [PATCH v4 2/4] kasan: record and print the free track
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, Linux-MM
	<linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>
Date: Wed, 20 May 2020 13:41:56 +0800
In-Reply-To: <CACT4Y+Zy0O3brZRvN5jbdXMosBv+aFgRGSubbhCwzOSUftGoeA@mail.gmail.com>
References: <20200519022517.24182-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+aJDO+2kSgNpcvHksfn+bZaFWPoGj3-55-dyjLHcHbFUg@mail.gmail.com>
	 <1589947387.29577.35.camel@mtksdccf07>
	 <CACT4Y+Zy0O3brZRvN5jbdXMosBv+aFgRGSubbhCwzOSUftGoeA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=f8ggBDvz;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
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

> On Wed, May 20, 2020 at 6:03 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > > On Tue, May 19, 2020 at 4:25 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > >
> > > > Move free track from slub alloc meta-data to slub free meta-data in
> > > > order to make struct kasan_free_meta size is 16 bytes. It is a good
> > > > size because it is the minimal redzone size and a good number of
> > > > alignment.
> > > >
> > > > For free track in generic KASAN, we do the modification in struct
> > > > kasan_alloc_meta and kasan_free_meta:
> > > > - remove free track from kasan_alloc_meta.
> > > > - add free track into kasan_free_meta.
> > > >
> > > > [1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
> > > >
> > > > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > > Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> > > > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > > > Cc: Dmitry Vyukov <dvyukov@google.com>
> > > > Cc: Alexander Potapenko <glider@google.com>
> > > > ---
> > > >  mm/kasan/common.c  | 22 ++--------------------
> > > >  mm/kasan/generic.c | 18 ++++++++++++++++++
> > > >  mm/kasan/kasan.h   |  7 +++++++
> > > >  mm/kasan/report.c  | 20 --------------------
> > > >  mm/kasan/tags.c    | 37 +++++++++++++++++++++++++++++++++++++
> > > >  5 files changed, 64 insertions(+), 40 deletions(-)
> > > >
> > > > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > > > index 8bc618289bb1..47b53912f322 100644
> > > > --- a/mm/kasan/common.c
> > > > +++ b/mm/kasan/common.c
> > > > @@ -51,7 +51,7 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags)
> > > >         return stack_depot_save(entries, nr_entries, flags);
> > > >  }
> > > >
> > > > -static inline void set_track(struct kasan_track *track, gfp_t flags)
> > > > +void kasan_set_track(struct kasan_track *track, gfp_t flags)
> > > >  {
> > > >         track->pid = current->pid;
> > > >         track->stack = kasan_save_stack(flags);
> > > > @@ -299,24 +299,6 @@ struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
> > > >         return (void *)object + cache->kasan_info.free_meta_offset;
> > > >  }
> > > >
> > > > -
> > > > -static void kasan_set_free_info(struct kmem_cache *cache,
> > > > -               void *object, u8 tag)
> > > > -{
> > > > -       struct kasan_alloc_meta *alloc_meta;
> > > > -       u8 idx = 0;
> > > > -
> > > > -       alloc_meta = get_alloc_info(cache, object);
> > > > -
> > > > -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > > > -       idx = alloc_meta->free_track_idx;
> > > > -       alloc_meta->free_pointer_tag[idx] = tag;
> > > > -       alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
> > > > -#endif
> > > > -
> > > > -       set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
> > > > -}
> > > > -
> > > >  void kasan_poison_slab(struct page *page)
> > > >  {
> > > >         unsigned long i;
> > > > @@ -492,7 +474,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
> > > >                 KASAN_KMALLOC_REDZONE);
> > > >
> > > >         if (cache->flags & SLAB_KASAN)
> > > > -               set_track(&get_alloc_info(cache, object)->alloc_track, flags);
> > > > +               kasan_set_track(&get_alloc_info(cache, object)->alloc_track, flags);
> > > >
> > > >         return set_tag(object, tag);
> > > >  }
> > > > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > > > index 3372bdcaf92a..763d8a13e0ac 100644
> > > > --- a/mm/kasan/generic.c
> > > > +++ b/mm/kasan/generic.c
> > > > @@ -344,3 +344,21 @@ void kasan_record_aux_stack(void *addr)
> > > >         alloc_info->aux_stack[1] = alloc_info->aux_stack[0];
> > > >         alloc_info->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
> > > >  }
> > > > +
> > > > +void kasan_set_free_info(struct kmem_cache *cache,
> > > > +                               void *object, u8 tag)
> > > > +{
> > > > +       struct kasan_free_meta *free_meta;
> > > > +
> > > > +       free_meta = get_free_info(cache, object);
> > > > +       kasan_set_track(&free_meta->free_track, GFP_NOWAIT);
> > > > +}
> > > > +
> > > > +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > > > +                               void *object, u8 tag)
> > > > +{
> > > > +       struct kasan_free_meta *free_meta;
> > > > +
> > > > +       free_meta = get_free_info(cache, object);
> > > > +       return &free_meta->free_track;
> > > > +}
> > > > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > > > index a7391bc83070..ad897ec36545 100644
> > > > --- a/mm/kasan/kasan.h
> > > > +++ b/mm/kasan/kasan.h
> > > > @@ -127,6 +127,9 @@ struct kasan_free_meta {
> > > >          * Otherwise it might be used for the allocator freelist.
> > > >          */
> > > >         struct qlist_node quarantine_link;
> > > > +#ifdef CONFIG_KASAN_GENERIC
> > > > +       struct kasan_track free_track;
> > > > +#endif
> > > >  };
> > > >
> > > >  struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
> > > > @@ -168,6 +171,10 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
> > > >  struct page *kasan_addr_to_page(const void *addr);
> > > >
> > > >  depot_stack_handle_t kasan_save_stack(gfp_t flags);
> > > > +void kasan_set_track(struct kasan_track *track, gfp_t flags);
> > > > +void kasan_set_free_info(struct kmem_cache *cache, void *object, u8 tag);
> > > > +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > > > +                               void *object, u8 tag);
> > > >
> > > >  #if defined(CONFIG_KASAN_GENERIC) && \
> > > >         (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
> > > > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > > > index 6f8f2bf8f53b..96d2657fe70f 100644
> > > > --- a/mm/kasan/report.c
> > > > +++ b/mm/kasan/report.c
> > > > @@ -159,26 +159,6 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
> > > >                 (void *)(object_addr + cache->object_size));
> > > >  }
> > > >
> > > > -static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > > > -               void *object, u8 tag)
> > > > -{
> > > > -       struct kasan_alloc_meta *alloc_meta;
> > > > -       int i = 0;
> > > > -
> > > > -       alloc_meta = get_alloc_info(cache, object);
> > > > -
> > > > -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > > > -       for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
> > > > -               if (alloc_meta->free_pointer_tag[i] == tag)
> > > > -                       break;
> > > > -       }
> > > > -       if (i == KASAN_NR_FREE_STACKS)
> > > > -               i = alloc_meta->free_track_idx;
> > > > -#endif
> > > > -
> > > > -       return &alloc_meta->free_track[i];
> > > > -}
> > > > -
> > > >  #ifdef CONFIG_KASAN_GENERIC
> > > >  static void print_stack(depot_stack_handle_t stack)
> > > >  {
> > > > diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> > > > index 25b7734e7013..201dee5d6ae0 100644
> > > > --- a/mm/kasan/tags.c
> > > > +++ b/mm/kasan/tags.c
> > > > @@ -162,3 +162,40 @@ void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size)
> > > >         kasan_poison_shadow((void *)addr, size, tag);
> > > >  }
> > > >  EXPORT_SYMBOL(__hwasan_tag_memory);
> > > > +
> > > > +void kasan_set_free_info(struct kmem_cache *cache,
> > > > +                               void *object, u8 tag)
> > > > +{
> > > > +       struct kasan_alloc_meta *alloc_meta;
> > > > +       u8 idx = 0;
> > > > +
> > > > +       alloc_meta = get_alloc_info(cache, object);
> > > > +
> > > > +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > > > +       idx = alloc_meta->free_track_idx;
> > > > +       alloc_meta->free_pointer_tag[idx] = tag;
> > > > +       alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
> > > > +#endif
> > > > +
> > > > +       kasan_set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
> > > > +}
> > > > +
> > > > +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > > > +                               void *object, u8 tag)
> > > > +{
> > > > +       struct kasan_alloc_meta *alloc_meta;
> > > > +       int i = 0;
> > > > +
> > > > +       alloc_meta = get_alloc_info(cache, object);
> > > > +
> > > > +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > > > +       for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
> > > > +               if (alloc_meta->free_pointer_tag[i] == tag)
> > > > +                       break;
> > > > +       }
> > > > +       if (i == KASAN_NR_FREE_STACKS)
> > > > +               i = alloc_meta->free_track_idx;
> > > > +#endif
> > > > +
> > > > +       return &alloc_meta->free_track[i];
> > > > +}
> > >
> > > Hi Walter,
> > >
> > > FTR I've uploaded this for review purposes here:
> > > https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/2458
> > >
> > > Diff from the previous version is available as:
> > > https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/2458/1..2
> > >
> > > I've tested this locally and with syzkaller. This is :
> > >
> > > [   80.583021][    C3] Freed by task 0:
> > > [   80.583480][    C3]  kasan_save_stack+0x1b/0x40 mm/kasan/common.c:49
> > > [   80.584056][    C3]  kasan_set_track+0x1c/0x30 mm/kasan/common.c:57
> > > [   80.584617][    C3]  kasan_set_free_info+0x1b/0x30 mm/kasan/generic.c:354
> > > [   80.585221][    C3]  __kasan_slab_free+0xd8/0x120 mm/kasan/common.c:438
> > > [   80.585814][    C3]  __cache_free mm/slab.c:3426 [inline]
> > > [   80.585814][    C3]  kfree+0x10b/0x2b0 mm/slab.c:3757
> > > [   80.586291][    C3]  kasan_rcu_reclaim+0x16/0x43 [test_kasan]
> > > [   80.587009][    C3]  rcu_do_batch kernel/rcu/tree.c:2207 [inline]
> > > [   80.587009][    C3]  rcu_core+0x59f/0x1370 kernel/rcu/tree.c:2434
> > > [   80.587537][    C3]  __do_softirq+0x26c/0x9fa kernel/softirq.c:292
> > > [   80.588085][    C3]
> > > [   80.588367][    C3] Last one call_rcu() call stack:
> > > [   80.589052][    C3]  kasan_save_stack+0x1b/0x40 mm/kasan/common.c:49
> > > [   80.589622][    C3]  kasan_record_aux_stack+0x82/0xb0 mm/kasan/generic.c:345
> > > [   80.590254][    C3]  __call_rcu kernel/rcu/tree.c:2672 [inline]
> > > [   80.590254][    C3]  call_rcu+0x14f/0x7f0 kernel/rcu/tree.c:2746
> > > [   80.590782][    C3]  kasan_rcu_uaf+0xe4/0xeb [test_kasan]
> > > [   80.591697][    C3]  kmalloc_tests_init+0xbc/0x1097 [test_kasan]
> > > [   80.592900][    C3]  do_one_initcall+0x10a/0x7d0 init/main.c:1196
> > > [   80.593494][    C3]  do_init_module+0x1e6/0x6d0 kernel/module.c:3539
> > > [   80.594066][    C3]  load_module+0x7464/0x9450 kernel/module.c:3890
> > > [   80.594626][    C3]  __do_sys_init_module+0x1e3/0x220 kernel/module.c:3953
> > > [   80.595265][    C3]  do_syscall_64+0xf6/0x7d0 arch/x86/entry/common.c:295
> > > [   80.595822][    C3]  entry_SYSCALL_64_after_hwframe+0x49/0xb3
> > >
> > >
> > > Overall this looks very good to me.
> > > But there is one aspect that bothers me. In the previous patch you had
> > > code that returned NULL from kasan_get_free_track() if the object is
> > > live (which means free meta is not available, it's occupied by object
> > > data). Now you dropped that code, but I think we still need it.
> > > Otherwise we cast user object data to free meta and print the free
> > > stack/pid from whatever garbage is there. This may lead to very
> > > confusing output and potentially to crashes in stackdepot.
> > >
> >
> > Yes, I totally agree with you. In the previous email I thought that
> > there is a problem with free track, but I did not point it out. Thank
> > you for pointing this problem. As you mentioned, we should fix it.
> >
> > > What do you think about this patch on top of your patches?
> > > https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/2478
> > > This way we very precisely mark the period of time when the object has
> > > free track live and set.
> > > If it looks good to you, feel free to incorporate it into your series.
> > >
> >
> > Thank you for providing good idea solution.
> >
> > I saw this patch, that is a great patch. I think it can fix the issue
> > which has garbage stack. it should work as described below.
> >
> > 1). When object is live, then don't print free stack.
> > 2). When object is NOT alive, after free object:
> > 2a). when object is in quarantine, then it can print free stack
> > 2b). when object is NOT in quarantine, then it can NOT print free stack.
> >
> > I have a question about 2), why we don't directly use
> > KASAN_KMALLOC_FREE? if we directly use it, then 2b) can print free
> > stack? 2b) may has use-after-free? so that it may need free stack.
> 
> 
> We can't use KASAN_KMALLOC_FREE because of this part:
> 
> static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
>                   unsigned long ip, bool quarantine)
> {
> ...
>     kasan_poison_shadow(object, rounded_up_size, KASAN_KMALLOC_FREE);
> 
>     if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
>             unlikely(!(cache->flags & SLAB_KASAN)))
>         return false;
> 
>     kasan_set_free_info(cache, object, tag);
> ...
> 
> 
> We may set KASAN_KMALLOC_FREE, but not set the track (or even have
> memory for the track!).
> The object may not have free meta allocated at all, e.g. very large
> object with ctor (no place to store meta), or it may be in a mempool:
> https://elixir.bootlin.com/linux/v5.7-rc6/source/mm/mempool.c#L109
> and mempool may be using the object memory itself (for its own next
> link or something).
> 
> KASAN_KMALLOC_FREETRACK very explicitly tracks the exact condition we
> want: we have meta info live now and we have free track set.

Yes, as you said, it is needed by this change.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1589953316.4440.12.camel%40mtksdccf07.
