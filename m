Return-Path: <kasan-dev+bncBCMIZB7QWENRBWPLSL3AKGQE5HLBFYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 55A321DA963
	for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 06:45:14 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id r17sf1358076iom.7
        for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 21:45:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589949913; cv=pass;
        d=google.com; s=arc-20160816;
        b=TF+jk7x8tA0Dpdu3EXPj0nsy+lHqTE+hl/+266kKDZtZ5tx0rg30op3JI4IuWgUjpT
         nsKKzRv3fCtZNbIHTSW7Ruik787f/RDY0qUI+1Ybd6P+f2ox48j+lvPWERqkPyNbXq4Q
         T3QdrN8yh7intd8gQzGd3UIoYOMUyYjLdPMmOSwXEKQBpkY2gjz7kQxLZ8tXKJEQg8mv
         AKPBBQA4gRKMQm9xRh6DgKTkIZKnrU5lwvso8kcQFgw2kg3hPhgrWLEXl1b+LMmI6fZL
         nRTVwFIR7mtkyYWwcxSJUx76QRpwXXn3lcgo2934aMJuWSgxklTht8EH1TFTXoh0hqIv
         kKTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=QcrLpTbQo46yOnKHkOAp/nwOCnsnJowgcAgKW6XUESQ=;
        b=IAXy7r7TQUMYqwNZ1G4wACJ1WpOcgxy3+8FACkPsDFf0vlge74mDRr4b4Yd0dOmJrp
         YNtzYj3SetFvF8YxrTHdEhAxx+45N16I4pfcxr5W6zVXhrI+Ya4ZPUZ6NmfGM7Yvcgh5
         uPnkYUwoFEHKai6toUMAJl6WAuTGNoeWIQG44Bo4SlI/6xSFHK4Ht9IEscVdp3lQSA3W
         SPFpaQmHH1eDW+2UR0BWs05mxp6N2P9/sqFXGAOClM9drHftSZSFGY+UXMpBPYFijlz8
         8eQkSalLl6Lgl7LPJE54TrBKPa82yHXzM2ZZYUqhHCWMBnbeFmVLuUuTTfm9Kqtlqwlc
         Ldtw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IksOG6lq;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QcrLpTbQo46yOnKHkOAp/nwOCnsnJowgcAgKW6XUESQ=;
        b=QpnnUfariE6jvQWmDGWKLWeX8g9pHvdLB/92wjNvk4N5c1DYxbSY+I+xrck+IyyLSV
         TsagV+xgKMRYhXEMJFu8kUn56B5LJf1hg3ZaiIneP6qb7ZTaI0vi/vMAcAiEF0BvNIfd
         B7dzGsNdI+MbH7OKBprRBvchRK0SkhIyYrWWbgQZGVdtu6Gnx5KlnHXsJWkklPH0uWmx
         s17k3MQnccFsY4vp8h1AEn65NUKXaA9YLVBf3DXBV0t7CRYYBVPHqcVGBnE3qZfo0O55
         ekHMfAwxHe1cDdI0+YfX/uQtH5M4DELQdRSxQHiR4hYbC03bYXsjg/feQnhSEmaJpLtF
         qYlg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QcrLpTbQo46yOnKHkOAp/nwOCnsnJowgcAgKW6XUESQ=;
        b=YWZPwSXkpkVToGNz5i5LGm2PcnKE66k7f5817glRHGovDu8hP1z2nfoRc1OaC7at43
         KRpwK9FEiLO8vWV2ax1dm7YDqUVDNnt0oK/7vBsV7OiFn9LWjrXfpdGd/+eTMERjZBb/
         Owz1X1d6Xoga7ymFBynbbF6OIikPLOH+PXsAUlGk9j4eTn3x/bgWbS+oSLZI4Eekj3sd
         y2fvRWLFUl1U/qOOSw1meSx6wrbZLIzQMp1w51Nlp85VfQWiVy8Ew6vK5CclPg9Q7oqv
         ojk+Aj43SrJlpOVuXO/b8D7OQDdJUwwBTdgXn0QxudCWXMetTlVTGgmspIPEPItoruAn
         DVZQ==
X-Gm-Message-State: AOAM530lJK7XhsfES8nT+7Gvaj2V+TSs+Wnh9i4VJjZK9mGBBjnBO+AE
	wtKrW+enCs0lV+fKwMrXiYg=
X-Google-Smtp-Source: ABdhPJwCUqvxNCIrvXNCXXjFp02N4xfjBIEEGfM8XRtCmPp8msmac3XSCpZcIUztnurOIjsvNvKAtQ==
X-Received: by 2002:a05:6e02:13e3:: with SMTP id w3mr2117639ilj.62.1589949913135;
        Tue, 19 May 2020 21:45:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5e:9806:: with SMTP id s6ls313612ioj.8.gmail; Tue, 19 May
 2020 21:45:12 -0700 (PDT)
X-Received: by 2002:a6b:7c45:: with SMTP id b5mr2028609ioq.31.1589949912767;
        Tue, 19 May 2020 21:45:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589949912; cv=none;
        d=google.com; s=arc-20160816;
        b=0Z21WrlkhmCuNtMnybFi9n0Dp6I+scU7uY/BiG8GwIC4OER1pHulePrGI/MWhDuVoH
         f3YWKbxV5g+xqiTYqAF1FRBXqrqINiomY4xvmvlDYjWhkMqJ+E5uEPz+HsFGVR3PAXqM
         VIpSVtAO2Lwn6/isdtEupqjmOqiuTdT90psdLWR/wEUl5LjYbOWy83Fl+xKegEGvPuQd
         wijj2F9rBIaelEPcIXDuLY2yc5hJaOD54wruKINrPzEUBQls3pteFV/CHhE0UZdJmuUY
         ny+D2EHvDrEnjBnHP6sV6w/2awO/h4Hozz1riZ79iCCRnmik7kUNo1li4xbqP1dclr6D
         sPOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SNby9Ybh2Qrd4287Y3ZzbQLjxz1GHTGW0zNl9NdTkP0=;
        b=lti57sj4+XRO/d3ojBwB2//wZ768C0FP3ZB2vKwGbV+RWrn9lVJL5NVS2qgfAueJgp
         JfxIlzIILlmvSdXwHJJk37NbK5nuL7dKZmOp7crUXKrEgrjoNg66v5ELo6OmSLwGrqpl
         Pcd5c51G2+AjslzhY5pzZe1wLpxzYm4wFIOoEKv/AI4U97GWraFUM00AnvBSxCOycAqF
         iEHTdbwkToWegqjc33cFqffXfL/DhCcQUDU1EupGI3rEoTC02RhX+SVYy+oPqO1DhMRc
         O+Wabv6/PXChHg5pcsjbCDU8KIJN0o9IhswuVp3JodzkePvN4wG3Uk9PlLMtud0HEnYV
         J2UQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IksOG6lq;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf41.google.com (mail-qv1-xf41.google.com. [2607:f8b0:4864:20::f41])
        by gmr-mx.google.com with ESMTPS id d3si90914ilg.0.2020.05.19.21.45.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 May 2020 21:45:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) client-ip=2607:f8b0:4864:20::f41;
Received: by mail-qv1-xf41.google.com with SMTP id z5so768483qvw.4
        for <kasan-dev@googlegroups.com>; Tue, 19 May 2020 21:45:12 -0700 (PDT)
X-Received: by 2002:a0c:db03:: with SMTP id d3mr3196334qvk.80.1589949911824;
 Tue, 19 May 2020 21:45:11 -0700 (PDT)
MIME-Version: 1.0
References: <20200519022517.24182-1-walter-zh.wu@mediatek.com>
 <CACT4Y+aJDO+2kSgNpcvHksfn+bZaFWPoGj3-55-dyjLHcHbFUg@mail.gmail.com> <1589947387.29577.35.camel@mtksdccf07>
In-Reply-To: <1589947387.29577.35.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 May 2020 06:45:00 +0200
Message-ID: <CACT4Y+Zy0O3brZRvN5jbdXMosBv+aFgRGSubbhCwzOSUftGoeA@mail.gmail.com>
Subject: Re: [PATCH v4 2/4] kasan: record and print the free track
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=IksOG6lq;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41
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

On Wed, May 20, 2020 at 6:03 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> > On Tue, May 19, 2020 at 4:25 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
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
> > >  mm/kasan/common.c  | 22 ++--------------------
> > >  mm/kasan/generic.c | 18 ++++++++++++++++++
> > >  mm/kasan/kasan.h   |  7 +++++++
> > >  mm/kasan/report.c  | 20 --------------------
> > >  mm/kasan/tags.c    | 37 +++++++++++++++++++++++++++++++++++++
> > >  5 files changed, 64 insertions(+), 40 deletions(-)
> > >
> > > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > > index 8bc618289bb1..47b53912f322 100644
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
> > > @@ -299,24 +299,6 @@ struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
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
> > > @@ -492,7 +474,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
> > >                 KASAN_KMALLOC_REDZONE);
> > >
> > >         if (cache->flags & SLAB_KASAN)
> > > -               set_track(&get_alloc_info(cache, object)->alloc_track, flags);
> > > +               kasan_set_track(&get_alloc_info(cache, object)->alloc_track, flags);
> > >
> > >         return set_tag(object, tag);
> > >  }
> > > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > > index 3372bdcaf92a..763d8a13e0ac 100644
> > > --- a/mm/kasan/generic.c
> > > +++ b/mm/kasan/generic.c
> > > @@ -344,3 +344,21 @@ void kasan_record_aux_stack(void *addr)
> > >         alloc_info->aux_stack[1] = alloc_info->aux_stack[0];
> > >         alloc_info->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
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
> > > index a7391bc83070..ad897ec36545 100644
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
> > > index 6f8f2bf8f53b..96d2657fe70f 100644
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
> >
> > Hi Walter,
> >
> > FTR I've uploaded this for review purposes here:
> > https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/2458
> >
> > Diff from the previous version is available as:
> > https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/2458/1..2
> >
> > I've tested this locally and with syzkaller. This is :
> >
> > [   80.583021][    C3] Freed by task 0:
> > [   80.583480][    C3]  kasan_save_stack+0x1b/0x40 mm/kasan/common.c:49
> > [   80.584056][    C3]  kasan_set_track+0x1c/0x30 mm/kasan/common.c:57
> > [   80.584617][    C3]  kasan_set_free_info+0x1b/0x30 mm/kasan/generic.c:354
> > [   80.585221][    C3]  __kasan_slab_free+0xd8/0x120 mm/kasan/common.c:438
> > [   80.585814][    C3]  __cache_free mm/slab.c:3426 [inline]
> > [   80.585814][    C3]  kfree+0x10b/0x2b0 mm/slab.c:3757
> > [   80.586291][    C3]  kasan_rcu_reclaim+0x16/0x43 [test_kasan]
> > [   80.587009][    C3]  rcu_do_batch kernel/rcu/tree.c:2207 [inline]
> > [   80.587009][    C3]  rcu_core+0x59f/0x1370 kernel/rcu/tree.c:2434
> > [   80.587537][    C3]  __do_softirq+0x26c/0x9fa kernel/softirq.c:292
> > [   80.588085][    C3]
> > [   80.588367][    C3] Last one call_rcu() call stack:
> > [   80.589052][    C3]  kasan_save_stack+0x1b/0x40 mm/kasan/common.c:49
> > [   80.589622][    C3]  kasan_record_aux_stack+0x82/0xb0 mm/kasan/generic.c:345
> > [   80.590254][    C3]  __call_rcu kernel/rcu/tree.c:2672 [inline]
> > [   80.590254][    C3]  call_rcu+0x14f/0x7f0 kernel/rcu/tree.c:2746
> > [   80.590782][    C3]  kasan_rcu_uaf+0xe4/0xeb [test_kasan]
> > [   80.591697][    C3]  kmalloc_tests_init+0xbc/0x1097 [test_kasan]
> > [   80.592900][    C3]  do_one_initcall+0x10a/0x7d0 init/main.c:1196
> > [   80.593494][    C3]  do_init_module+0x1e6/0x6d0 kernel/module.c:3539
> > [   80.594066][    C3]  load_module+0x7464/0x9450 kernel/module.c:3890
> > [   80.594626][    C3]  __do_sys_init_module+0x1e3/0x220 kernel/module.c:3953
> > [   80.595265][    C3]  do_syscall_64+0xf6/0x7d0 arch/x86/entry/common.c:295
> > [   80.595822][    C3]  entry_SYSCALL_64_after_hwframe+0x49/0xb3
> >
> >
> > Overall this looks very good to me.
> > But there is one aspect that bothers me. In the previous patch you had
> > code that returned NULL from kasan_get_free_track() if the object is
> > live (which means free meta is not available, it's occupied by object
> > data). Now you dropped that code, but I think we still need it.
> > Otherwise we cast user object data to free meta and print the free
> > stack/pid from whatever garbage is there. This may lead to very
> > confusing output and potentially to crashes in stackdepot.
> >
>
> Yes, I totally agree with you. In the previous email I thought that
> there is a problem with free track, but I did not point it out. Thank
> you for pointing this problem. As you mentioned, we should fix it.
>
> > What do you think about this patch on top of your patches?
> > https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/2478
> > This way we very precisely mark the period of time when the object has
> > free track live and set.
> > If it looks good to you, feel free to incorporate it into your series.
> >
>
> Thank you for providing good idea solution.
>
> I saw this patch, that is a great patch. I think it can fix the issue
> which has garbage stack. it should work as described below.
>
> 1). When object is live, then don't print free stack.
> 2). When object is NOT alive, after free object:
> 2a). when object is in quarantine, then it can print free stack
> 2b). when object is NOT in quarantine, then it can NOT print free stack.
>
> I have a question about 2), why we don't directly use
> KASAN_KMALLOC_FREE? if we directly use it, then 2b) can print free
> stack? 2b) may has use-after-free? so that it may need free stack.


We can't use KASAN_KMALLOC_FREE because of this part:

static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
                  unsigned long ip, bool quarantine)
{
...
    kasan_poison_shadow(object, rounded_up_size, KASAN_KMALLOC_FREE);

    if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
            unlikely(!(cache->flags & SLAB_KASAN)))
        return false;

    kasan_set_free_info(cache, object, tag);
...


We may set KASAN_KMALLOC_FREE, but not set the track (or even have
memory for the track!).
The object may not have free meta allocated at all, e.g. very large
object with ctor (no place to store meta), or it may be in a mempool:
https://elixir.bootlin.com/linux/v5.7-rc6/source/mm/mempool.c#L109
and mempool may be using the object memory itself (for its own next
link or something).

KASAN_KMALLOC_FREETRACK very explicitly tracks the exact condition we
want: we have meta info live now and we have free track set.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZy0O3brZRvN5jbdXMosBv%2BaFgRGSubbhCwzOSUftGoeA%40mail.gmail.com.
