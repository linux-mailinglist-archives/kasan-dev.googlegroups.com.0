Return-Path: <kasan-dev+bncBDGPTM5BQUDRBFPLSP3AKGQE33OWUEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 79F021DAE80
	for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 11:17:10 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id v1sf1235751ybo.23
        for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 02:17:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589966229; cv=pass;
        d=google.com; s=arc-20160816;
        b=peEyEQp17PUs4suMtrRaaRjvpKqOoLT/Wzbeg7vP6xH55hRUhtOFHZNBEPcNeZ5dXN
         dra7IufbM2aGUdwMaUtgBmqPlkt+Ad0jqzN0LEvj761N+U/6sg5dgYWup3K9GnKi6w/W
         MiVuOmAfgIBTrg5EtsZrqpHpE2i/wi/s7jee+OUGwRAvzY47PIALNy6I51CevRjrszcJ
         /0w/cjonyA++81oHxGAz5fglFBhw0ivLe0sjdOxEAwMu04FvKZmGRS1JAMKaOajx39bI
         0Ae/UTYmZVlQ3mHMCzZ+iMPfI9ZIweAtbKjT+37ifsXlcSojTEgs7xnW8cMRvVbkv999
         zZ9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=Q7ZLJiH+l7BGG6w81EyWybobpyvMwURuQbDSQRf1lWo=;
        b=Sn0S0m+X7AYrzItsMzCTr6sMxE+UkkNS2nfcTDl8Wsj+4Fx020wzsJ2sPIb3gMyTcl
         Jivld0ssIhkKZr1z9uQPrfjlicIjwf8X8e0sXtN+yOmSuhWC+McZbDzDkkt4Sip0bhM2
         kion6myq8LNI1DxgLkwfzBXimXXz7HC1mQK7p5bKiN6iWVKQq6VvmqtuC08hazP1pjFt
         0q2DBWG88MiHRdDhlO7ZPJE3Zv7Ic5QSqbA3nOtOUiAL5Mg3tJ1wNnUMlSbmvGJmz2JD
         c+oGmBKYbcfpfo6FTTidpiQ7dF+tQSyx2Tmoj2tLFmdBvOY3Eg8RI+Z1EiJgYCD4Pg2A
         ZbAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=n8zrKAPP;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q7ZLJiH+l7BGG6w81EyWybobpyvMwURuQbDSQRf1lWo=;
        b=X9miwHfsB+MHIXRbwTSS9ThF4r72m3N7GOQyRqE9xqqmRb7JL+H17/dSDMaXSYvxd0
         8mIH6ZCNNvRdn27tsW1QQtEKSzX89oTkGCfp5679HKguDixzqXH82GtSVGHt8A1lp9mS
         r9jbtJWv/yV0lNAXO83k8HzcILd04sIs2B3YF0VaRAcMh9/G8VexIsdvgr+rONnMlDbO
         NIxkzScw1RLEy7lOorh/WKUFdkHhz88zz345aoxBqaewuMlJc1KBMpXaGGvHyVfjK6eX
         54EDIuiwVr427oZvz5jsc70SigmA4i9FB9YpPA1XIYqe/2F7jJ6AmZ96cdR8kEm6raes
         tHrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q7ZLJiH+l7BGG6w81EyWybobpyvMwURuQbDSQRf1lWo=;
        b=KiLrkqwX8H4ueDnjku1gW+bRvxnGxpQm0ktw8yU+nxkqloVjzxtoR8nwVki+jAyb50
         K2MVGISpmIvOIMTgsucYKEPpXYnp1ZM00HKNDwx06APLCCFY8QWkR7AuqlTsN1bKCm1f
         PDbfYBp/tVoQgFeVjPXbA6dzrVl4uNhqRsBcuSHLScS4f/xo0G09oagKGn6vPguQwL4Z
         g+7nFQihM36Tnb0cARGTRNgrqpsAz3Qi7akpshiTI3jbhILie1ZEcVf+b13m9lKOVCC2
         mE5kRNCbGfmyST4PWeDTx8BV/50R0Nas3wg3B2j6Lzpoi1n2qXA9VGlQppaD2wp/X5g8
         PGKA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531oTzzYQCci8VcnX8DzOJghB+fD3R+gR5ANLUwxYWlgB9/DiCX1
	n2cDsFQU9ZXACxMjU9KHCRc=
X-Google-Smtp-Source: ABdhPJz68THlOGejIOgSNt4jVNty/ORSy0ycU3bVoGPpksGXwAOETnIYZGAbmSowABJVktCGhiDXrA==
X-Received: by 2002:a25:13c5:: with SMTP id 188mr5528982ybt.353.1589966229452;
        Wed, 20 May 2020 02:17:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:be4d:: with SMTP id d13ls928788ybm.2.gmail; Wed, 20 May
 2020 02:17:09 -0700 (PDT)
X-Received: by 2002:a25:bb08:: with SMTP id z8mr5685531ybg.129.1589966229071;
        Wed, 20 May 2020 02:17:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589966229; cv=none;
        d=google.com; s=arc-20160816;
        b=K0yH/ALDSV6hvmfkx32SnFP2lRNOOQLdSmNe1YldoC3/UKpf2dWa7jvyh3VbjGfX+G
         pFZHxayRPnHu44HkOGbQlbvm3M5Gn6BacpttyQlWsNQyYNFdnvt8/43kX2lwwkRThKkx
         +hLIKduLlavF25ecITaor7ce4LCwgqPmD30uCn5Nx3Mszunv5sDO71z8gb4UzgPrmv34
         Ra/JLJOKY1YH0WU/YOpHvrNh71Vy7/rPsZAfihGab0FxvgaxVmPUHXYDPNPC1wNYANzG
         nF8XWVOxJemw+aYCHQVCA4sU2WNArjKnklKdzXyp8y+hERMPjlA/SpCOqE1OFyG+z4zn
         X3eA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=GgFKY5TA54aiL2c8IIB1pKoJZCio1gYPWkrJIRlvhOo=;
        b=QUXXllbn0hUIgeasIypx1UdT6bMgt7igDmgDYSDP4QnSX7LTRGZ6TMPqXygZmUQLy/
         8aHHoe49Kby+nlbP549Xe+/ELbhZbczMhB18ldub2AY5EPMdQe8HdmHe5+74F50abvgi
         0lDHHrlUocJ6dUAXtndkyUB1Xqi3q/wfhZVprS9qQC859ecRhzlfhBvuk8nwqT2IFMI1
         xDrPBjJ+/yLzwef4sBpBTgCF+fIWSB+GlqoRN+Sm9gO9/ZybAfY/vfLiVPPVRsgG7Bhh
         Vjko8V5EvAbbbE1GpmV4ybzH+iDJcYJZu+RPL+iOqodbCzYdBFX/15PIqaBcQYfrD4sB
         hP+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=n8zrKAPP;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id l199si129981ybl.5.2020.05.20.02.17.08
        for <kasan-dev@googlegroups.com>;
        Wed, 20 May 2020 02:17:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 380035610f8745719597dfc818bc3bc0-20200520
X-UUID: 380035610f8745719597dfc818bc3bc0-20200520
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 646279205; Wed, 20 May 2020 17:17:03 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 20 May 2020 17:17:00 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 20 May 2020 17:16:59 +0800
Message-ID: <1589966220.14692.24.camel@mtksdccf07>
Subject: Re: [PATCH v4 2/4] kasan: record and print the free track
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, Linux-MM
	<linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>
Date: Wed, 20 May 2020 17:17:00 +0800
In-Reply-To: <CACT4Y+Z42fQe4ijnA7HksAqrnpyzGU5pyY2bRFBETsL-mkB9_g@mail.gmail.com>
References: <20200519022517.24182-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+aJDO+2kSgNpcvHksfn+bZaFWPoGj3-55-dyjLHcHbFUg@mail.gmail.com>
	 <1589947387.29577.35.camel@mtksdccf07>
	 <CACT4Y+Zy0O3brZRvN5jbdXMosBv+aFgRGSubbhCwzOSUftGoeA@mail.gmail.com>
	 <1589951659.4440.4.camel@mtksdccf07> <1589955526.4440.22.camel@mtksdccf07>
	 <CACT4Y+Z42fQe4ijnA7HksAqrnpyzGU5pyY2bRFBETsL-mkB9_g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=n8zrKAPP;       spf=pass
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

> On Wed, May 20, 2020 at 8:18 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > On Wed, 2020-05-20 at 13:14 +0800, Walter Wu wrote:
> > > > On Wed, May 20, 2020 at 6:03 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > > >
> > > > > > On Tue, May 19, 2020 at 4:25 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > > > > >
> > > > > > > Move free track from slub alloc meta-data to slub free meta-data in
> > > > > > > order to make struct kasan_free_meta size is 16 bytes. It is a good
> > > > > > > size because it is the minimal redzone size and a good number of
> > > > > > > alignment.
> > > > > > >
> > > > > > > For free track in generic KASAN, we do the modification in struct
> > > > > > > kasan_alloc_meta and kasan_free_meta:
> > > > > > > - remove free track from kasan_alloc_meta.
> > > > > > > - add free track into kasan_free_meta.
> > > > > > >
> > > > > > > [1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
> > > > > > >
> > > > > > > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > > > > > Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> > > > > > > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > > > > > > Cc: Dmitry Vyukov <dvyukov@google.com>
> > > > > > > Cc: Alexander Potapenko <glider@google.com>
> > > > > > > ---
> > > > > > >  mm/kasan/common.c  | 22 ++--------------------
> > > > > > >  mm/kasan/generic.c | 18 ++++++++++++++++++
> > > > > > >  mm/kasan/kasan.h   |  7 +++++++
> > > > > > >  mm/kasan/report.c  | 20 --------------------
> > > > > > >  mm/kasan/tags.c    | 37 +++++++++++++++++++++++++++++++++++++
> > > > > > >  5 files changed, 64 insertions(+), 40 deletions(-)
> > > > > > >
> > > > > > > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > > > > > > index 8bc618289bb1..47b53912f322 100644
> > > > > > > --- a/mm/kasan/common.c
> > > > > > > +++ b/mm/kasan/common.c
> > > > > > > @@ -51,7 +51,7 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags)
> > > > > > >         return stack_depot_save(entries, nr_entries, flags);
> > > > > > >  }
> > > > > > >
> > > > > > > -static inline void set_track(struct kasan_track *track, gfp_t flags)
> > > > > > > +void kasan_set_track(struct kasan_track *track, gfp_t flags)
> > > > > > >  {
> > > > > > >         track->pid = current->pid;
> > > > > > >         track->stack = kasan_save_stack(flags);
> > > > > > > @@ -299,24 +299,6 @@ struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
> > > > > > >         return (void *)object + cache->kasan_info.free_meta_offset;
> > > > > > >  }
> > > > > > >
> > > > > > > -
> > > > > > > -static void kasan_set_free_info(struct kmem_cache *cache,
> > > > > > > -               void *object, u8 tag)
> > > > > > > -{
> > > > > > > -       struct kasan_alloc_meta *alloc_meta;
> > > > > > > -       u8 idx = 0;
> > > > > > > -
> > > > > > > -       alloc_meta = get_alloc_info(cache, object);
> > > > > > > -
> > > > > > > -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > > > > > > -       idx = alloc_meta->free_track_idx;
> > > > > > > -       alloc_meta->free_pointer_tag[idx] = tag;
> > > > > > > -       alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
> > > > > > > -#endif
> > > > > > > -
> > > > > > > -       set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
> > > > > > > -}
> > > > > > > -
> > > > > > >  void kasan_poison_slab(struct page *page)
> > > > > > >  {
> > > > > > >         unsigned long i;
> > > > > > > @@ -492,7 +474,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
> > > > > > >                 KASAN_KMALLOC_REDZONE);
> > > > > > >
> > > > > > >         if (cache->flags & SLAB_KASAN)
> > > > > > > -               set_track(&get_alloc_info(cache, object)->alloc_track, flags);
> > > > > > > +               kasan_set_track(&get_alloc_info(cache, object)->alloc_track, flags);
> > > > > > >
> > > > > > >         return set_tag(object, tag);
> > > > > > >  }
> > > > > > > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > > > > > > index 3372bdcaf92a..763d8a13e0ac 100644
> > > > > > > --- a/mm/kasan/generic.c
> > > > > > > +++ b/mm/kasan/generic.c
> > > > > > > @@ -344,3 +344,21 @@ void kasan_record_aux_stack(void *addr)
> > > > > > >         alloc_info->aux_stack[1] = alloc_info->aux_stack[0];
> > > > > > >         alloc_info->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
> > > > > > >  }
> > > > > > > +
> > > > > > > +void kasan_set_free_info(struct kmem_cache *cache,
> > > > > > > +                               void *object, u8 tag)
> > > > > > > +{
> > > > > > > +       struct kasan_free_meta *free_meta;
> > > > > > > +
> > > > > > > +       free_meta = get_free_info(cache, object);
> > > > > > > +       kasan_set_track(&free_meta->free_track, GFP_NOWAIT);
> > > > > > > +}
> > > > > > > +
> > > > > > > +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > > > > > > +                               void *object, u8 tag)
> > > > > > > +{
> > > > > > > +       struct kasan_free_meta *free_meta;
> > > > > > > +
> > > > > > > +       free_meta = get_free_info(cache, object);
> > > > > > > +       return &free_meta->free_track;
> > > > > > > +}
> > > > > > > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > > > > > > index a7391bc83070..ad897ec36545 100644
> > > > > > > --- a/mm/kasan/kasan.h
> > > > > > > +++ b/mm/kasan/kasan.h
> > > > > > > @@ -127,6 +127,9 @@ struct kasan_free_meta {
> > > > > > >          * Otherwise it might be used for the allocator freelist.
> > > > > > >          */
> > > > > > >         struct qlist_node quarantine_link;
> > > > > > > +#ifdef CONFIG_KASAN_GENERIC
> > > > > > > +       struct kasan_track free_track;
> > > > > > > +#endif
> > > > > > >  };
> > > > > > >
> > > > > > >  struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
> > > > > > > @@ -168,6 +171,10 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
> > > > > > >  struct page *kasan_addr_to_page(const void *addr);
> > > > > > >
> > > > > > >  depot_stack_handle_t kasan_save_stack(gfp_t flags);
> > > > > > > +void kasan_set_track(struct kasan_track *track, gfp_t flags);
> > > > > > > +void kasan_set_free_info(struct kmem_cache *cache, void *object, u8 tag);
> > > > > > > +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > > > > > > +                               void *object, u8 tag);
> > > > > > >
> > > > > > >  #if defined(CONFIG_KASAN_GENERIC) && \
> > > > > > >         (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
> > > > > > > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > > > > > > index 6f8f2bf8f53b..96d2657fe70f 100644
> > > > > > > --- a/mm/kasan/report.c
> > > > > > > +++ b/mm/kasan/report.c
> > > > > > > @@ -159,26 +159,6 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
> > > > > > >                 (void *)(object_addr + cache->object_size));
> > > > > > >  }
> > > > > > >
> > > > > > > -static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > > > > > > -               void *object, u8 tag)
> > > > > > > -{
> > > > > > > -       struct kasan_alloc_meta *alloc_meta;
> > > > > > > -       int i = 0;
> > > > > > > -
> > > > > > > -       alloc_meta = get_alloc_info(cache, object);
> > > > > > > -
> > > > > > > -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > > > > > > -       for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
> > > > > > > -               if (alloc_meta->free_pointer_tag[i] == tag)
> > > > > > > -                       break;
> > > > > > > -       }
> > > > > > > -       if (i == KASAN_NR_FREE_STACKS)
> > > > > > > -               i = alloc_meta->free_track_idx;
> > > > > > > -#endif
> > > > > > > -
> > > > > > > -       return &alloc_meta->free_track[i];
> > > > > > > -}
> > > > > > > -
> > > > > > >  #ifdef CONFIG_KASAN_GENERIC
> > > > > > >  static void print_stack(depot_stack_handle_t stack)
> > > > > > >  {
> > > > > > > diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> > > > > > > index 25b7734e7013..201dee5d6ae0 100644
> > > > > > > --- a/mm/kasan/tags.c
> > > > > > > +++ b/mm/kasan/tags.c
> > > > > > > @@ -162,3 +162,40 @@ void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size)
> > > > > > >         kasan_poison_shadow((void *)addr, size, tag);
> > > > > > >  }
> > > > > > >  EXPORT_SYMBOL(__hwasan_tag_memory);
> > > > > > > +
> > > > > > > +void kasan_set_free_info(struct kmem_cache *cache,
> > > > > > > +                               void *object, u8 tag)
> > > > > > > +{
> > > > > > > +       struct kasan_alloc_meta *alloc_meta;
> > > > > > > +       u8 idx = 0;
> > > > > > > +
> > > > > > > +       alloc_meta = get_alloc_info(cache, object);
> > > > > > > +
> > > > > > > +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > > > > > > +       idx = alloc_meta->free_track_idx;
> > > > > > > +       alloc_meta->free_pointer_tag[idx] = tag;
> > > > > > > +       alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
> > > > > > > +#endif
> > > > > > > +
> > > > > > > +       kasan_set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
> > > > > > > +}
> > > > > > > +
> > > > > > > +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > > > > > > +                               void *object, u8 tag)
> > > > > > > +{
> > > > > > > +       struct kasan_alloc_meta *alloc_meta;
> > > > > > > +       int i = 0;
> > > > > > > +
> > > > > > > +       alloc_meta = get_alloc_info(cache, object);
> > > > > > > +
> > > > > > > +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > > > > > > +       for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
> > > > > > > +               if (alloc_meta->free_pointer_tag[i] == tag)
> > > > > > > +                       break;
> > > > > > > +       }
> > > > > > > +       if (i == KASAN_NR_FREE_STACKS)
> > > > > > > +               i = alloc_meta->free_track_idx;
> > > > > > > +#endif
> > > > > > > +
> > > > > > > +       return &alloc_meta->free_track[i];
> > > > > > > +}
> > > > > >
> > > > > > Hi Walter,
> > > > > >
> > > > > > FTR I've uploaded this for review purposes here:
> > > > > > https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/2458
> > > > > >
> > > > > > Diff from the previous version is available as:
> > > > > > https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/2458/1..2
> > > > > >
> > > > > > I've tested this locally and with syzkaller. This is :
> > > > > >
> > > > > > [   80.583021][    C3] Freed by task 0:
> > > > > > [   80.583480][    C3]  kasan_save_stack+0x1b/0x40 mm/kasan/common.c:49
> > > > > > [   80.584056][    C3]  kasan_set_track+0x1c/0x30 mm/kasan/common.c:57
> > > > > > [   80.584617][    C3]  kasan_set_free_info+0x1b/0x30 mm/kasan/generic.c:354
> > > > > > [   80.585221][    C3]  __kasan_slab_free+0xd8/0x120 mm/kasan/common.c:438
> > > > > > [   80.585814][    C3]  __cache_free mm/slab.c:3426 [inline]
> > > > > > [   80.585814][    C3]  kfree+0x10b/0x2b0 mm/slab.c:3757
> > > > > > [   80.586291][    C3]  kasan_rcu_reclaim+0x16/0x43 [test_kasan]
> > > > > > [   80.587009][    C3]  rcu_do_batch kernel/rcu/tree.c:2207 [inline]
> > > > > > [   80.587009][    C3]  rcu_core+0x59f/0x1370 kernel/rcu/tree.c:2434
> > > > > > [   80.587537][    C3]  __do_softirq+0x26c/0x9fa kernel/softirq.c:292
> > > > > > [   80.588085][    C3]
> > > > > > [   80.588367][    C3] Last one call_rcu() call stack:
> > > > > > [   80.589052][    C3]  kasan_save_stack+0x1b/0x40 mm/kasan/common.c:49
> > > > > > [   80.589622][    C3]  kasan_record_aux_stack+0x82/0xb0 mm/kasan/generic.c:345
> > > > > > [   80.590254][    C3]  __call_rcu kernel/rcu/tree.c:2672 [inline]
> > > > > > [   80.590254][    C3]  call_rcu+0x14f/0x7f0 kernel/rcu/tree.c:2746
> > > > > > [   80.590782][    C3]  kasan_rcu_uaf+0xe4/0xeb [test_kasan]
> > > > > > [   80.591697][    C3]  kmalloc_tests_init+0xbc/0x1097 [test_kasan]
> > > > > > [   80.592900][    C3]  do_one_initcall+0x10a/0x7d0 init/main.c:1196
> > > > > > [   80.593494][    C3]  do_init_module+0x1e6/0x6d0 kernel/module.c:3539
> > > > > > [   80.594066][    C3]  load_module+0x7464/0x9450 kernel/module.c:3890
> > > > > > [   80.594626][    C3]  __do_sys_init_module+0x1e3/0x220 kernel/module.c:3953
> > > > > > [   80.595265][    C3]  do_syscall_64+0xf6/0x7d0 arch/x86/entry/common.c:295
> > > > > > [   80.595822][    C3]  entry_SYSCALL_64_after_hwframe+0x49/0xb3
> > > > > >
> > > > > >
> > > > > > Overall this looks very good to me.
> > > > > > But there is one aspect that bothers me. In the previous patch you had
> > > > > > code that returned NULL from kasan_get_free_track() if the object is
> > > > > > live (which means free meta is not available, it's occupied by object
> > > > > > data). Now you dropped that code, but I think we still need it.
> > > > > > Otherwise we cast user object data to free meta and print the free
> > > > > > stack/pid from whatever garbage is there. This may lead to very
> > > > > > confusing output and potentially to crashes in stackdepot.
> > > > > >
> > > > >
> > > > > Yes, I totally agree with you. In the previous email I thought that
> > > > > there is a problem with free track, but I did not point it out. Thank
> > > > > you for pointing this problem. As you mentioned, we should fix it.
> > > > >
> > > > > > What do you think about this patch on top of your patches?
> > > > > > https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/2478
> > > > > > This way we very precisely mark the period of time when the object has
> > > > > > free track live and set.
> > > > > > If it looks good to you, feel free to incorporate it into your series.
> > > > > >
> > > > >
> > > > > Thank you for providing good idea solution.
> > > > >
> > > > > I saw this patch, that is a great patch. I think it can fix the issue
> > > > > which has garbage stack. it should work as described below.
> > > > >
> > > > > 1). When object is live, then don't print free stack.
> > > > > 2). When object is NOT alive, after free object:
> > > > > 2a). when object is in quarantine, then it can print free stack
> > > > > 2b). when object is NOT in quarantine, then it can NOT print free stack.
> > > > >
> > > > > I have a question about 2), why we don't directly use
> > > > > KASAN_KMALLOC_FREE? if we directly use it, then 2b) can print free
> > > > > stack? 2b) may has use-after-free? so that it may need free stack.
> > > >
> >
> > About 2b), I see another question. When do qlink_free(), it will be
> > written KASAN_KMALLOC_FREE from KASAN_KMALLOC_FREETRACK? if we don't
> > write shadow memory, it is still KASAN_KMALLOC_FREETRACK, then 2b) will
> > have free stack? Because I see you add KASAN_KMALLOC_FREETRACK to get
> > use-after-free in get_shadow_bug_type(). so should it not write
> > KASAN_KMALLOC_FREE?
> 
> It may or may not work.
> The potential problem is that when qlink_free calls ___cache_free,
> slab/slub may start using object memory for its own purposes, e.g.
> store the next link. This next link may overwrite part of free meta.
> It actually may work because the slab/slib next link is likely to
> overlap with kasan_free_meta.quarantine_link only. And we may have
> kasan_free_meta.free_track intact while KASAN_KMALLOC_FREE is set. But
> this needs careful checking for both slab and slub and if they may use
> more than 1 word in some configurations.
> 

This problem looks like existing, even without this change? currently
KASAN may get wrong free stack?

Regardless of whether the shadow memory content is
KASAN_KMALLOC_FREETRACK or KASAN_KMALLOC_FREE, it may have this problem?
But because of kasan_get_free_track() have conditions to get free track,
so that if shadow memory content is KASAN_KMALLOC_FREE, then it will
avoid this problem and always print right free stack.

> 
> > > > We can't use KASAN_KMALLOC_FREE because of this part:
> > > >
> > > > static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
> > > >                   unsigned long ip, bool quarantine)
> > > > {
> > > > ...
> > > >     kasan_poison_shadow(object, rounded_up_size, KASAN_KMALLOC_FREE);
> > > >
> > > >     if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
> > > >             unlikely(!(cache->flags & SLAB_KASAN)))
> > > >         return false;
> > > >
> > > >     kasan_set_free_info(cache, object, tag);
> > > > ...
> > > >
> > >
> > > Ok, I see. When return false, then the shadow memory content has
> > > KASAN_KMALLOC_FREE, but it doesn't set free stack, so that we need to
> > > avoid this situation. Thank for you reminder.
> > >
> > > >
> > > > We may set KASAN_KMALLOC_FREE, but not set the track (or even have
> > > > memory for the track!).
> > > > The object may not have free meta allocated at all, e.g. very large
> > > > object with ctor (no place to store meta), or it may be in a mempool:
> > > > https://elixir.bootlin.com/linux/v5.7-rc6/source/mm/mempool.c#L109
> > > > and mempool may be using the object memory itself (for its own next
> > > > link or something).
> > > >
> > > > KASAN_KMALLOC_FREETRACK very explicitly tracks the exact condition we
> > > > want: we have meta info live now and we have free track set.
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1589966220.14692.24.camel%40mtksdccf07.
