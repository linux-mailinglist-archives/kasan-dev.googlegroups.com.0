Return-Path: <kasan-dev+bncBDGPTM5BQUDRBA6YSL3AKGQEXIL6OVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id EABE11DA8EF
	for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 06:03:16 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id t11sf2304256qvv.11
        for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 21:03:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589947396; cv=pass;
        d=google.com; s=arc-20160816;
        b=pFTUQtPdGc5wd7zi35LIrV4i3ijJGuIdKPT67uDGptWzzOULjDJ+MJprXKCNmhmQJN
         QO03jRq3XZ+YJZecD8yJnBY/mmHLuLgGmec28HrBK+1zsIfetvyVxs86xAefZIIqmH1q
         0a40AOLKul1xJA+15O0H7dYAwZI4yglMTPKaZe1WrCbzWObKTpA2Q9AHbR0eGhpZPo14
         fgOjZFc2QODgXWy+aF3iykBwJWjVf5Tn1KktAVwX3rdy+v7LiyP8cPJS8yQuhW25qpFT
         ZFZiUV4ZrxpFQOkrcYGXjTjr3bdKnAzRxKyWxC4dth8KDNwMaFhuOG86sDEGIqtBugS5
         YwwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:date:cc:to:from:subject
         :message-id:sender:dkim-signature;
        bh=aKEcXoxjDrQy8/PNsz4fCoWp6Freq9VAfqIPfPOBubs=;
        b=pCos5tWiNY8DVtiC5GqhzeMNuNU7lu7z5sF9mKJzh/l9QOcwZUNugPgWyT0vFd+9cD
         YAD/i3Wymmp9LSsBd1P5Z6rNoExCXMtdyAfzGv5k2jZtdek9BIoK80R9dwfMPJDewKzc
         EFRE4al/npLLFjRGbDFQ2Aq/fBLyePh8GlfMy82QuCv1ZOtmDtgldhfGcHvuUI2e9URf
         qlJnpP3+2ItVxCWDNuDYv3VgLH8vk+tZQK2DocVWL1uE1zyjUxCt5drJpXIB72d5QjEL
         FHSBJxz85TycJgzCrYltXRQ8pnBHofNoh6Tk8OiZKPUUmKoArGztWvo5Br39VTVaLfeZ
         wpFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=W6sEy9ac;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aKEcXoxjDrQy8/PNsz4fCoWp6Freq9VAfqIPfPOBubs=;
        b=qJMd5LGLae/VNxFanxZbpHpFLvh1yYCy+vlAzcWGFkgWJUV+q9tgjrfgskPg8jmyuw
         3uhiOhfGd62hHOTR3W58RMcR9j5J6qDp+sVGy2JC+sDOVwNP2ZZKyIuh5gmNcRAx0CnB
         +GkJMDJWbTvypxQwCaSKsMCpte+PqExbNO4KfiQN3ZJnxc++SUs3JIWHr1Xl399N4w/s
         t+A4HWVOYRU8fD+BVWl67/ooEjaRCDx9+qspQHcdRDeKN6Yb1eQqHlt0xOjG/+zGSeEc
         rSPtTX/p7kmkrx1yFIDziF5TshgrNm593vh1aLwCsD9wqbLrOn/MSlGGe5vtY9H77erb
         kSug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=aKEcXoxjDrQy8/PNsz4fCoWp6Freq9VAfqIPfPOBubs=;
        b=sR4uDyJD/l5Npqsn/rgZ7idXgBBL4E5rXXXX8y7OCLLDIWA1wU6XhJFilfNr8fOigY
         vPY2zEp8z7Z3D9/cA977eCf9BuYm5GJjZYwRynB0mhq1EzMdH53udy5LXwajO+4sExQM
         /U7frkrZSKMAmTtTbWjIosVHmj6FLLpPPZHCAsxv+XnLKH2/rJhAfGtLDyAf2C6SdJLZ
         RJV+6pzDh0sUHQDkvEBua/uQ4YTiJ+WFdUDIy2ZiD35Ume7EKK88TbTi+FVNWZ7WbI20
         imuoD6DrcVAK7Be8MtojDGNUE22ReUMsTyzuBSjJTtqjyYHa/nAI6zRlmlws79HTI8Wa
         rYfw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530lpsoJKgiiGjhMql6fwHs84veMPjTkUV5od4Ct+ZpSGlZ5Q0Sk
	phnmv7WOOr9ii0P7LdaaVH4=
X-Google-Smtp-Source: ABdhPJyogN1ki4CUFZ64sYtSej+k/VFLahY7mFU2riI5Q6Mx874tbbojoz3ncyLKhrCXzZTMEKoW/Q==
X-Received: by 2002:a37:b5c3:: with SMTP id e186mr2592750qkf.158.1589947395986;
        Tue, 19 May 2020 21:03:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:e001:: with SMTP id m1ls975506qkk.9.gmail; Tue, 19 May
 2020 21:03:15 -0700 (PDT)
X-Received: by 2002:a05:620a:10a9:: with SMTP id h9mr2916280qkk.408.1589947395678;
        Tue, 19 May 2020 21:03:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589947395; cv=none;
        d=google.com; s=arc-20160816;
        b=JLeHRvAOuxcbTLpf0OWAiodzC8y8zLMJ2QXbRfih9jW/LIl9HZMWLBnJzN54q3aP7x
         zjLXL2tw4syW1hfc2aeqUg+4R8hF/B7gf1oePZGVz26EVTExzLxgKVC5l+hZ/t8n2uci
         f0Vg1OPw/hnLWj0NwicWlbLdgVFz4ezObQGb2VtFFo9VatuT99kPqQ1npdUHYXLO9Tjr
         Q7l4mHFVVzTGzNXc3SQsWCrCDA+uprJbai+Oe2HKdJRNUtU8jnCvCcR5IeG17R+T7x4A
         W5cgKlUMKoIUHYdrh/pvkspWAvD26d1aPgBZTOQ7ewlXcMiLsRuzr9lVNgDmJ4/VmRg2
         XWvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=TmRVvVdb3wuVxMBsQEcmlWS8GtzHpKrc/mM7HRLXBeU=;
        b=WvghShdBnW7SeQQY7kah6rMD4nQsjLbWmHkyLSV+BKDMmqlNWuAZwtH4F77vOwE0Zt
         +JkZ5ZX2oqWbfstjfM6iqMTBlUb1x5Om/mUvqGJJBfpvw1QSR84qpPMq1GwnwwwbemF8
         XJ199TCw5IvzqBTnqDfpGaeKsl9LdyBdB+S4sqbUb8wLNCcJLKRI/tVK5hecbOIp07gV
         /Tcll/POtJ4BnuPzHPBXLttDNpZ22vrsHAqPlRTVHGYGooCECoXWXSZ94CEA16uiNY/u
         TsenP9p6ExUsL3KQLs9sa3uF/mb3iilESPcNroqBJs1GxSlKJFPFCnZ5zli7TpCE5kSO
         wAWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=W6sEy9ac;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id g126si103512qkb.0.2020.05.19.21.03.14
        for <kasan-dev@googlegroups.com>;
        Tue, 19 May 2020 21:03:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 76521071c3da49a384a683aac6301fc0-20200520
X-UUID: 76521071c3da49a384a683aac6301fc0-20200520
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 895467556; Wed, 20 May 2020 12:03:09 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 20 May 2020 12:03:07 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 20 May 2020 12:03:07 +0800
Message-ID: <1589947387.29577.35.camel@mtksdccf07>
Subject: Re: [PATCH v4 2/4] kasan: record and print the free track
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, Linux-MM
	<linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>
Date: Wed, 20 May 2020 12:03:07 +0800
In-Reply-To: <CACT4Y+aJDO+2kSgNpcvHksfn+bZaFWPoGj3-55-dyjLHcHbFUg@mail.gmail.com>
References: <20200519022517.24182-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+aJDO+2kSgNpcvHksfn+bZaFWPoGj3-55-dyjLHcHbFUg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=W6sEy9ac;       spf=pass
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

> On Tue, May 19, 2020 at 4:25 AM Walter Wu <walter-zh.wu@mediatek.com> wro=
te:
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
> > [1]https://bugzilla.kernel.org/show_bug.cgi?id=3D198437
> >
> > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > ---
> >  mm/kasan/common.c  | 22 ++--------------------
> >  mm/kasan/generic.c | 18 ++++++++++++++++++
> >  mm/kasan/kasan.h   |  7 +++++++
> >  mm/kasan/report.c  | 20 --------------------
> >  mm/kasan/tags.c    | 37 +++++++++++++++++++++++++++++++++++++
> >  5 files changed, 64 insertions(+), 40 deletions(-)
> >
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 8bc618289bb1..47b53912f322 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -51,7 +51,7 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags)
> >         return stack_depot_save(entries, nr_entries, flags);
> >  }
> >
> > -static inline void set_track(struct kasan_track *track, gfp_t flags)
> > +void kasan_set_track(struct kasan_track *track, gfp_t flags)
> >  {
> >         track->pid =3D current->pid;
> >         track->stack =3D kasan_save_stack(flags);
> > @@ -299,24 +299,6 @@ struct kasan_free_meta *get_free_info(struct kmem_=
cache *cache,
> >         return (void *)object + cache->kasan_info.free_meta_offset;
> >  }
> >
> > -
> > -static void kasan_set_free_info(struct kmem_cache *cache,
> > -               void *object, u8 tag)
> > -{
> > -       struct kasan_alloc_meta *alloc_meta;
> > -       u8 idx =3D 0;
> > -
> > -       alloc_meta =3D get_alloc_info(cache, object);
> > -
> > -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > -       idx =3D alloc_meta->free_track_idx;
> > -       alloc_meta->free_pointer_tag[idx] =3D tag;
> > -       alloc_meta->free_track_idx =3D (idx + 1) % KASAN_NR_FREE_STACKS=
;
> > -#endif
> > -
> > -       set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
> > -}
> > -
> >  void kasan_poison_slab(struct page *page)
> >  {
> >         unsigned long i;
> > @@ -492,7 +474,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cac=
he, const void *object,
> >                 KASAN_KMALLOC_REDZONE);
> >
> >         if (cache->flags & SLAB_KASAN)
> > -               set_track(&get_alloc_info(cache, object)->alloc_track, =
flags);
> > +               kasan_set_track(&get_alloc_info(cache, object)->alloc_t=
rack, flags);
> >
> >         return set_tag(object, tag);
> >  }
> > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > index 3372bdcaf92a..763d8a13e0ac 100644
> > --- a/mm/kasan/generic.c
> > +++ b/mm/kasan/generic.c
> > @@ -344,3 +344,21 @@ void kasan_record_aux_stack(void *addr)
> >         alloc_info->aux_stack[1] =3D alloc_info->aux_stack[0];
> >         alloc_info->aux_stack[0] =3D kasan_save_stack(GFP_NOWAIT);
> >  }
> > +
> > +void kasan_set_free_info(struct kmem_cache *cache,
> > +                               void *object, u8 tag)
> > +{
> > +       struct kasan_free_meta *free_meta;
> > +
> > +       free_meta =3D get_free_info(cache, object);
> > +       kasan_set_track(&free_meta->free_track, GFP_NOWAIT);
> > +}
> > +
> > +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > +                               void *object, u8 tag)
> > +{
> > +       struct kasan_free_meta *free_meta;
> > +
> > +       free_meta =3D get_free_info(cache, object);
> > +       return &free_meta->free_track;
> > +}
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index a7391bc83070..ad897ec36545 100644
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
> > @@ -168,6 +171,10 @@ void kasan_report_invalid_free(void *object, unsig=
ned long ip);
> >  struct page *kasan_addr_to_page(const void *addr);
> >
> >  depot_stack_handle_t kasan_save_stack(gfp_t flags);
> > +void kasan_set_track(struct kasan_track *track, gfp_t flags);
> > +void kasan_set_free_info(struct kmem_cache *cache, void *object, u8 ta=
g);
> > +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > +                               void *object, u8 tag);
> >
> >  #if defined(CONFIG_KASAN_GENERIC) && \
> >         (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index 6f8f2bf8f53b..96d2657fe70f 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -159,26 +159,6 @@ static void describe_object_addr(struct kmem_cache=
 *cache, void *object,
> >                 (void *)(object_addr + cache->object_size));
> >  }
> >
> > -static struct kasan_track *kasan_get_free_track(struct kmem_cache *cac=
he,
> > -               void *object, u8 tag)
> > -{
> > -       struct kasan_alloc_meta *alloc_meta;
> > -       int i =3D 0;
> > -
> > -       alloc_meta =3D get_alloc_info(cache, object);
> > -
> > -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > -       for (i =3D 0; i < KASAN_NR_FREE_STACKS; i++) {
> > -               if (alloc_meta->free_pointer_tag[i] =3D=3D tag)
> > -                       break;
> > -       }
> > -       if (i =3D=3D KASAN_NR_FREE_STACKS)
> > -               i =3D alloc_meta->free_track_idx;
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
> > @@ -162,3 +162,40 @@ void __hwasan_tag_memory(unsigned long addr, u8 ta=
g, unsigned long size)
> >         kasan_poison_shadow((void *)addr, size, tag);
> >  }
> >  EXPORT_SYMBOL(__hwasan_tag_memory);
> > +
> > +void kasan_set_free_info(struct kmem_cache *cache,
> > +                               void *object, u8 tag)
> > +{
> > +       struct kasan_alloc_meta *alloc_meta;
> > +       u8 idx =3D 0;
> > +
> > +       alloc_meta =3D get_alloc_info(cache, object);
> > +
> > +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > +       idx =3D alloc_meta->free_track_idx;
> > +       alloc_meta->free_pointer_tag[idx] =3D tag;
> > +       alloc_meta->free_track_idx =3D (idx + 1) % KASAN_NR_FREE_STACKS=
;
> > +#endif
> > +
> > +       kasan_set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
> > +}
> > +
> > +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > +                               void *object, u8 tag)
> > +{
> > +       struct kasan_alloc_meta *alloc_meta;
> > +       int i =3D 0;
> > +
> > +       alloc_meta =3D get_alloc_info(cache, object);
> > +
> > +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > +       for (i =3D 0; i < KASAN_NR_FREE_STACKS; i++) {
> > +               if (alloc_meta->free_pointer_tag[i] =3D=3D tag)
> > +                       break;
> > +       }
> > +       if (i =3D=3D KASAN_NR_FREE_STACKS)
> > +               i =3D alloc_meta->free_track_idx;
> > +#endif
> > +
> > +       return &alloc_meta->free_track[i];
> > +}
>=20
> Hi Walter,
>=20
> FTR I've uploaded this for review purposes here:
> https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+=
/2458
>=20
> Diff from the previous version is available as:
> https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+=
/2458/1..2
>=20
> I've tested this locally and with syzkaller. This is =F0=9F=94=A5=F0=9F=
=94=A5=F0=9F=94=A5:
>=20
> [   80.583021][    C3] Freed by task 0:
> [   80.583480][    C3]  kasan_save_stack+0x1b/0x40 mm/kasan/common.c:49
> [   80.584056][    C3]  kasan_set_track+0x1c/0x30 mm/kasan/common.c:57
> [   80.584617][    C3]  kasan_set_free_info+0x1b/0x30 mm/kasan/generic.c:=
354
> [   80.585221][    C3]  __kasan_slab_free+0xd8/0x120 mm/kasan/common.c:43=
8
> [   80.585814][    C3]  __cache_free mm/slab.c:3426 [inline]
> [   80.585814][    C3]  kfree+0x10b/0x2b0 mm/slab.c:3757
> [   80.586291][    C3]  kasan_rcu_reclaim+0x16/0x43 [test_kasan]
> [   80.587009][    C3]  rcu_do_batch kernel/rcu/tree.c:2207 [inline]
> [   80.587009][    C3]  rcu_core+0x59f/0x1370 kernel/rcu/tree.c:2434
> [   80.587537][    C3]  __do_softirq+0x26c/0x9fa kernel/softirq.c:292
> [   80.588085][    C3]
> [   80.588367][    C3] Last one call_rcu() call stack:
> [   80.589052][    C3]  kasan_save_stack+0x1b/0x40 mm/kasan/common.c:49
> [   80.589622][    C3]  kasan_record_aux_stack+0x82/0xb0 mm/kasan/generic=
.c:345
> [   80.590254][    C3]  __call_rcu kernel/rcu/tree.c:2672 [inline]
> [   80.590254][    C3]  call_rcu+0x14f/0x7f0 kernel/rcu/tree.c:2746
> [   80.590782][    C3]  kasan_rcu_uaf+0xe4/0xeb [test_kasan]
> [   80.591697][    C3]  kmalloc_tests_init+0xbc/0x1097 [test_kasan]
> [   80.592900][    C3]  do_one_initcall+0x10a/0x7d0 init/main.c:1196
> [   80.593494][    C3]  do_init_module+0x1e6/0x6d0 kernel/module.c:3539
> [   80.594066][    C3]  load_module+0x7464/0x9450 kernel/module.c:3890
> [   80.594626][    C3]  __do_sys_init_module+0x1e3/0x220 kernel/module.c:=
3953
> [   80.595265][    C3]  do_syscall_64+0xf6/0x7d0 arch/x86/entry/common.c:=
295
> [   80.595822][    C3]  entry_SYSCALL_64_after_hwframe+0x49/0xb3
>=20
>=20
> Overall this looks very good to me.
> But there is one aspect that bothers me. In the previous patch you had
> code that returned NULL from kasan_get_free_track() if the object is
> live (which means free meta is not available, it's occupied by object
> data). Now you dropped that code, but I think we still need it.
> Otherwise we cast user object data to free meta and print the free
> stack/pid from whatever garbage is there. This may lead to very
> confusing output and potentially to crashes in stackdepot.
>=20

Yes, I totally agree with you. In the previous email I thought that
there is a problem with free track, but I did not point it out. Thank
you for pointing this problem. As you mentioned, we should fix it.

> What do you think about this patch on top of your patches?
> https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+=
/2478
> This way we very precisely mark the period of time when the object has
> free track live and set.
> If it looks good to you, feel free to incorporate it into your series.
>=20

Thank you for providing good idea solution.

I saw this patch, that is a great patch. I think it can fix the issue
which has garbage stack. it should work as described below.

1). When object is live, then don't print free stack.
2). When object is NOT alive, after free object:
2a). when object is in quarantine, then it can print free stack
2b). when object is NOT in quarantine, then it can NOT print free stack.

I have a question about 2), why we don't directly use
KASAN_KMALLOC_FREE? if we directly use it, then 2b) can print free
stack? 2b) may has use-after-free? so that it may need free stack.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1589947387.29577.35.camel%40mtksdccf07.
