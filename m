Return-Path: <kasan-dev+bncBAABBVFF7XTQKGQEK7ZU4UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F4503C4A6
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2019 09:05:58 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id n5sf10138557qkf.7
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2019 00:05:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560236757; cv=pass;
        d=google.com; s=arc-20160816;
        b=ycVkGjoNen269QfAtlK1uFF2KNO5ejMSDnowXZZr21MASktDOOg9AFf/pgfrfCYzOG
         h1p3UkXDMfWRTPHwcc3SGszawFeXEv7NTmbZdpS2G0SqTT745i6+ZNeH/CulCrSl0Xyx
         +ojwVjtn+ixeR1hUyAuhY1xTnItEmVHST8cwDUBnYJWRQ+LiJ1GrTwz6QdmecWDBGXX2
         cOBIn30o5wBLZk+IprQUre0tumTqKrla39GbsppaCZMt9znCL5gy5hpDrhnIiWaFuAm3
         G+TZbo2xweI8ogBRzaLfqXHQdCJYptA+zO06GmLfnadZQYnEZRTQuwBU0QWX/2EsvoGW
         fkmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=qQTh2AaC/0Y5YQIpezWiahNxTGJ6jSiEGdSvrRQ73pQ=;
        b=rTXXM+fXBibjCWSUYruUHsGwzEUj+w/5a/P+nnhzBfGrA7DaB4XhwkGQgBudhBzEPD
         l2Dgq/Ssc1D8+TnupFeeHrkeJfEhrXG9Ch6TwWov8GESGPTSDhP8YYtYtwdVKCoMWjOu
         f54zyRiju7/B25n3v0tkvSl1jO9b85Z42pY7XqPKmjiLvniq0bIiFSooJTFG+VsKELe2
         HgQPjpTynY8nrv1nQF0+Rro2FUyYx1EY1XS9q21Pd+YxOQemtRxQj6Re2pweMdvq4zyE
         zLcpvq8UflUP+tnX/X89mK2DNyvlsEYtc2NKOFTaQhjUhMP0o6o4haaIYYDqUmrjaF46
         D1JQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qQTh2AaC/0Y5YQIpezWiahNxTGJ6jSiEGdSvrRQ73pQ=;
        b=a+yzdQswB2/S+mLHbWnxsyjg1b2TbV1FY8kuN+2vEDoJ4W2M/E5NuFkBbOoIwhBNck
         CVBMHo1iNliVrPAEAmT0A1+qkOTm51VEGQI+WFKGwpARrtsNhNJgnvFQarlb5/HSq+o7
         YT2/KKOyv3J2pHKudPMDNf3K8pXKM2ubizQZNHEcO9EeSXH6MIo8UvtoMdkd7erjHkBT
         eDA1XAEks8rDnoHZ5+LMGOzvKzYfpUdODXNd+ViNQzSBX7zn6PQAZvh2NYVkXGihn+ti
         nO7f41b3MHqg6QxdIw69d0szPJxDELYKrrXBaos5FsTTYQxm15FRdlCEhgGjGpFyf+k2
         X4kw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qQTh2AaC/0Y5YQIpezWiahNxTGJ6jSiEGdSvrRQ73pQ=;
        b=OS4XtS3UphhwwLbUrqJ9a0m73svDf9bYgnzjbWxIURkZJS1L3DpO0St4A5fZOs/hIa
         EVADUJmoIWfp5fliGjfF3VEVMyc39eMpGsAdr5XOEggF4rDCCvJaHarzqBK08Hn8GFt4
         Iw4HpoqLwuUUQNff5nDqO0pb8GMa2EhZ8FmQ19CGmkSdyc+dOs9sXTew8UcD0T2q7bKl
         JsmcngKv2l4lYns/mY1A+IBG49CXj/RtKY/syd7AvANw8Oc5/bCIj+bYk1g+oEhLbZ1I
         u+RUQ79FPMhgC9E3hvWxY2cWpLNoBJ5cQX1XA6mjmVr7CF1TbWKwRIfAAWA4IHhQx+jr
         3ccw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXCn6/asFTKs0/qQlquwbHUyZUb0EHsbc6QRIl0r6IRR7i8JOfY
	Ls34p+bF/0FIztZywjmhX9M=
X-Google-Smtp-Source: APXvYqwbKAaVbNAi9oAaoPPOdbLCryySFJ0hGLG1jfR6q4Zbox1GBEgxFQwTizaIuv/l2FxZDgA/Pg==
X-Received: by 2002:a0c:c3c7:: with SMTP id p7mr25936917qvi.125.1560236757160;
        Tue, 11 Jun 2019 00:05:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:52d7:: with SMTP id g206ls1586501qkb.5.gmail; Tue, 11
 Jun 2019 00:05:56 -0700 (PDT)
X-Received: by 2002:a37:b5c5:: with SMTP id e188mr20636742qkf.55.1560236756640;
        Tue, 11 Jun 2019 00:05:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560236756; cv=none;
        d=google.com; s=arc-20160816;
        b=BM8DL3ZjWu41PjXme0tbfuGXEZoUYL0aVAae+KwQT2wQkPs4oipaIKe6iktOWqI27z
         pN4eqtYjxHFB8Av9TIrv7VgHJoxcZG+woXVy4fjpDashrDuHYgbKR81k2vJRBzeoskW2
         0tCZ5whkEH96eijuQoVYEOgEbsiO3NUEct6+eHwHbnbqYVrLirpZzwbDD0CMzaSH6H0C
         jfoeIQYEnvX8F7lI4Hiy6T/dcYzXc129C6LkV3x6S9aNcZIdQ8XWK4f8fXW/dHz0K7rl
         6JaCclqwfkU+B3L6PrQkKmz02cyLLMRxcis1TK1pgkOjGPJyDlAlsqATiS9V/95cZWSg
         cKfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=zWFGsm8VT3/sPgQ+R8t/ryYTFDqOss+upjvCnjyGuyM=;
        b=yQesTWFtm50OLptOWbzggtavcoEip3W9J8ypG13asacgU7x4z8lf1Ssv8xqUni7vh6
         cAMfBFLLnSUGirDLt3MxETEYaZ3jr+j6JAWSw13270FZpyjYagp5w9PD6khx7+5vbxUN
         Y2vnAFsePVg2FqK7Bcv3opyjFfnxOvUT/VN0gWTL4DtfUsGTZy9ZZMwLH4UZzF4y3DxN
         u50VLVdaMSYrSFBoxEyixA+f4+pQu346xng6S15QttC5EvuUAWGYQ2YzypvtlB8p8Rot
         y+vB1XdvGah0bUqO9fduYAKNbZvnhyXSOpThNjnkfFHliOUyxDTHoX1bXUqej7dr3eix
         Ysfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id m55si594093qtm.0.2019.06.11.00.05.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 Jun 2019 00:05:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: f325e566181946b2bd522143bc1369fe-20190611
X-UUID: f325e566181946b2bd522143bc1369fe-20190611
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(mhqrelay.mediatek.com ESMTP with TLS)
	with ESMTP id 1487741607; Tue, 11 Jun 2019 15:05:43 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs08n1.mediatek.inc (172.21.101.55) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Tue, 11 Jun 2019 15:05:42 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Tue, 11 Jun 2019 15:05:42 +0800
Message-ID: <1560236742.4832.34.camel@mtksdccf07>
Subject: Re: [PATCH v2] kasan: add memory corruption identification for
 software tag-based mode
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Matthias Brugger <matthias.bgg@gmail.com>, "Martin
 Schwidefsky" <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>, "Vasily
 Gorbik" <gor@linux.ibm.com>, Andrey Konovalov <andreyknvl@google.com>, "Jason
 A. Donenfeld" <Jason@zx2c4.com>, Miles Chen
 =?UTF-8?Q?=28=E9=99=B3=E6=B0=91=E6=A8=BA=29?= <Miles.Chen@mediatek.com>,
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>,
	Linux-MM <linux-mm@kvack.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, "linux-mediatek@lists.infradead.org"
	<linux-mediatek@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>
Date: Tue, 11 Jun 2019 15:05:42 +0800
In-Reply-To: <CACT4Y+aetKEM9UkfSoVf8EaDNTD40mEF0xyaRiuw=DPEaGpTkQ@mail.gmail.com>
References: <1559651172-28989-1-git-send-email-walter-zh.wu@mediatek.com>
	 <CACT4Y+Y9_85YB8CCwmKerDWc45Z00hMd6Pc-STEbr0cmYSqnoA@mail.gmail.com>
	 <1560151690.20384.3.camel@mtksdccf07>
	 <CACT4Y+aetKEM9UkfSoVf8EaDNTD40mEF0xyaRiuw=DPEaGpTkQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
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

On Mon, 2019-06-10 at 13:46 +0200, Dmitry Vyukov wrote:
> On Mon, Jun 10, 2019 at 9:28 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > On Fri, 2019-06-07 at 21:18 +0800, Dmitry Vyukov wrote:
> > > > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > > > index b40ea104dd36..be0667225b58 100644
> > > > --- a/include/linux/kasan.h
> > > > +++ b/include/linux/kasan.h
> > > > @@ -164,7 +164,11 @@ void kasan_cache_shutdown(struct kmem_cache *cache);
> > > >
> > > >  #else /* CONFIG_KASAN_GENERIC */
> > > >
> > > > +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > > > +void kasan_cache_shrink(struct kmem_cache *cache);
> > > > +#else
> > >
> > > Please restructure the code so that we don't duplicate this function
> > > name 3 times in this header.
> > >
> > We have fixed it, Thank you for your reminder.
> >
> >
> > > >  static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
> > > > +#endif
> > > >  static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
> > > >
> > > >  #endif /* CONFIG_KASAN_GENERIC */
> > > > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > > > index 9950b660e62d..17a4952c5eee 100644
> > > > --- a/lib/Kconfig.kasan
> > > > +++ b/lib/Kconfig.kasan
> > > > @@ -134,6 +134,15 @@ config KASAN_S390_4_LEVEL_PAGING
> > > >           to 3TB of RAM with KASan enabled). This options allows to force
> > > >           4-level paging instead.
> > > >
> > > > +config KASAN_SW_TAGS_IDENTIFY
> > > > +       bool "Enable memory corruption idenitfication"
> > >
> > > s/idenitfication/identification/
> > >
> > I should replace my glasses.
> >
> >
> > > > +       depends on KASAN_SW_TAGS
> > > > +       help
> > > > +         Now tag-based KASAN bug report always shows invalid-access error, This
> > > > +         options can identify it whether it is use-after-free or out-of-bound.
> > > > +         This will make it easier for programmers to see the memory corruption
> > > > +         problem.
> > >
> > > This description looks like a change description, i.e. it describes
> > > the current behavior and how it changes. I think code comments should
> > > not have such, they should describe the current state of the things.
> > > It should also mention the trade-off, otherwise it raises reasonable
> > > questions like "why it's not enabled by default?" and "why do I ever
> > > want to not enable it?".
> > > I would do something like:
> > >
> > > This option enables best-effort identification of bug type
> > > (use-after-free or out-of-bounds)
> > > at the cost of increased memory consumption for object quarantine.
> > >
> > I totally agree with your comments. Would you think we should try to add the cost?
> > It may be that it consumes about 1/128th of available memory at full quarantine usage rate.
> 
> Hi,
> 
> I don't understand the question. We should not add costs if not
> necessary. Or you mean why we should add _docs_ regarding the cost? Or
> what?
> 
I mean the description of option. Should it add the description for
memory costs. I see KASAN_SW_TAGS and KASAN_GENERIC options to show the
memory costs. So We originally think it is possible to add the
description, if users want to enable it, maybe they want to know its
memory costs.

If you think it is not necessary, we will not add it.

> > > > +
> > > >  config TEST_KASAN
> > > >         tristate "Module for testing KASAN for bug detection"
> > > >         depends on m && KASAN
> > > > diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> > > > index 5d1065efbd47..d8540e5070cb 100644
> > > > --- a/mm/kasan/Makefile
> > > > +++ b/mm/kasan/Makefile
> > > > @@ -19,3 +19,4 @@ CFLAGS_tags.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> > > >  obj-$(CONFIG_KASAN) := common.o init.o report.o
> > > >  obj-$(CONFIG_KASAN_GENERIC) += generic.o generic_report.o quarantine.o
> > > >  obj-$(CONFIG_KASAN_SW_TAGS) += tags.o tags_report.o
> > > > +obj-$(CONFIG_KASAN_SW_TAGS_IDENTIFY) += quarantine.o
> > > > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > > > index 80bbe62b16cd..e309fbbee831 100644
> > > > --- a/mm/kasan/common.c
> > > > +++ b/mm/kasan/common.c
> > > > @@ -81,7 +81,7 @@ static inline depot_stack_handle_t save_stack(gfp_t flags)
> > > >         return depot_save_stack(&trace, flags);
> > > >  }
> > > >
> > > > -static inline void set_track(struct kasan_track *track, gfp_t flags)
> > > > +void set_track(struct kasan_track *track, gfp_t flags)
> > >
> > > If you make it non-static, it should get kasan_ prefix. The name is too generic.
> > >
> > Ok, We will add it into next version.
> >
> >
> > >
> > > >  {
> > > >         track->pid = current->pid;
> > > >         track->stack = save_stack(flags);
> > > > @@ -457,7 +457,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
> > > >                 return false;
> > > >
> > > >         set_track(&get_alloc_info(cache, object)->free_track, GFP_NOWAIT);
> > > > -       quarantine_put(get_free_info(cache, object), cache);
> > > > +       quarantine_put(get_free_info(cache, tagged_object), cache);
> > > >
> > > >         return IS_ENABLED(CONFIG_KASAN_GENERIC);
> > > >  }
> > > > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > > > index 3e0c11f7d7a1..1be04abe2e0d 100644
> > > > --- a/mm/kasan/kasan.h
> > > > +++ b/mm/kasan/kasan.h
> > > > @@ -98,6 +98,12 @@ struct kasan_alloc_meta {
> > > >  struct qlist_node {
> > > >         struct qlist_node *next;
> > > >  };
> > > > +struct qlist_object {
> > > > +       unsigned long addr;
> > > > +       unsigned int size;
> > > > +       struct kasan_track free_track;
> > > > +       struct qlist_node qnode;
> > > > +};
> > > >  struct kasan_free_meta {
> > > >         /* This field is used while the object is in the quarantine.
> > > >          * Otherwise it might be used for the allocator freelist.
> > > > @@ -133,11 +139,12 @@ void kasan_report(unsigned long addr, size_t size,
> > > >                 bool is_write, unsigned long ip);
> > > >  void kasan_report_invalid_free(void *object, unsigned long ip);
> > > >
> > > > -#if defined(CONFIG_KASAN_GENERIC) && \
> > > > -       (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
> > > > +#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS_IDENTIFY)) \
> > > > +       && (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
> > > >  void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
> > > >  void quarantine_reduce(void);
> > > >  void quarantine_remove_cache(struct kmem_cache *cache);
> > > > +void set_track(struct kasan_track *track, gfp_t flags);
> > > >  #else
> > > >  static inline void quarantine_put(struct kasan_free_meta *info,
> > > >                                 struct kmem_cache *cache) { }
> > > > @@ -151,6 +158,31 @@ void print_tags(u8 addr_tag, const void *addr);
> > > >
> > > >  u8 random_tag(void);
> > > >
> > > > +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > > > +bool quarantine_find_object(void *object,
> > > > +               struct kasan_track *free_track);
> > > > +
> > > > +struct qlist_object *qobject_create(struct kasan_free_meta *info,
> > > > +               struct kmem_cache *cache);
> > > > +
> > > > +void qobject_free(struct qlist_node *qlink, struct kmem_cache *cache);
> > > > +#else
> > > > +static inline bool quarantine_find_object(void *object,
> > > > +               struct kasan_track *free_track)
> > > > +{
> > > > +       return false;
> > > > +}
> > > > +
> > > > +static inline struct qlist_object *qobject_create(struct kasan_free_meta *info,
> > > > +               struct kmem_cache *cache)
> > > > +{
> > > > +       return NULL;
> > > > +}
> > > > +
> > > > +static inline void qobject_free(struct qlist_node *qlink,
> > > > +               struct kmem_cache *cache) {}
> > > > +#endif
> > > > +
> > > >  #else
> > > >
> > > >  static inline void print_tags(u8 addr_tag, const void *addr) { }
> > > > @@ -160,6 +192,20 @@ static inline u8 random_tag(void)
> > > >         return 0;
> > > >  }
> > > >
> > > > +static inline bool quarantine_find_object(void *object,
> > >
> > >
> > > Please restructure the code so that we don't duplicate this function
> > > name 3 times in this header.
> > >
> > We have fixed it.
> >
> >
> > > > +               struct kasan_track *free_track)
> > > > +{
> > > > +       return false;
> > > > +}
> > > > +
> > > > +static inline struct qlist_object *qobject_create(struct kasan_free_meta *info,
> > > > +               struct kmem_cache *cache)
> > > > +{
> > > > +       return NULL;
> > > > +}
> > > > +
> > > > +static inline void qobject_free(struct qlist_node *qlink,
> > > > +               struct kmem_cache *cache) {}
> > > >  #endif
> > > >
> > > >  #ifndef arch_kasan_set_tag
> > > > diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> > > > index 978bc4a3eb51..43b009659d80 100644
> > > > --- a/mm/kasan/quarantine.c
> > > > +++ b/mm/kasan/quarantine.c
> > > > @@ -61,12 +61,16 @@ static void qlist_init(struct qlist_head *q)
> > > >  static void qlist_put(struct qlist_head *q, struct qlist_node *qlink,
> > > >                 size_t size)
> > > >  {
> > > > -       if (unlikely(qlist_empty(q)))
> > > > +       struct qlist_node *prev_qlink = q->head;
> > > > +
> > > > +       if (unlikely(qlist_empty(q))) {
> > > >                 q->head = qlink;
> > > > -       else
> > > > -               q->tail->next = qlink;
> > > > -       q->tail = qlink;
> > > > -       qlink->next = NULL;
> > > > +               q->tail = qlink;
> > > > +               qlink->next = NULL;
> > > > +       } else {
> > > > +               q->head = qlink;
> > > > +               qlink->next = prev_qlink;
> > > > +       }
> > > >         q->bytes += size;
> > > >  }
> > > >
> > > > @@ -121,7 +125,11 @@ static unsigned long quarantine_batch_size;
> > > >   * Quarantine doesn't support memory shrinker with SLAB allocator, so we keep
> > > >   * the ratio low to avoid OOM.
> > > >   */
> > > > +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > > > +#define QUARANTINE_FRACTION 128
> > >
> > > Explain in a comment why we use lower value for sw tags mode.
> > >
> > The comment is below.
> > "Tag-based KASAN only stores freed object information rather than the
> > object itself. The quarantine in tag-based KASAN only needs less usage
> > to achieve the same effect as generic KASAN. So We reduce the
> > QUARANTINE_FRACTION value to slim the quarantine"
> >
> >
> > > > +#else
> > > >  #define QUARANTINE_FRACTION 32
> > > > +#endif
> > > >
> > > >  static struct kmem_cache *qlink_to_cache(struct qlist_node *qlink)
> > > >  {
> > > > @@ -139,16 +147,24 @@ static void *qlink_to_object(struct qlist_node *qlink, struct kmem_cache *cache)
> > > >
> > > >  static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
> > > >  {
> > > > -       void *object = qlink_to_object(qlink, cache);
> > > >         unsigned long flags;
> > > > +       struct kmem_cache *obj_cache;
> > > > +       void *object;
> > > >
> > > > -       if (IS_ENABLED(CONFIG_SLAB))
> > > > -               local_irq_save(flags);
> > > > +       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS_IDENTIFY)) {
> > > > +               qobject_free(qlink, cache);
> > > > +       } else {
> > > > +               obj_cache = cache ? cache :     qlink_to_cache(qlink);
> > > > +               object = qlink_to_object(qlink, obj_cache);
> > > >
> > > > -       ___cache_free(cache, object, _THIS_IP_);
> > > > +               if (IS_ENABLED(CONFIG_SLAB))
> > > > +                       local_irq_save(flags);
> > > >
> > > > -       if (IS_ENABLED(CONFIG_SLAB))
> > > > -               local_irq_restore(flags);
> > > > +               ___cache_free(obj_cache, object, _THIS_IP_);
> > > > +
> > > > +               if (IS_ENABLED(CONFIG_SLAB))
> > > > +                       local_irq_restore(flags);
> > > > +       }
> > > >  }
> > > >
> > > >  static void qlist_free_all(struct qlist_head *q, struct kmem_cache *cache)
> > > > @@ -160,11 +176,9 @@ static void qlist_free_all(struct qlist_head *q, struct kmem_cache *cache)
> > > >
> > > >         qlink = q->head;
> > > >         while (qlink) {
> > > > -               struct kmem_cache *obj_cache =
> > > > -                       cache ? cache : qlink_to_cache(qlink);
> > > >                 struct qlist_node *next = qlink->next;
> > > >
> > > > -               qlink_free(qlink, obj_cache);
> > > > +               qlink_free(qlink, cache);
> > > >                 qlink = next;
> > > >         }
> > > >         qlist_init(q);
> > > > @@ -175,6 +189,8 @@ void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
> > > >         unsigned long flags;
> > > >         struct qlist_head *q;
> > > >         struct qlist_head temp = QLIST_INIT;
> > > > +       struct kmem_cache *qobject_cache;
> > > > +       struct qlist_object *free_obj_info;
> > > >
> > > >         /*
> > > >          * Note: irq must be disabled until after we move the batch to the
> > > > @@ -187,7 +203,19 @@ void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
> > > >         local_irq_save(flags);
> > > >
> > > >         q = this_cpu_ptr(&cpu_quarantine);
> > > > -       qlist_put(q, &info->quarantine_link, cache->size);
> > > > +       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS_IDENTIFY)) {
> > > > +               free_obj_info = qobject_create(info, cache);
> > > > +               if (!free_obj_info) {
> > > > +                       local_irq_restore(flags);
> > > > +                       return;
> > > > +               }
> > > > +
> > > > +               qobject_cache = qlink_to_cache(&free_obj_info->qnode);
> > > > +               qlist_put(q, &free_obj_info->qnode, qobject_cache->size);
> > >
> > > We could use sizeof(*free_obj_info), which looks simpler. Any reason
> > > to do another hop through the cache?
> > >
> > We originally thought we should store the whole slab usage(including metadata)
> > instead of qobject size.
> > If we use sizeof(*free_obj_info), then below calculation is incorrect.
> > total quarantine size = (totalram_pages() << PAGE_SHIFT) / QUARANTINE_FRACTION
> > - QUARANTINE_PERCPU_SIZE*num_online_cpus()
> 
> So this is total size which is more precise. I see.
> 
> 
> > > > +       } else {
> > > > +               qlist_put(q, &info->quarantine_link, cache->size);
> > > > +       }
> > > > +
> > > >         if (unlikely(q->bytes > QUARANTINE_PERCPU_SIZE)) {
> > > >                 qlist_move_all(q, &temp);
> > > >
> > > > @@ -220,7 +248,6 @@ void quarantine_reduce(void)
> > > >         if (likely(READ_ONCE(quarantine_size) <=
> > > >                    READ_ONCE(quarantine_max_size)))
> > > >                 return;
> > > > -
> > > >         /*
> > > >          * srcu critical section ensures that quarantine_remove_cache()
> > > >          * will not miss objects belonging to the cache while they are in our
> > > > @@ -327,3 +354,90 @@ void quarantine_remove_cache(struct kmem_cache *cache)
> > > >
> > > >         synchronize_srcu(&remove_cache_srcu);
> > > >  }
> > > > +
> > > > +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > > > +static noinline bool qlist_find_object(struct qlist_head *from, void *arg)
> > > > +{
> > > > +       struct qlist_node *curr;
> > > > +       struct qlist_object *curr_obj;
> > > > +       struct qlist_object *target = (struct qlist_object *)arg;
> > > > +
> > > > +       if (unlikely(qlist_empty(from)))
> > > > +               return false;
> > > > +
> > > > +       curr = from->head;
> > > > +       while (curr) {
> > > > +               struct qlist_node *next = curr->next;
> > > > +
> > > > +               curr_obj = container_of(curr, struct qlist_object, qnode);
> > > > +               if (unlikely((target->addr >= curr_obj->addr) &&
> > > > +                       (target->addr < (curr_obj->addr + curr_obj->size)))) {
> > > > +                       target->free_track = curr_obj->free_track;
> > > > +                       return true;
> > > > +               }
> > > > +
> > > > +               curr = next;
> > > > +       }
> > > > +       return false;
> > > > +}
> > > > +
> > > > +static noinline int per_cpu_find_object(void *arg)
> > > > +{
> > > > +       struct qlist_head *q;
> > > > +
> > > > +       q = this_cpu_ptr(&cpu_quarantine);
> > > > +       return qlist_find_object(q, arg);
> > > > +}
> > > > +
> > > > +struct cpumask cpu_allowed_mask __read_mostly;
> > > > +
> > > > +bool quarantine_find_object(void *addr, struct kasan_track *free_track)
> > > > +{
> > > > +       unsigned long flags;
> > > > +       bool find = false;
> > > > +       int cpu, i;
> > > > +       struct qlist_object target;
> > > > +
> > > > +       target.addr = (unsigned long)addr;
> > > > +
> > > > +       cpumask_copy(&cpu_allowed_mask, cpu_online_mask);
> > > > +       for_each_cpu(cpu, &cpu_allowed_mask) {
> > > > +               find = smp_call_on_cpu(cpu, per_cpu_find_object,
> > > > +                               (void *)&target, true);
> > > > +               if (find) {
> > > > +                       if (free_track)
> > > > +                               *free_track = target.free_track;
> > > > +                       return true;
> > > > +               }
> > > > +       }
> > > > +
> > > > +       raw_spin_lock_irqsave(&quarantine_lock, flags);
> > > > +       for (i = quarantine_tail; i >= 0; i--) {
> > > > +               if (qlist_empty(&global_quarantine[i]))
> > > > +                       continue;
> > > > +               find = qlist_find_object(&global_quarantine[i],
> > > > +                               (void *)&target);
> > > > +               if (find) {
> > > > +                       if (free_track)
> > > > +                               *free_track = target.free_track;
> > > > +                       raw_spin_unlock_irqrestore(&quarantine_lock, flags);
> > > > +                       return true;
> > > > +               }
> > > > +       }
> > > > +       for (i = QUARANTINE_BATCHES-1; i > quarantine_tail; i--) {
> > >
> > > Find a way to calculate the right index using a single loop, rather
> > > that copy-paste the whole loop body to do a small adjustment to index.
> > >
> > single loop:
> >
> >     for (i = quarantine_tail, j = 1; i != quarantine_tail || j != 2;
> > i--) {
> 
> I would find the classic loop form easier to follow and then compute
> the actual index as necessary.
> Something along the following lines:
> 
> for (i = 0; i < QUARANTINE_BATCHES; i++) {
>     idx = quarantine_tail - i;
>     if (idx < 0)
>         idx += QUARANTINE_BATCHES;
>     ...
> 
Thanks your helps. It is smart code.
I am too persistent to treat 'i' as the index rather than calculate new
index.

> >         if (i < 0) {
> >             i = QUARANTINE_BATCHES;
> >             j = 2;
> >             continue;
> >         }
> >         if (qlist_empty(&global_quarantine[i]))
> >             continue;
> >         find = qlist_find_object(&global_quarantine[i],
> >                 (void *)&target);
> >         if (find) {
> >             if (free_track)
> >                 *free_track = target.free_track;
> >             raw_spin_unlock_irqrestore(&quarantine_lock, flags);
> >             return true;
> >         }
> >     }
> >
> >
> > > > +               if (qlist_empty(&global_quarantine[i]))
> > > > +                       continue;
> > > > +               find = qlist_find_object(&global_quarantine[i],
> > > > +                               (void *)&target);
> > > > +               if (find) {
> > > > +                       if (free_track)
> > > > +                               *free_track = target.free_track;
> > > > +                       raw_spin_unlock_irqrestore(&quarantine_lock, flags);
> > > > +                       return true;
> > > > +               }
> > > > +       }
> > > > +       raw_spin_unlock_irqrestore(&quarantine_lock, flags);
> > > > +
> > > > +       return false;
> > > > +}
> > > > +#endif
> > > > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > > > index ca9418fe9232..3cbc24cd3d43 100644
> > > > --- a/mm/kasan/report.c
> > > > +++ b/mm/kasan/report.c
> > > > @@ -150,18 +150,27 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
> > > >  }
> > > >
> > > >  static void describe_object(struct kmem_cache *cache, void *object,
> > > > -                               const void *addr)
> > > > +                               const void *tagged_addr)
> > > >  {
> > > > +       void *untagged_addr = reset_tag(tagged_addr);
> > > >         struct kasan_alloc_meta *alloc_info = get_alloc_info(cache, object);
> > > > +       struct kasan_track free_track;
> > > >
> > > >         if (cache->flags & SLAB_KASAN) {
> > > > -               print_track(&alloc_info->alloc_track, "Allocated");
> > > > -               pr_err("\n");
> > > > -               print_track(&alloc_info->free_track, "Freed");
> > > > -               pr_err("\n");
> > > > +               if (IS_ENABLED(CONFIG_KASAN_SW_TAGS_IDENTIFY) &&
> > > > +                       quarantine_find_object((void *)tagged_addr,
> > > > +                               &free_track)) {
> > > > +                       print_track(&free_track, "Freed");
> > > > +                       pr_err("\n");
> > > > +               } else {
> > > > +                       print_track(&alloc_info->alloc_track, "Allocated");
> > > > +                       pr_err("\n");
> > > > +                       print_track(&alloc_info->free_track, "Freed");
> > > > +                       pr_err("\n");
> > > > +               }
> > > >         }
> > > >
> > > > -       describe_object_addr(cache, object, addr);
> > > > +       describe_object_addr(cache, object, untagged_addr);
> > > >  }
> > > >
> > > >  static inline bool kernel_or_module_addr(const void *addr)
> > > > @@ -180,23 +189,25 @@ static inline bool init_task_stack_addr(const void *addr)
> > > >                         sizeof(init_thread_union.stack));
> > > >  }
> > > >
> > > > -static void print_address_description(void *addr)
> > > > +static void print_address_description(void *tagged_addr)
> > > >  {
> > > > -       struct page *page = addr_to_page(addr);
> > > > +       void *untagged_addr = reset_tag(tagged_addr);
> > > > +       struct page *page = addr_to_page(untagged_addr);
> > > >
> > > >         dump_stack();
> > > >         pr_err("\n");
> > > >
> > > >         if (page && PageSlab(page)) {
> > > >                 struct kmem_cache *cache = page->slab_cache;
> > > > -               void *object = nearest_obj(cache, page, addr);
> > > > +               void *object = nearest_obj(cache, page, untagged_addr);
> > > >
> > > > -               describe_object(cache, object, addr);
> > > > +               describe_object(cache, object, tagged_addr);
> > > >         }
> > > >
> > > > -       if (kernel_or_module_addr(addr) && !init_task_stack_addr(addr)) {
> > > > +       if (kernel_or_module_addr(untagged_addr) &&
> > > > +                       !init_task_stack_addr(untagged_addr)) {
> > > >                 pr_err("The buggy address belongs to the variable:\n");
> > > > -               pr_err(" %pS\n", addr);
> > > > +               pr_err(" %pS\n", untagged_addr);
> > > >         }
> > > >
> > > >         if (page) {
> > > > @@ -314,7 +325,7 @@ void kasan_report(unsigned long addr, size_t size,
> > > >         pr_err("\n");
> > > >
> > > >         if (addr_has_shadow(untagged_addr)) {
> > > > -               print_address_description(untagged_addr);
> > > > +               print_address_description(tagged_addr);
> > > >                 pr_err("\n");
> > > >                 print_shadow_for_address(info.first_bad_addr);
> > > >         } else {
> > > > diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> > > > index 63fca3172659..7804b48f760e 100644
> > > > --- a/mm/kasan/tags.c
> > > > +++ b/mm/kasan/tags.c
> > > > @@ -124,6 +124,53 @@ void check_memory_region(unsigned long addr, size_t size, bool write,
> > > >         }
> > > >  }
> > > >
> > > > +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > > > +void kasan_cache_shrink(struct kmem_cache *cache)
> > > > +{
> > > > +       quarantine_remove_cache(cache);
> > >
> > > This does not look to be necessary. There are no objects from that
> > > cache in the quarantine in general. Let's not over-complicate this.
> > >
> > Ok, we will remove it.
> >
> > >
> > >
> > > > +}
> > > > +
> > > > +struct qlist_object *qobject_create(struct kasan_free_meta *info,
> > > > +                                               struct kmem_cache *cache)
> > > > +{
> > > > +       struct qlist_object *qobject_info;
> > > > +       void *object;
> > > > +
> > > > +       object = ((void *)info) - cache->kasan_info.free_meta_offset;
> > > > +       qobject_info = kmalloc(sizeof(struct qlist_object), GFP_NOWAIT);
> > > > +       if (!qobject_info)
> > > > +               return NULL;
> > > > +       qobject_info->addr = (unsigned long) object;
> > > > +       qobject_info->size = cache->object_size;
> > > > +       set_track(&qobject_info->free_track, GFP_NOWAIT);
> > > > +
> > > > +       return qobject_info;
> > > > +}
> > > > +
> > > > +static struct kmem_cache *qobject_to_cache(struct qlist_object *qobject)
> > > > +{
> > > > +       return virt_to_head_page(qobject)->slab_cache;
> > >
> > > This looks identical to the existing qlink_to_cache, please use the
> > > existing function.
> > >
> > > > +}
> > > > +
> > > > +void qobject_free(struct qlist_node *qlink, struct kmem_cache *cache)
> > > > +{
> > > > +       struct qlist_object *qobject = container_of(qlink,
> > > > +                       struct qlist_object, qnode);
> > > > +       unsigned long flags;
> > > > +
> > > > +       struct kmem_cache *qobject_cache =
> > > > +                       cache ? cache : qobject_to_cache(qobject);
> > >
> > > I don't understand this part.
> > > Will caller ever pass us the right cache? Or cache is always NULL? If
> > > it's always NULL, why do we accept it at all?
> > 2 call flow at v2.
> > a). kmalloc() -> quarantine_reduce() -> qlist_free_all(&to_free, NULL)
> > -> qlink_free(qlink, NULL) -> qobject_free(qlink, NULL)
> > b). kmem_cache_shrink() -> kasan_cache_shrink(cache) ->
> > quarantine_remove_cache() -> qlist_free_all(&to_free, cache); ->
> > qlink_free(qlink, cache) -> qobject_free(qlink, cache)
> >
> > It passes the NULL parameter at flow a.
> > It passes the cache of slab at flow b.
> >
> > We always need calculate the slab cache to If we remove flow b.
> 
> Good. Let's do it. The simpler, the better.
> 
> > > We also allocate qobjects with kmalloc always, so we must use kfree,
> > > why do we even mess with caches?
> > >
> > We call ___cache_free() to free the qobject instead of kfree(), because
> > it should be out of quarantine.
> 
> I see. Probably this mismatch worth a comment.
> 
Yes, we will add the comment at qobject_free() in order to avoid letting
others misunderstand.


> > > > +
> > > > +       if (IS_ENABLED(CONFIG_SLAB))
> > > > +               local_irq_save(flags);
> > > > +
> > > > +       ___cache_free(qobject_cache, (void *)qobject, _THIS_IP_);
> > > > +
> > > > +       if (IS_ENABLED(CONFIG_SLAB))
> > > > +               local_irq_restore(flags);
> > > > +}
> > > > +#endif
> > > > +
> > > >  #define DEFINE_HWASAN_LOAD_STORE(size)                                 \
> > > >         void __hwasan_load##size##_noabort(unsigned long addr)          \
> > > >         {                                                               \
> > > > diff --git a/mm/kasan/tags_report.c b/mm/kasan/tags_report.c
> > > > index 8eaf5f722271..63b0b1f381ff 100644
> > > > --- a/mm/kasan/tags_report.c
> > > > +++ b/mm/kasan/tags_report.c
> > > > @@ -36,7 +36,13 @@
> > > >
> > > >  const char *get_bug_type(struct kasan_access_info *info)
> > > >  {
> > > > -       return "invalid-access";
> > > > +       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS_IDENTIFY)) {
> > > > +               if (quarantine_find_object((void *)info->access_addr, NULL))
> > > > +                       return "use-after-free";
> > > > +               else
> > > > +                       return "out-of-bounds";
> > > > +       } else
> > > > +               return "invalid-access";
> > > >  }
> > > >
> > > >  void *find_first_bad_addr(void *addr, size_t size)
> > > > diff --git a/mm/slub.c b/mm/slub.c
> > > > index 1b08fbcb7e61..751429d02846 100644
> > > > --- a/mm/slub.c
> > > > +++ b/mm/slub.c
> > > > @@ -3004,7 +3004,7 @@ static __always_inline void slab_free(struct kmem_cache *s, struct page *page,
> > > >                 do_slab_free(s, page, head, tail, cnt, addr);
> > > >  }
> > > >
> > > > -#ifdef CONFIG_KASAN_GENERIC
> > > > +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS_IDENTIFY)
> > > >  void ___cache_free(struct kmem_cache *cache, void *x, unsigned long addr)
> > > >  {
> > > >         do_slab_free(cache, virt_to_head_page(x), x, NULL, 1, addr);


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1560236742.4832.34.camel%40mtksdccf07.
For more options, visit https://groups.google.com/d/optout.
