Return-Path: <kasan-dev+bncBAABB2FEXHTQKGQEWDWJDPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 06E8C2D927
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 11:35:38 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id c16sf1318691ioo.20
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 02:35:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559122537; cv=pass;
        d=google.com; s=arc-20160816;
        b=DZEqCzPYCP2C2A2uxEMPTI43yph1gG40i0PCs+EXC98EoKMi8jvdGqIJ6YvSYp7khq
         Lo3wuYO29x72M3Oq2ulo72PrfF1dqreK0hMEP9XTNz3YJT8HIpDB4nBMcEhK+kfQ/Vxx
         zxPA8DQ6qJrEyRejDiEcmJxvV9Xf8lANTI9LkDq4bGSJxqxxb+RSPFxpBY0+0/+FiG66
         TwvZrQ4u4A9eEfGJEs3SQ+zLW11Y77Nf4fnqxi/wec+pyuAwvz03Yi8DPyQX0yOzI2i3
         E9oToSLhp59eAwBgIM4tYtX5tjvOirTqBfiJRGcH/6je9BUp8BlZB82HTpIcfx9XuXX6
         8yFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=Tp7VnSdYQb9XGkaatNJID8V8kFFNHXRySGn/yohPK9M=;
        b=fJiVpWbtyjKCoiQs7hADxuqnMyu+P9xNZjxlKba2w37uSjYWpZwnrKWdZXLg7KG5RH
         cxNDR8M+T2a3TLvi2/iCQaUx2EWc96AQC5xLVeB7chlUopjN8KDs4riDMHI7virqxzdb
         9bxvdR5xCc6hNhb9HQTlYNKRvfPG/PnlP4zSfuPK4eOeByF1FQO/1jnw04IQgftvXgl9
         xSIPYZ1fWnGuuis0/5B2xiIcarZ5LrfjgGbNaXRXKL7kRZakJruZLPHZ9cluhdZ3Ue4l
         g0sgovnj/TeI62gvROMejl4CZVqYxjcoe6CUrujHhEu+Je3jX+5nTYwun3ntoyScTkwg
         dOwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Tp7VnSdYQb9XGkaatNJID8V8kFFNHXRySGn/yohPK9M=;
        b=GTxudNQUnlcp+/C2tn4u/8rW7aBMOw0ZOOjbr2oWdqTPI8BGvX4xbnEOIrRQKM7HVS
         qce7VIsEoW2ahPj0xhLtC9VZJ2uUgErSR8Ex7GTs8oWhstmlhyTaZnoXSRZFp5ZtK0bC
         QqfhmQO8KhqHciAcuNfjMwEE5aeANG7XaR9k9uPiW9H0q69ZYdyKzRMOKHSB+xXKVyWW
         WsnckKDf3iDfi1r1QoXnsgOs0m3mrRv9gqmRA5DHoEU5QNtoVPK4VyfI5VhKNOwZ8WBD
         mZL3lyBg7cx3dbf0aZTLO5oezWC3H7MS7M3aFZHUqCZlVJvv57TTgknMtcHfjk8ObcmJ
         zlCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Tp7VnSdYQb9XGkaatNJID8V8kFFNHXRySGn/yohPK9M=;
        b=ZblZktV8Hgo61GZ7KkaC/WlsX0yt9VcQhlvakT1n978pJbgDcFMGUbirezDeK0GEJR
         OjU/KnFMznBzUWgLuGL2pyFwzh9K9z3zVZW0xfg4+Uww65l6WHQ27YeddMJQchrHZSz5
         Q7HKoQVfkzPGLD1+JiwcdrVsTY9TtP+cHq4lLyy7MiZhEZLsWWhCfot8oRIADKVXzwU6
         PK/ISDxoWTyg3FIugdAqByehrhtqQkG+fPbch6bMqk+CGHr2/4TD8DiJhIXGSfPLXnfW
         XTCbCYpVIAUe7iHw6E3AUlIBxDwnVh1j/c3Bkh2gqKtP8b71lov9LDhwyMyGkQs4u/v0
         ow9w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVTolzdgpFdqwMPFY6zBLfegLYWI/+YXPNH2a27PBWxe8RAcvep
	SuxU5mIE5CGo7BpOiuoIlHI=
X-Google-Smtp-Source: APXvYqyVNRP14cLdgV1g3QWehr0JRyG2s+Wx5puKjAbrpI9JVXn10BGRDx7sTSIjFxiryjreH0ejXA==
X-Received: by 2002:a5d:9e49:: with SMTP id i9mr17152662ioi.290.1559122536933;
        Wed, 29 May 2019 02:35:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:a12:: with SMTP id z18ls260439ioi.15.gmail; Wed, 29 May
 2019 02:35:36 -0700 (PDT)
X-Received: by 2002:a6b:e61a:: with SMTP id g26mr10026496ioh.300.1559122536683;
        Wed, 29 May 2019 02:35:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559122536; cv=none;
        d=google.com; s=arc-20160816;
        b=eZYmIRWqfkFQ9DSI7lCB5AWLfvK12sfLDtSZ8yUt1amr5G4e6pU7AxAeCJbZyUfjVQ
         e88Z97j9pkOUO6OfmqU+vnwHMHMMzEVChZ+x5MSpMPH1u+VwmRVv7x47SUervxTo0RG3
         i+wMJEQDd4AJVzzw6DsIGR7Gv9UCtpYz1Wn792vspEiB6bMv1CWdFov+TdMj5x4Br6g1
         /2dK2JQSORGz2SpmFD3WeRxHt4akpUQiTrZ4NRd3g/eWVUX881XK2guIdsuATxPQ13Bz
         /SBbtMRvm0I+egCkmlpL8ARqoH4U4wH2bTvSUIUiXahdh00cQzHukGZojst3cqZIPM1O
         aPmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=hw+1Ev5zFt94wvsuAYSmAQUyzNkosySEKNw8VlJkIRc=;
        b=LLjn0OoRi2/gboDYETE5MMgbiA8UtOJ2zjWEd7a1QokKuYmxQ3FBBvFVDkne6L0SSw
         cIWFdADiMfYXt7dGklCD58OcmCJE8OExs0sXgfAdzjrPxLfs25G1T3itJ6mfQEZHtYOt
         pH6TZXQhal09kTK0LzTxTYBlsSia7B9gx52spuvIa5GyBb6dWY4eo6H+W29LNm4KkX7b
         spEKINAAl36PLx2e9sqCx8AyopV8/Glf70ud9lrSMud8kH7o8oxzFw9HSZbkwe34DoUX
         qZnfJb5aT1WNC8BRA85ueSN/sLG06y5p9ZryAqmqmdGdK4zN39arzxF0+vB/voj8jdJT
         yRPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTPS id a19si80011ita.0.2019.05.29.02.35.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 May 2019 02:35:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: d30e00251bb840368195b29455158f68-20190529
X-UUID: d30e00251bb840368195b29455158f68-20190529
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(mhqrelay.mediatek.com ESMTP with TLS)
	with ESMTP id 605601674; Wed, 29 May 2019 17:35:31 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Wed, 29 May 2019 17:35:29 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Wed, 29 May 2019 17:35:29 +0800
Message-ID: <1559122529.17186.24.camel@mtksdccf07>
Subject: Re: [PATCH] kasan: add memory corruption identification for
 software tag-based mode
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Matthias Brugger <matthias.bgg@gmail.com>, "Miles
 Chen" <miles.chen@mediatek.com>, kasan-dev <kasan-dev@googlegroups.com>, LKML
	<linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, "Linux ARM"
	<linux-arm-kernel@lists.infradead.org>, <linux-mediatek@lists.infradead.org>,
	<wsd_upstream@mediatek.com>, "Catalin Marinas" <catalin.marinas@arm.com>
Date: Wed, 29 May 2019 17:35:29 +0800
In-Reply-To: <CACT4Y+aCnODuffR7PafyYispp_U+ZdY1Dr0XQYvmghkogLJzSw@mail.gmail.com>
References: <1559027797-30303-1-git-send-email-walter-zh.wu@mediatek.com>
	 <CACT4Y+aCnODuffR7PafyYispp_U+ZdY1Dr0XQYvmghkogLJzSw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
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

> Hi Walter,
>=20
> Please describe your use case.
> For testing context the generic KASAN works better and it does have
> quarantine already. For prod/canary environment the quarantine may be
> unacceptable in most cases.
> I think we also want to use tag-based KASAN as a base for ARM MTE
> support in near future and quarantine will be most likely unacceptable
> for main MTE use cases. So at the very least I think this should be
> configurable. +Catalin for this.
>=20
My patch hope the tag-based KASAN bug report make it easier for
programmers to see memory corruption problem.=20
Because now tag-based KASAN bug report always shows =E2=80=9Cinvalid-access=
=E2=80=9D
error, my patch can identify it whether it is use-after-free or
out-of-bound.

We can try to make our patch is feature option. Thanks your suggestion.
Would you explain why the quarantine is unacceptable for main MTE?
Thanks.


> You don't change total quarantine size and charge only sizeof(struct
> qlist_object). If I am reading this correctly, this means that
> quarantine will have the same large overhead as with generic KASAN. We
> will just cache much more objects there. The boot benchmarks may be
> unrepresentative for this. Don't we need to reduce quarantine size or
> something?
>=20
Yes, we will try to choose 2. My original idea is belong to it. So we
will reduce quarantine size.

1). If quarantine size is the same with generic KASAN and tag-based
KASAN, then the miss rate of use-after-free case in generic KASAN is
larger than tag-based KASAN.
2). If tag-based KASAN quarantine size is smaller generic KASAN, then
the miss rate of use-after-free case may be the same, but tag-based
KASAN can save slab memory usage.


>=20
> > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > ---
> >  include/linux/kasan.h  |  20 +++++---
> >  mm/kasan/Makefile      |   4 +-
> >  mm/kasan/common.c      |  15 +++++-
> >  mm/kasan/generic.c     |  11 -----
> >  mm/kasan/kasan.h       |  45 ++++++++++++++++-
> >  mm/kasan/quarantine.c  | 107 ++++++++++++++++++++++++++++++++++++++---
> >  mm/kasan/report.c      |  36 +++++++++-----
> >  mm/kasan/tags.c        |  64 ++++++++++++++++++++++++
> >  mm/kasan/tags_report.c |   5 +-
> >  mm/slub.c              |   2 -
> >  10 files changed, 262 insertions(+), 47 deletions(-)
> >
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index b40ea104dd36..bbb52a8bf4a9 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -83,6 +83,9 @@ size_t kasan_metadata_size(struct kmem_cache *cache);
> >  bool kasan_save_enable_multi_shot(void);
> >  void kasan_restore_multi_shot(bool enabled);
> >
> > +void kasan_cache_shrink(struct kmem_cache *cache);
> > +void kasan_cache_shutdown(struct kmem_cache *cache);
> > +
> >  #else /* CONFIG_KASAN */
> >
> >  static inline void kasan_unpoison_shadow(const void *address, size_t s=
ize) {}
> > @@ -153,20 +156,14 @@ static inline void kasan_remove_zero_shadow(void =
*start,
> >  static inline void kasan_unpoison_slab(const void *ptr) { }
> >  static inline size_t kasan_metadata_size(struct kmem_cache *cache) { r=
eturn 0; }
> >
> > +static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
> > +static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
> >  #endif /* CONFIG_KASAN */
> >
> >  #ifdef CONFIG_KASAN_GENERIC
> >
> >  #define KASAN_SHADOW_INIT 0
> >
> > -void kasan_cache_shrink(struct kmem_cache *cache);
> > -void kasan_cache_shutdown(struct kmem_cache *cache);
> > -
> > -#else /* CONFIG_KASAN_GENERIC */
> > -
> > -static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
> > -static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
>=20
> Why do we need to move these functions?
> For generic KASAN that's required because we store the objects
> themselves in the quarantine, but it's not the case for tag-based mode
> with your patch...
>=20
The quarantine in tag-based KASAN includes new objects which we create.
Those objects are the freed information. They can be shrunk by calling
them. So we move these function into CONFIG_KASAN.=20


> > -
> >  #endif /* CONFIG_KASAN_GENERIC */
> >
> >  #ifdef CONFIG_KASAN_SW_TAGS
> > @@ -180,6 +177,8 @@ void *kasan_reset_tag(const void *addr);
> >  void kasan_report(unsigned long addr, size_t size,
> >                 bool is_write, unsigned long ip);
> >
> > +struct kasan_alloc_meta *get_object_track(void);
> > +
> >  #else /* CONFIG_KASAN_SW_TAGS */
> >
> >  static inline void kasan_init_tags(void) { }
> > @@ -189,6 +188,11 @@ static inline void *kasan_reset_tag(const void *ad=
dr)
> >         return (void *)addr;
> >  }
> >
> > +static inline struct kasan_alloc_meta *get_object_track(void)
> > +{
> > +       return 0;
> > +}
> > +
> >  #endif /* CONFIG_KASAN_SW_TAGS */
> >
> >  #endif /* LINUX_KASAN_H */
> > diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> > index 5d1065efbd47..03b0fe22ec55 100644
> > --- a/mm/kasan/Makefile
> > +++ b/mm/kasan/Makefile
> > @@ -16,6 +16,6 @@ CFLAGS_common.o :=3D $(call cc-option, -fno-conserve-=
stack -fno-stack-protector)
> >  CFLAGS_generic.o :=3D $(call cc-option, -fno-conserve-stack -fno-stack=
-protector)
> >  CFLAGS_tags.o :=3D $(call cc-option, -fno-conserve-stack -fno-stack-pr=
otector)
> >
> > -obj-$(CONFIG_KASAN) :=3D common.o init.o report.o
> > -obj-$(CONFIG_KASAN_GENERIC) +=3D generic.o generic_report.o quarantine=
.o
> > +obj-$(CONFIG_KASAN) :=3D common.o init.o report.o quarantine.o
> > +obj-$(CONFIG_KASAN_GENERIC) +=3D generic.o generic_report.o
> >  obj-$(CONFIG_KASAN_SW_TAGS) +=3D tags.o tags_report.o
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 80bbe62b16cd..919f693a58ab 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -81,7 +81,7 @@ static inline depot_stack_handle_t save_stack(gfp_t f=
lags)
> >         return depot_save_stack(&trace, flags);
> >  }
> >
> > -static inline void set_track(struct kasan_track *track, gfp_t flags)
> > +void set_track(struct kasan_track *track, gfp_t flags)
> >  {
> >         track->pid =3D current->pid;
> >         track->stack =3D save_stack(flags);
> > @@ -457,7 +457,7 @@ static bool __kasan_slab_free(struct kmem_cache *ca=
che, void *object,
> >                 return false;
> >
> >         set_track(&get_alloc_info(cache, object)->free_track, GFP_NOWAI=
T);
> > -       quarantine_put(get_free_info(cache, object), cache);
> > +       quarantine_put(get_free_info(cache, tagged_object), cache);
>=20
> Why do we need this change?
>=20
In order to add freed object information into quarantine.
The freed object information is tag address , size, and free backtrace.


> >
> >         return IS_ENABLED(CONFIG_KASAN_GENERIC);
> >  }
> > @@ -614,6 +614,17 @@ void kasan_free_shadow(const struct vm_struct *vm)
> >                 vfree(kasan_mem_to_shadow(vm->addr));
> >  }
> >
> > +void kasan_cache_shrink(struct kmem_cache *cache)
> > +{
> > +       quarantine_remove_cache(cache);
> > +}
> > +
> > +void kasan_cache_shutdown(struct kmem_cache *cache)
> > +{
> > +       if (!__kmem_cache_empty(cache))
> > +               quarantine_remove_cache(cache);
> > +}
> > +
> >  #ifdef CONFIG_MEMORY_HOTPLUG
> >  static bool shadow_mapped(unsigned long addr)
> >  {
> > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > index 504c79363a34..5f579051dead 100644
> > --- a/mm/kasan/generic.c
> > +++ b/mm/kasan/generic.c
> > @@ -191,17 +191,6 @@ void check_memory_region(unsigned long addr, size_=
t size, bool write,
> >         check_memory_region_inline(addr, size, write, ret_ip);
> >  }
> >
> > -void kasan_cache_shrink(struct kmem_cache *cache)
> > -{
> > -       quarantine_remove_cache(cache);
> > -}
> > -
> > -void kasan_cache_shutdown(struct kmem_cache *cache)
> > -{
> > -       if (!__kmem_cache_empty(cache))
> > -               quarantine_remove_cache(cache);
> > -}
> > -
> >  static void register_global(struct kasan_global *global)
> >  {
> >         size_t aligned_size =3D round_up(global->size, KASAN_SHADOW_SCA=
LE_SIZE);
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index 3e0c11f7d7a1..6848a93660d9 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -95,9 +95,21 @@ struct kasan_alloc_meta {
> >         struct kasan_track free_track;
> >  };
> >
> > +#ifdef CONFIG_KASAN_GENERIC
> >  struct qlist_node {
> >         struct qlist_node *next;
> >  };
> > +#else
> > +struct qlist_object {
> > +       unsigned long addr;
> > +       unsigned int size;
> > +       struct kasan_alloc_meta free_track;
>=20
> Why is this kasan_alloc_meta rather then kasan_track? We don't
> memorize alloc stack...
>=20
Yes, you are right, we only need the free_track of kasan_alloc_meta. We
will change it.


> > +};
> > +struct qlist_node {
> > +       struct qlist_object *qobject;
> > +       struct qlist_node *next;
> > +};
> > +#endif
> >  struct kasan_free_meta {
> >         /* This field is used while the object is in the quarantine.
> >          * Otherwise it might be used for the allocator freelist.
> > @@ -133,16 +145,19 @@ void kasan_report(unsigned long addr, size_t size=
,
> >                 bool is_write, unsigned long ip);
> >  void kasan_report_invalid_free(void *object, unsigned long ip);
> >
> > -#if defined(CONFIG_KASAN_GENERIC) && \
> > +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS) && =
\
>=20
> This condition seems to be always true, no?
>=20
Yes, it is always true, it should be removed.


> >         (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
> > +
> >  void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *c=
ache);
> >  void quarantine_reduce(void);
> >  void quarantine_remove_cache(struct kmem_cache *cache);
> > +void set_track(struct kasan_track *track, gfp_t flags);
> >  #else
> >  static inline void quarantine_put(struct kasan_free_meta *info,
> >                                 struct kmem_cache *cache) { }
> >  static inline void quarantine_reduce(void) { }
> >  static inline void quarantine_remove_cache(struct kmem_cache *cache) {=
 }
> > +static inline void set_track(struct kasan_track *track, gfp_t flags) {=
}
> >  #endif
> >
> >  #ifdef CONFIG_KASAN_SW_TAGS
> > @@ -151,6 +166,15 @@ void print_tags(u8 addr_tag, const void *addr);
> >
> >  u8 random_tag(void);
> >
> > +bool quarantine_find_object(void *object);
> > +
> > +int qobject_add_size(void);
>=20
> Would be more reasonable to use size_t type for object sizes.
>=20
the sum of qobect and qnode size?


> > +
> > +struct qlist_node *qobject_create(struct kasan_free_meta *info,
> > +               struct kmem_cache *cache);
> > +
> > +void qobject_free(struct qlist_node *qlink, struct kmem_cache *cache);
> > +
> >  #else
> >
> >  static inline void print_tags(u8 addr_tag, const void *addr) { }
> > @@ -160,6 +184,25 @@ static inline u8 random_tag(void)
> >         return 0;
> >  }
> >
> > +static inline bool quarantine_find_object(void *object)
> > +{
> > +       return 0;
>=20
> s/0/false/
>=20
Thanks for your friendly reminder. we will change it.


> > +}
> > +
> > +static inline int qobject_add_size(void)
> > +{
> > +       return 0;
> > +}
> > +
> > +static inline struct qlist_node *qobject_create(struct kasan_free_meta=
 *info,
> > +               struct kmem_cache *cache)
> > +{
> > +       return 0;
>=20
> s/0/NULL/
>=20
Thanks for your friendly reminder. we will change it.


> > +}
> > +
> > +static inline void qobject_free(struct qlist_node *qlink,
> > +               struct kmem_cache *cache) {}
> > +
> >  #endif
> >
> >  #ifndef arch_kasan_set_tag
> > diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> > index 978bc4a3eb51..f14c8dbec552 100644
> > --- a/mm/kasan/quarantine.c
> > +++ b/mm/kasan/quarantine.c
> > @@ -67,7 +67,10 @@ static void qlist_put(struct qlist_head *q, struct q=
list_node *qlink,
> >                 q->tail->next =3D qlink;
> >         q->tail =3D qlink;
> >         qlink->next =3D NULL;
> > -       q->bytes +=3D size;
> > +       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
>=20
> It would be more reasonable to pass the right size from the caller. It
> already have to have the branch on CONFIG_KASAN_SW_TAGS because it
> needs to allocate qobject or not, that would be the right place to
> pass the right size.
>=20
In tag-based KASAN, we will pass the sum of qobject and qnode size to it
and review qlist_put() caller whether it pass right size.


> > +               q->bytes +=3D qobject_add_size();
> > +       else
> > +               q->bytes +=3D size;
> >  }
> >
> >  static void qlist_move_all(struct qlist_head *from, struct qlist_head =
*to)
> > @@ -139,13 +142,18 @@ static void *qlink_to_object(struct qlist_node *q=
link, struct kmem_cache *cache)
> >
> >  static void qlink_free(struct qlist_node *qlink, struct kmem_cache *ca=
che)
> >  {
> > -       void *object =3D qlink_to_object(qlink, cache);
> >         unsigned long flags;
> > +       struct kmem_cache *obj_cache =3D
> > +                       cache ? cache : qlink_to_cache(qlink);
> > +       void *object =3D qlink_to_object(qlink, obj_cache);
> > +
> > +       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> > +               qobject_free(qlink, cache);
> >
> >         if (IS_ENABLED(CONFIG_SLAB))
> >                 local_irq_save(flags);
> >
> > -       ___cache_free(cache, object, _THIS_IP_);
> > +       ___cache_free(obj_cache, object, _THIS_IP_);
> >
> >         if (IS_ENABLED(CONFIG_SLAB))
> >                 local_irq_restore(flags);
> > @@ -160,11 +168,9 @@ static void qlist_free_all(struct qlist_head *q, s=
truct kmem_cache *cache)
> >
> >         qlink =3D q->head;
> >         while (qlink) {
> > -               struct kmem_cache *obj_cache =3D
> > -                       cache ? cache : qlink_to_cache(qlink);
> >                 struct qlist_node *next =3D qlink->next;
> >
> > -               qlink_free(qlink, obj_cache);
> > +               qlink_free(qlink, cache);
> >                 qlink =3D next;
> >         }
> >         qlist_init(q);
> > @@ -187,7 +193,18 @@ void quarantine_put(struct kasan_free_meta *info, =
struct kmem_cache *cache)
> >         local_irq_save(flags);
> >
> >         q =3D this_cpu_ptr(&cpu_quarantine);
> > -       qlist_put(q, &info->quarantine_link, cache->size);
> > +       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS)) {
> > +               struct qlist_node *free_obj_info =3D qobject_create(inf=
o, cache);
> > +
> > +               if (!free_obj_info) {
> > +                       local_irq_restore(flags);
> > +                       return;
> > +               }
> > +               qlist_put(q, free_obj_info, cache->size);
> > +       } else {
> > +               qlist_put(q, &info->quarantine_link, cache->size);
> > +       }
> > +
> >         if (unlikely(q->bytes > QUARANTINE_PERCPU_SIZE)) {
> >                 qlist_move_all(q, &temp);
> >
> > @@ -327,3 +344,79 @@ void quarantine_remove_cache(struct kmem_cache *ca=
che)
> >
> >         synchronize_srcu(&remove_cache_srcu);
> >  }
> > +
> > +#ifdef CONFIG_KASAN_SW_TAGS
> > +static struct kasan_alloc_meta object_free_track;
>=20
> This global is a dirty solution. It's better passed as argument to the
> required functions rather than functions leave part of state in a
> global and somebody picks it up later.
>=20
Thanks your suggestion, we will change the implementation here.


> > +
> > +struct kasan_alloc_meta *get_object_track(void)
> > +{
> > +       return &object_free_track;
> > +}
> > +
> > +static bool qlist_find_object(struct qlist_head *from, void *addr)
> > +{
> > +       struct qlist_node *curr;
> > +       struct qlist_object *curr_obj;
> > +
> > +       if (unlikely(qlist_empty(from)))
> > +               return false;
> > +
> > +       curr =3D from->head;
> > +       while (curr) {
> > +               struct qlist_node *next =3D curr->next;
> > +
> > +               curr_obj =3D curr->qobject;
> > +               if (unlikely(((unsigned long)addr >=3D curr_obj->addr)
> > +                       && ((unsigned long)addr <
> > +                                       (curr_obj->addr + curr_obj->siz=
e)))) {
> > +                       object_free_track =3D curr_obj->free_track;
> > +
> > +                       return true;
> > +               }
> > +
> > +               curr =3D next;
> > +       }
> > +       return false;
> > +}
> > +
> > +static int per_cpu_find_object(void *arg)
> > +{
> > +       void *addr =3D arg;
> > +       struct qlist_head *q;
> > +
> > +       q =3D this_cpu_ptr(&cpu_quarantine);
> > +       return qlist_find_object(q, addr);
> > +}
> > +
> > +struct cpumask cpu_allowed_mask __read_mostly;
> > +
> > +bool quarantine_find_object(void *addr)
> > +{
> > +       unsigned long flags, i;
> > +       bool find =3D false;
> > +       int cpu;
> > +
> > +       cpumask_copy(&cpu_allowed_mask, cpu_online_mask);
> > +       for_each_cpu(cpu, &cpu_allowed_mask) {
> > +               find =3D smp_call_on_cpu(cpu, per_cpu_find_object, addr=
, true);
>=20
> There can be multiple qobjects in the quarantine associated with the
> address, right? If so, we need to find the last one rather then a
> random one.
>=20
The qobject includes the address which has tag and range, corruption
address must be satisfied with the same tag and within object address
range, then it is found in the quarantine.
It should not easy to get multiple qobjects have the same tag and within
object address range.


> > +               if (find)
> > +                       return true;
> > +       }
> > +
> > +       raw_spin_lock_irqsave(&quarantine_lock, flags);
> > +       for (i =3D 0; i < QUARANTINE_BATCHES; i++) {
> > +               if (qlist_empty(&global_quarantine[i]))
> > +                       continue;
> > +               find =3D qlist_find_object(&global_quarantine[i], addr)=
;
> > +               /* Scanning whole quarantine can take a while. */
> > +               raw_spin_unlock_irqrestore(&quarantine_lock, flags);
> > +               cond_resched();
> > +               raw_spin_lock_irqsave(&quarantine_lock, flags);
> > +       }
> > +       raw_spin_unlock_irqrestore(&quarantine_lock, flags);
> > +
> > +       synchronize_srcu(&remove_cache_srcu);
> > +
> > +       return find;
> > +}
> > +#endif
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index ca9418fe9232..9cfabf2f0c40 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -150,18 +150,26 @@ static void describe_object_addr(struct kmem_cach=
e *cache, void *object,
> >  }
> >
> >  static void describe_object(struct kmem_cache *cache, void *object,
> > -                               const void *addr)
> > +                               const void *tagged_addr)
> >  {
> > +       void *untagged_addr =3D reset_tag(tagged_addr);
> >         struct kasan_alloc_meta *alloc_info =3D get_alloc_info(cache, o=
bject);
> >
> >         if (cache->flags & SLAB_KASAN) {
> > -               print_track(&alloc_info->alloc_track, "Allocated");
> > -               pr_err("\n");
> > -               print_track(&alloc_info->free_track, "Freed");
> > -               pr_err("\n");
> > +               if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) &&
> > +                       quarantine_find_object((void *)tagged_addr)) {
>=20
> Can't this be an out-of-bound even if we find the object in quarantine?
> For example, if we've freed an object, then reallocated and accessed
> out-of-bounds within the object bounds?
> Overall suggesting that this is a use-after-free rather than
> out-of-bounds without redzones and quarantining the object itself is
> quite imprecise. We can confuse a user even more...
>=20
the qobject stores object range and address which has tag, even if
the object reallocate and accessed out-of-bounds, then new object and
old object in quarantine should be different tag value, so it should be
no found in quarantine.


>=20
> > +                       alloc_info =3D get_object_track();
> > +                       print_track(&alloc_info->free_track, "Freed");
> > +                       pr_err("\n");
> > +               } else {
> > +                       print_track(&alloc_info->alloc_track, "Allocate=
d");
> > +                       pr_err("\n");
> > +                       print_track(&alloc_info->free_track, "Freed");
> > +                       pr_err("\n");
> > +               }
> >         }
> >
> > -       describe_object_addr(cache, object, addr);
> > +       describe_object_addr(cache, object, untagged_addr);
> >  }
> >
> >  static inline bool kernel_or_module_addr(const void *addr)
> > @@ -180,23 +188,25 @@ static inline bool init_task_stack_addr(const voi=
d *addr)
> >                         sizeof(init_thread_union.stack));
> >  }
> >
> > -static void print_address_description(void *addr)
> > +static void print_address_description(void *tagged_addr)
> >  {
> > -       struct page *page =3D addr_to_page(addr);
> > +       void *untagged_addr =3D reset_tag(tagged_addr);
> > +       struct page *page =3D addr_to_page(untagged_addr);
> >
> >         dump_stack();
> >         pr_err("\n");
> >
> >         if (page && PageSlab(page)) {
> >                 struct kmem_cache *cache =3D page->slab_cache;
> > -               void *object =3D nearest_obj(cache, page, addr);
> > +               void *object =3D nearest_obj(cache, page, untagged_addr=
);
> >
> > -               describe_object(cache, object, addr);
> > +               describe_object(cache, object, tagged_addr);
> >         }
> >
> > -       if (kernel_or_module_addr(addr) && !init_task_stack_addr(addr))=
 {
> > +       if (kernel_or_module_addr(untagged_addr) &&
> > +                       !init_task_stack_addr(untagged_addr)) {
> >                 pr_err("The buggy address belongs to the variable:\n");
> > -               pr_err(" %pS\n", addr);
> > +               pr_err(" %pS\n", untagged_addr);
> >         }
> >
> >         if (page) {
> > @@ -314,7 +324,7 @@ void kasan_report(unsigned long addr, size_t size,
> >         pr_err("\n");
> >
> >         if (addr_has_shadow(untagged_addr)) {
> > -               print_address_description(untagged_addr);
> > +               print_address_description(tagged_addr);
> >                 pr_err("\n");
> >                 print_shadow_for_address(info.first_bad_addr);
> >         } else {
> > diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> > index 63fca3172659..fa5d1e29003d 100644
> > --- a/mm/kasan/tags.c
> > +++ b/mm/kasan/tags.c
> > @@ -124,6 +124,70 @@ void check_memory_region(unsigned long addr, size_=
t size, bool write,
> >         }
> >  }
> >
> > +int qobject_add_size(void)
> > +{
> > +       return sizeof(struct qlist_object);
>=20
> Shouldn't this also account for qlist_node?
>=20
yes, we will count it.


> > +}
> > +
> > +static struct kmem_cache *qobject_to_cache(struct qlist_object *qobjec=
t)
> > +{
> > +       return virt_to_head_page(qobject)->slab_cache;
> > +}
> > +
> > +struct qlist_node *qobject_create(struct kasan_free_meta *info,
> > +                                               struct kmem_cache *cach=
e)
> > +{
> > +       struct qlist_node *free_obj_info;
> > +       struct qlist_object *qobject_info;
> > +       struct kasan_alloc_meta *object_track;
> > +       void *object;
> > +
> > +       object =3D ((void *)info) - cache->kasan_info.free_meta_offset;
> > +       qobject_info =3D kmalloc(sizeof(struct qlist_object), GFP_NOWAI=
T);
> > +       if (!qobject_info)
> > +               return NULL;
> > +       qobject_info->addr =3D (unsigned long) object;
> > +       qobject_info->size =3D cache->object_size;
> > +       object_track =3D &qobject_info->free_track;
> > +       set_track(&object_track->free_track, GFP_NOWAIT);
> > +
> > +       free_obj_info =3D kmalloc(sizeof(struct qlist_node), GFP_NOWAIT=
);
>=20
> Why don't we allocate qlist_object and qlist_node in a single
> allocation? Doing 2 allocations is both unnecessary slow and leads to
> more complex code. We need to allocate them with a single allocations.
> Also I think they should be allocated from a dedicated cache that opts
> out of quarantine?
>=20
Single allocation is good suggestion, if we only has one allocation.
then we need to move all member of qlist_object to qlist_node?

struct qlist_object {
    unsigned long addr;
    unsigned int size;
    struct kasan_alloc_meta free_track;
};
struct qlist_node {
    struct qlist_object *qobject;
    struct qlist_node *next;
};


We call call ___cache_free() to free the qobject and qnode, it should be
out of quarantine?


Thanks,
Walter

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1559122529.17186.24.camel%40mtksdccf07.
For more options, visit https://groups.google.com/d/optout.
