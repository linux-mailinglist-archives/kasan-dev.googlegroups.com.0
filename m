Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBJGDXOVQMGQE6MT4IQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 201F2804CAE
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Dec 2023 09:39:02 +0100 (CET)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-1fb04956beesf4119212fac.0
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Dec 2023 00:39:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701765541; cv=pass;
        d=google.com; s=arc-20160816;
        b=qwmLaYGsvjsyTe6bUNcLWgeQ8f1XWnM+YymjKMJyAIBQEcZAcpUkysrWIQ/WDjRhu4
         RJriRT84sCzNw8jxiSYSiLJwOv6bJuFN0ZUtyKDtHMLdFWv3FPlDrrVsHQuzYSIva+a4
         SH16htpHw2fnyQN13B7YfD7Gvffqvxnx8mugA1VBDAm8Q/1RsDNjEd/zA5l1n9zPLZSx
         n+/3AbZZTCtkzaicCJ95caKLobn/B3YSf21zVkJ+xaX9e3QmVB128sL9VBixqjkxjVUX
         aoZ3xPzPjzDe5L/ND2U7x4zGOCXczbDsDJBAqH5o7Wy0bYtJpKIc9PAsft1YAKn5DFex
         R/hA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=LiUmvipw3BljGyVZVwDoDL3RU7jvt/5y0OLoM/TpCow=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=jz92BiybkI4AS8xMqT9vtwVWImACmDl6IpqlQA+JSXD/D5RK89hAVtcMLzw4h9salU
         6gXcnW54sOOpwYsBwK/oxEE3yc729wbY7OeZ2gkLdOoonMLPXf/0SlulWfWgRxZ3BxUo
         /27XCJyHtCXnmPYad1hHaL3kFi9bbPNg03sSd/ID7MOdBsqJrwT9L66R++J3a/oYvvnp
         8JjUCMwaTkE+bYv2JU0TiEeKzxQAjnyWv32tFQX41AxcKNLNZ8XwC64OA1aMXkPYWX31
         Ef2d+p/pgU5f2ouaQ+MONIjjr+WJZJ3nFdSfs+RXPlgxKiHYZt/8uZ5h/gRDLXMzzssj
         VFGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Kp890iJA;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::92e as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701765541; x=1702370341; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=LiUmvipw3BljGyVZVwDoDL3RU7jvt/5y0OLoM/TpCow=;
        b=G7AZ6DX5G6rzaNMkhBHxtbeEXmDpc7rWvBThHvWnP1Ja1xNZz2UT7bs7Tw7VPND/vu
         K5h77N3xuV+Aoxos22o4l+//o+dU0NPQkM/Yj/91ICBtz5h+XUIg4vHgKCUTe6+yjDMB
         tyA8ZhuuqwB6WC2sAJ1x6m/dlf5tQETHCXchHb8quuzpyUcA6DTHQLPGaWdEFtUjYxs/
         F31AjrjeDHHyNiOfeFb2Yx8T/bDaekrZBG3Ejqy6K75MzHQ3fdiTaxygbLLRzl2jaKfw
         mic+fQDle9o+EFs5viDFDsO642Qa3+mHxAPQODTQbmkpZ97LVD1fG1PLJXUSY7nfFflY
         OVcQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701765541; x=1702370341; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LiUmvipw3BljGyVZVwDoDL3RU7jvt/5y0OLoM/TpCow=;
        b=BWxLOhXD14PgN5ZhP/O5LcIAKU1TmI54GMutOAs0IZpwckZVTuHrxEv8hJUNJnXqA3
         /9H0yAbOLRZHZCarhVz56bAcwkoAsU5MLRZBb0a4agFrsVKwv7GFMLFulW87dv/OCRhC
         NjhR19k0gTdjK2+uBTX8re0bDBnFJkqkd1AYTObuG0rQhN6Z3QAnIvaYLgG7wGFH0NSO
         IlWOVXEYocjz6WHMSBIz0eBwjLWKJBjdfGKKKqmoUVd97HxbPHtzkYcCGyC7OBbSSlFE
         GJ9ZeVSVk7YljIh3an/KSIt3WKHpy62+kmSS7kQ0DiXcwu6/62J4I7OGXQiJwM/b6p7x
         DMBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701765541; x=1702370341;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LiUmvipw3BljGyVZVwDoDL3RU7jvt/5y0OLoM/TpCow=;
        b=u70++r8sHJhy6OrCSDhVGGG9Z1p0q/LAE6KIQMkxKIkywpPkx3EFn16IJDaLGWuqkN
         BkNNdtPoOotdQHuUVXh2VoIIBU/QrSUWTsNkB0F17iq5qevdIS9GtY/ad0Stlyqe1HVI
         jY+rClyAkmMugT5IXc3EUjMxUNp9WppyB1QRNnTN9BjhIg8awpoMmf/inzS0PVvn504j
         04R7/U7kGKeIDekYU3D2IwYQoGxUxNKEeZD4QWhEPNU4CN2STDEGeVu0EuYXKMwdi3G+
         IOTQj50qqgq1OTINkI7O2T8MR6q8rqdiC20qnxjeyiQRkwbkQyB1GM5XlENdKOXXPc4T
         P2PA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxcgjq/9eOjCVh4XVmvdCVf5VOeyKlB3mP0NbDtrY+ZQGhg/KEg
	Z8mjfGZGI28ejfjrI+6zrPQ=
X-Google-Smtp-Source: AGHT+IG2DvHJvW6UeRuTH8yA8wp8IlgK1iqYLwlf/eAX41j5uAilcxjei+mxdxi4CQX64PY8NftByw==
X-Received: by 2002:a05:6870:961f:b0:1f9:f54a:f5ef with SMTP id d31-20020a056870961f00b001f9f54af5efmr443163oaq.19.1701765540902;
        Tue, 05 Dec 2023 00:39:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:454:b0:1f4:88df:8b64 with SMTP id
 i20-20020a056870045400b001f488df8b64ls8464914oak.1.-pod-prod-09-us; Tue, 05
 Dec 2023 00:39:00 -0800 (PST)
X-Received: by 2002:a05:6870:d252:b0:1fa:ee9e:85d5 with SMTP id h18-20020a056870d25200b001faee9e85d5mr4058460oac.11.1701765540629;
        Tue, 05 Dec 2023 00:39:00 -0800 (PST)
Received: by 2002:a05:620a:1789:b0:778:a9dc:3cb2 with SMTP id af79cd13be357-77f1b08c380ms85a;
        Mon, 4 Dec 2023 20:48:19 -0800 (PST)
X-Received: by 2002:ac8:5a53:0:b0:410:9668:530a with SMTP id o19-20020ac85a53000000b004109668530amr1030754qta.21.1701751699034;
        Mon, 04 Dec 2023 20:48:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701751699; cv=none;
        d=google.com; s=arc-20160816;
        b=nZvq2/ZuB1pxqOQtizK3pdTtIxuWGjLH2aPkEll3yWpiqTp4pS3Qg0HkOt1Ympafc1
         1PwaO/n8+Nuf/63YgRua6EiJnJwrfjozZBG04v7NEhp4C/zuAVHbEMamTdK7zwemz4Z1
         1glUbplce2hVr6UVjO9WZiirQ4OE2BQOJSv5Mxjx7bmxJh4JumYphTbnySBwhW86QFwJ
         mhvtv+U7GgcthEIGZBSCrYyy4nz3ypQkt6dde69aNF5aqJoS79xxkldj14phAR2uCvYi
         gR7HKwihyUgHBaBkncUweYttOjATRZs8yuO7wCN03RA9Q+2p3jXx/MWSa5FTfG0uu47y
         nV9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=l6U7HYB+MMDXs4im/MnwOh3wT6+xRnbqGtkbQLiIJbE=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=QXIhRzmNaXPVHN4CCCe0RKMtQPxvubdwXJx33Kj4Ael0H0VLL1SkC2RRq760IapUdB
         e3E1gUYD/LLI71Ls511gVkBAXh4OgzTYtQVYc+eQsSr8csn/hQbYMz+LA4oN8twAWweI
         ygt7SGREqaS8R8XCYV3u8RpfD075+Mca5p53hKwsquxEROCJz9d+0TDzgLoQpo5TMpdy
         p+UdkSusiQnAs2X7+kqwtJN2/Q4x/q4xWlensn63sooa1HG9F6bmFF0dgOzVDhAvcsVm
         hbDip8yYGe5ckeGNIYCfRfAVLM+7gXIz8TInOZpp47OrCo+LXu2mzEimxAd820XPOhkA
         gl/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Kp890iJA;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::92e as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ua1-x92e.google.com (mail-ua1-x92e.google.com. [2607:f8b0:4864:20::92e])
        by gmr-mx.google.com with ESMTPS id bw17-20020a05622a099100b0041ce9eb6295si2465284qtb.1.2023.12.04.20.48.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Dec 2023 20:48:19 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::92e as permitted sender) client-ip=2607:f8b0:4864:20::92e;
Received: by mail-ua1-x92e.google.com with SMTP id a1e0cc1a2514c-7c59ac49f12so1640354241.1
        for <kasan-dev@googlegroups.com>; Mon, 04 Dec 2023 20:48:19 -0800 (PST)
X-Received: by 2002:a05:6102:2dc:b0:464:77f1:f34e with SMTP id
 h28-20020a05610202dc00b0046477f1f34emr651042vsh.28.1701751698506; Mon, 04 Dec
 2023 20:48:18 -0800 (PST)
MIME-Version: 1.0
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
 <20231120-slab-remove-slab-v2-3-9c9c70177183@suse.cz> <ZW6mjFlmm0ME18OQ@localhost.localdomain>
In-Reply-To: <ZW6mjFlmm0ME18OQ@localhost.localdomain>
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Date: Tue, 5 Dec 2023 13:48:07 +0900
Message-ID: <CAB=+i9R+zZo-AGuEAYDzEZV7f=YSC9fdczARQijk-WPZUr0iDA@mail.gmail.com>
Subject: Re: [PATCH v2 03/21] KASAN: remove code paths guarded by CONFIG_SLAB
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Marco Elver <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>, Michal Hocko <mhocko@kernel.org>, 
	Shakeel Butt <shakeelb@google.com>, Muchun Song <muchun.song@linux.dev>, 
	Kees Cook <keescook@chromium.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org, 
	linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Kp890iJA;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::92e
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On Tue, Dec 5, 2023 at 1:27=E2=80=AFPM Hyeonggon Yoo <42.hyeyoo@gmail.com> =
wrote:
>
> On Mon, Nov 20, 2023 at 07:34:14PM +0100, Vlastimil Babka wrote:
> > With SLAB removed and SLUB the only remaining allocator, we can clean u=
p
> > some code that was depending on the choice.
> >
> > Reviewed-by: Kees Cook <keescook@chromium.org>
> > Reviewed-by: Marco Elver <elver@google.com>
> > Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> > ---
> >  mm/kasan/common.c     | 13 ++-----------
> >  mm/kasan/kasan.h      |  3 +--
> >  mm/kasan/quarantine.c |  7 -------
> >  3 files changed, 3 insertions(+), 20 deletions(-)
> >
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 256930da578a..5d95219e69d7 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -153,10 +153,6 @@ void __kasan_poison_object_data(struct kmem_cache =
*cache, void *object)
> >   * 2. A cache might be SLAB_TYPESAFE_BY_RCU, which means objects can b=
e
> >   *    accessed after being freed. We preassign tags for objects in the=
se
> >   *    caches as well.
> > - * 3. For SLAB allocator we can't preassign tags randomly since the fr=
eelist
> > - *    is stored as an array of indexes instead of a linked list. Assig=
n tags
> > - *    based on objects indexes, so that objects that are next to each =
other
> > - *    get different tags.
> >   */
> >  static inline u8 assign_tag(struct kmem_cache *cache,
> >                                       const void *object, bool init)
> > @@ -171,17 +167,12 @@ static inline u8 assign_tag(struct kmem_cache *ca=
che,
> >       if (!cache->ctor && !(cache->flags & SLAB_TYPESAFE_BY_RCU))
> >               return init ? KASAN_TAG_KERNEL : kasan_random_tag();
> >
> > -     /* For caches that either have a constructor or SLAB_TYPESAFE_BY_=
RCU: */
> > -#ifdef CONFIG_SLAB
> > -     /* For SLAB assign tags based on the object index in the freelist=
. */
> > -     return (u8)obj_to_index(cache, virt_to_slab(object), (void *)obje=
ct);
> > -#else
> >       /*
> > -      * For SLUB assign a random tag during slab creation, otherwise r=
euse
> > +      * For caches that either have a constructor or SLAB_TYPESAFE_BY_=
RCU,
> > +      * assign a random tag during slab creation, otherwise reuse
> >        * the already assigned tag.
> >        */
> >       return init ? kasan_random_tag() : get_tag(object);
> > -#endif
> >  }
> >
> >  void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index 8b06bab5c406..eef50233640a 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -373,8 +373,7 @@ void kasan_set_track(struct kasan_track *track, gfp=
_t flags);
> >  void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp=
_t flags);
> >  void kasan_save_free_info(struct kmem_cache *cache, void *object);
> >
> > -#if defined(CONFIG_KASAN_GENERIC) && \
> > -     (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
> > +#ifdef CONFIG_KASAN_GENERIC
> >  bool kasan_quarantine_put(struct kmem_cache *cache, void *object);
> >  void kasan_quarantine_reduce(void);
> >  void kasan_quarantine_remove_cache(struct kmem_cache *cache);
> > diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> > index ca4529156735..138c57b836f2 100644
> > --- a/mm/kasan/quarantine.c
> > +++ b/mm/kasan/quarantine.c
> > @@ -144,10 +144,6 @@ static void qlink_free(struct qlist_node *qlink, s=
truct kmem_cache *cache)
> >  {
> >       void *object =3D qlink_to_object(qlink, cache);
> >       struct kasan_free_meta *meta =3D kasan_get_free_meta(cache, objec=
t);
> > -     unsigned long flags;
> > -
> > -     if (IS_ENABLED(CONFIG_SLAB))
> > -             local_irq_save(flags);
> >
> >       /*
> >        * If init_on_free is enabled and KASAN's free metadata is stored=
 in
> > @@ -166,9 +162,6 @@ static void qlink_free(struct qlist_node *qlink, st=
ruct kmem_cache *cache)
> >       *(u8 *)kasan_mem_to_shadow(object) =3D KASAN_SLAB_FREE;
> >
> >       ___cache_free(cache, object, _THIS_IP_);
> > -
> > -     if (IS_ENABLED(CONFIG_SLAB))
> > -             local_irq_restore(flags);
> >  }
> >
> >  static void qlist_free_all(struct qlist_head *q, struct kmem_cache *ca=
che)
>
> Looks good to me,
> Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

nit: Some KASAN tests depends on SLUB, but as now it's the only allocator
      KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB); in
      mm/kasan/kasan_test.c can be removed

>
> >
> > --
> > 2.42.1
> >
> >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAB%3D%2Bi9R%2BzZo-AGuEAYDzEZV7f%3DYSC9fdczARQijk-WPZUr0iDA%40mai=
l.gmail.com.
