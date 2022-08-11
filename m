Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3VC2OLQMGQE2GTPTLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id EDF1D58FA47
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Aug 2022 11:52:47 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id m5-20020a170902f64500b0016d313f3ce7sf11288435plg.23
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Aug 2022 02:52:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660211566; cv=pass;
        d=google.com; s=arc-20160816;
        b=GvKwAd0yHyy7Ji3PdQ3VNHrU47j90bwu+XJncOYlIJ6wR0cf8/JOoZs44YyWBxFm2r
         Oizt0LG33sT5oRJReutFmY5a48t6gNyJfISh7FOgGPd7hfprIvJPYQsCrDoWavIxIo/v
         7xjYTBB1pOnrCJr45/aBTOebkrnhIM/eHdWCOwbNbtCrROaokHjOeITxlICk8qId7WQB
         dxIDg4176sndNcE08FDBNIianf8Rv+EHigdeyXUlBT20iwTXi49cp9qbOI2JyquX2Nod
         iH4yaYcDY+3Cf9DYI3iAjVY8Kpe7lDfS/U+3etrcxzC3H2S1lxIkw/C/cAZ0h/l5yac+
         SAyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=G/Wfjeb3esXxroHfgnq808qjecG1umKLIwbX9m1IKsU=;
        b=SE94t6sxKfO6yLfh+8bIhdMHL4Fz+KODpRlxUIg5mLProZtkAbHZoeyV9KOycQz4ov
         IRYO3TR0Q52e2dOURtvMR600LOySFpE9tdNGYd73qGcKIYekMO9Vy6jYkNqgysL45vUE
         BT9nnncDb1BDHx15lUoGbHvYtrnb6AllulospCUxOMJnUyXhtEoQNccMP6Abwr0ovvuh
         eVkbfxNbfM3Ln0LxeQm7yTzt1xPScDBVhiFXHrHbhQ77DUqkKhV7PYqtkGk+ovocmo6N
         EF7yjCVb8Oyy+8BQhP0hVY5q8uiGRxiWeWHziwk2Qo6n9hCEBrpdRqqNGJiQwhQbBVbb
         FYug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VqdDDiDV;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=G/Wfjeb3esXxroHfgnq808qjecG1umKLIwbX9m1IKsU=;
        b=aWosHM3n7YptSmxqcW1ZMdcKn9l8wF289Ztf23nbbYFOM8aCOFl99ATmq05nggM+IF
         N85yVHtPkKrJYWTwdUYKfoFIkou/ezTo332yVHApAKcej5yfXD13u5ByhyfRkfO2edpx
         dM/Uvv4bzJGBXOL3e5BJQPnx/ieSXzABwOKlF1sJfW9cCc5Y4d6fGRkXF+VMirRw2LtI
         pULIo3cEqoZgsInVBbVUfQFGHQYNHyxIuZ6x+igbtiE3oL7XRgHiA4R/EqEsTQa+rp7w
         1Kc7NwEQ/kbmP/ClDWtoIiqSMwdR/whKVudisrVnfVG2QddoDJPeu3783DWTHYFnQars
         rnUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=G/Wfjeb3esXxroHfgnq808qjecG1umKLIwbX9m1IKsU=;
        b=rs2LtBf89N2pdA3sreBdgV//6di3JA9cIQ+Bqshq8EoAbqJFRpYFv3MLViAJJt2Fgu
         016jWLyfi0uUBFvoiMHDJsqMUiVcNYyu1PBPaD5jMFwU3yWTRS+T6s/ys7G3kwkdmYZX
         N5tRs9VJCvck94Txz5knUhuKcpceB8wXLmOADtI45XkA6MwueHyL7T/90rjBHxBPNaPP
         4stDTC5ylgh2dqvBoLD0RYRJyTXsJfehpZfSDOlxh/C7KsJptSwcKncKvloQfAJB+LQV
         7I7MEYPqTMRb+HQtIkqFGgpD/gFAxaI80q5EgRMpUEgv/hizrdPkeVhyQ9cNYvgThQST
         9N2g==
X-Gm-Message-State: ACgBeo3eGXvbQtShoLgpisDsxHglpqDV370loJ7BQzboPfndDAlItqmx
	K3aLf8UiuqoZ9bxui2Hv/Mo=
X-Google-Smtp-Source: AA6agR6/Ucej4IHkJeRhE+EhJAMzFFJ3mxoq/2ppyCxnNRE+yXYLqIvQ6S67lWS4Zgim33iMAWgdfQ==
X-Received: by 2002:a17:90b:514:b0:1f5:59b2:fceb with SMTP id r20-20020a17090b051400b001f559b2fcebmr8118832pjz.82.1660211566146;
        Thu, 11 Aug 2022 02:52:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:130b:b0:1f2:fb55:49b0 with SMTP id
 h11-20020a17090a130b00b001f2fb5549b0ls2724436pja.2.-pod-canary-gmail; Thu, 11
 Aug 2022 02:52:45 -0700 (PDT)
X-Received: by 2002:a17:903:2113:b0:16f:6ee:65f2 with SMTP id o19-20020a170903211300b0016f06ee65f2mr31878473ple.76.1660211565285;
        Thu, 11 Aug 2022 02:52:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660211565; cv=none;
        d=google.com; s=arc-20160816;
        b=cY1QlWQUFw3b5+MgWJVIfdrxyoNL+dVJhdJtCXMkriQX64qk/y8elCPk4AGCnLlV+e
         82dlw7IlgC111ITRMuXZIQsyPFzNQR3fUWqc9XMqD8vBE1pm26f76hnG0m7IMTtFPU+V
         KAvQmn/hz+sNA4e5xWINlGZw7k1qXa3Igiyl6mmZ7DxEOLEQtCS5TJURNvcqtEx/evaQ
         6N85bnwhrI8nVPtoNkZAWm7jque6X8rFgtYJI+TTRdX7+fTwyQvugI6WKyXNNdlSzKIv
         Cg/i0g/qjN2Gn+ur+k0Ybs96Kgb75D8Ju/OJKFR7e7JA+RcRpBDQJKZnLvh4fAj1gNsz
         TaRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4TbeJ47O6jDOlyunrlIhv/Q2h3DuJDhmv18eJjgF8uk=;
        b=asneYN4TiijVcCeKuR2ZhqKAt5lc6xqAQUhs+vP0JoOOcjrPfS/0r7Xo1MlXtBGX2q
         8V8peVBXj1MgpluEO+NLNIs2wvTGNbnoNq7Zil0YVzxpjsnDMslV6SW0339f5IWv8uiZ
         +wfKMpdohC8UxTbIHlzd566eSEu6857f4SS+rZQLc7Fb4HR3b/zR37B+NupEXa4iQe1J
         x6/SaOjfa+xDAsKfg1yD9mddCLHKT3t0kSE0fcGB0c9elCdBGj+8NOpM1rNOaGXh69W2
         sIRgn9JGWX8QwuhVkuek+Kh1o/ertI7asskBhlpJtjThBLR4L+o4zcwRKIi4PG+iBh8A
         pPDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VqdDDiDV;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112b.google.com (mail-yw1-x112b.google.com. [2607:f8b0:4864:20::112b])
        by gmr-mx.google.com with ESMTPS id np13-20020a17090b4c4d00b001f29166eab0si145435pjb.0.2022.08.11.02.52.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Aug 2022 02:52:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112b as permitted sender) client-ip=2607:f8b0:4864:20::112b;
Received: by mail-yw1-x112b.google.com with SMTP id 00721157ae682-32269d60830so167692757b3.2
        for <kasan-dev@googlegroups.com>; Thu, 11 Aug 2022 02:52:45 -0700 (PDT)
X-Received: by 2002:a0d:eb12:0:b0:31f:38af:6ff with SMTP id
 u18-20020a0deb12000000b0031f38af06ffmr31250407ywe.4.1660211564413; Thu, 11
 Aug 2022 02:52:44 -0700 (PDT)
MIME-Version: 1.0
References: <20220811085938.2506536-1-imran.f.khan@oracle.com> <d3cd0f34-b30b-9a1d-8715-439ffb818539@suse.cz>
In-Reply-To: <d3cd0f34-b30b-9a1d-8715-439ffb818539@suse.cz>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 11 Aug 2022 11:52:07 +0200
Message-ID: <CANpmjNMYwxbkOc+LxLfZ--163yfXpQj69oOfEFkSwq7JZurbdA@mail.gmail.com>
Subject: Re: [PATCH v2] Introduce sysfs interface to disable kfence for
 selected slabs.
To: vbabka@suse.cz
Cc: Imran Khan <imran.f.khan@oracle.com>, glider@google.com, dvyukov@google.com, 
	cl@linux.com, penberg@kernel.org, rientjes@google.com, iamjoonsoo.kim@lge.com, 
	akpm@linux-foundation.org, roman.gushchin@linux.dev, 42.hyeyoo@gmail.com, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=VqdDDiDV;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112b as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 11 Aug 2022 at 11:31, <vbabka@suse.cz> wrote:
>
> On 8/11/22 10:59, Imran Khan wrote:
> > By default kfence allocation can happen for any slab object, whose size
> > is up to PAGE_SIZE, as long as that allocation is the first allocation
> > after expiration of kfence sample interval. But in certain debugging
> > scenarios we may be interested in debugging corruptions involving
> > some specific slub objects like dentry or ext4_* etc. In such cases
> > limiting kfence for allocations involving only specific slub objects
> > will increase the probablity of catching the issue since kfence pool
> > will not be consumed by other slab objects.
>
> So you want to enable specific caches for kfence.
>
> > This patch introduces a sysfs interface '/sys/kernel/slab/<name>/skip_kfence'
> > to disable kfence for specific slabs. Having the interface work in this
> > way does not impact current/default behavior of kfence and allows us to
> > use kfence for specific slabs (when needed) as well. The decision to
> > skip/use kfence is taken depending on whether kmem_cache.flags has
> > (newly introduced) SLAB_SKIP_KFENCE flag set or not.
>
> But this seems everything is still enabled and you can selectively disable.
> Isn't that rather impractical?

A script just iterates through all the caches that they don't want,
and sets skip_kfence? It doesn't look more complicated.

> How about making this cache flag rather denote that KFENCE is enabled (not
> skipped), set it by default only for for caches with size <= 1024, then you

Where does 1024 come from? PAGE_SIZE?

The problem with that opt-in vs. opt-out is that it becomes more
complex to maintain opt-in (as the first RFC of this did). With the
new flag SLAB_SKIP_KFENCE, it also can serve a dual purpose, where
someone might want to explicitly opt out by default and pass it to
kmem_cache_create() (for whatever reason; not that we'd encourage
that).

I feel that the real use cases for selectively enabling caches for
KFENCE are very narrow, and a design that introduces lots of
complexity elsewhere, just to support this feature cannot be justified
(which is why I suggested the simpler design here back in
https://lore.kernel.org/lkml/CANpmjNNmD9z7oRqSaP72m90kWL7jYH+cxNAZEGpJP8oLrDV-vw@mail.gmail.com/
)

> can drop the size check in __kfence_alloc and rely only on the flag? And if
> you need, you can also enable a cache with size > 1024 with the sysfs
> interface, to override the limit, which isn't possible now.
> (I don't think changing the limit to always act on s->object_size instead of
> e.g. size passed to kmalloc() that it can pick up now, will change anything
> in practice)
> Then you can also have a kernel boot param that tells kfence to set the flag
> on no cache at all, and you can easily enable just the specific caches you
> want. Or make a parameter that lets you override the 1024 size limit
> globally, and if you set it to 0, it means no cache is enabled for kfence?
>
> > Signed-off-by: Imran Khan <imran.f.khan@oracle.com>
> > ---
> >
> > Changes since v1:
> >  - Remove RFC tag
> >
> >  include/linux/slab.h |  6 ++++++
> >  mm/kfence/core.c     |  7 +++++++
> >  mm/slub.c            | 27 +++++++++++++++++++++++++++
> >  3 files changed, 40 insertions(+)
> >
> > diff --git a/include/linux/slab.h b/include/linux/slab.h
> > index 0fefdf528e0d..947d912fd08c 100644
> > --- a/include/linux/slab.h
> > +++ b/include/linux/slab.h
> > @@ -119,6 +119,12 @@
> >   */
> >  #define SLAB_NO_USER_FLAGS   ((slab_flags_t __force)0x10000000U)
> >
> > +#ifdef CONFIG_KFENCE
> > +#define SLAB_SKIP_KFENCE            ((slab_flags_t __force)0x20000000U)
> > +#else
> > +#define SLAB_SKIP_KFENCE            0
> > +#endif
> > +
> >  /* The following flags affect the page allocator grouping pages by mobility */
> >  /* Objects are reclaimable */
> >  #define SLAB_RECLAIM_ACCOUNT ((slab_flags_t __force)0x00020000U)
> > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > index c252081b11df..8c08ae2101d7 100644
> > --- a/mm/kfence/core.c
> > +++ b/mm/kfence/core.c
> > @@ -1003,6 +1003,13 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
> >               return NULL;
> >       }
> >
> > +     /*
> > +      * Skip allocations for this slab, if KFENCE has been disabled for
> > +      * this slab.
> > +      */
> > +     if (s->flags & SLAB_SKIP_KFENCE)
> > +             return NULL;
> > +
> >       if (atomic_inc_return(&kfence_allocation_gate) > 1)
> >               return NULL;
> >  #ifdef CONFIG_KFENCE_STATIC_KEYS
> > diff --git a/mm/slub.c b/mm/slub.c
> > index 862dbd9af4f5..ee8b48327536 100644
> > --- a/mm/slub.c
> > +++ b/mm/slub.c
> > @@ -5745,6 +5745,30 @@ STAT_ATTR(CPU_PARTIAL_NODE, cpu_partial_node);
> >  STAT_ATTR(CPU_PARTIAL_DRAIN, cpu_partial_drain);
> >  #endif       /* CONFIG_SLUB_STATS */
> >
> > +#ifdef CONFIG_KFENCE
> > +static ssize_t skip_kfence_show(struct kmem_cache *s, char *buf)
> > +{
> > +     return sysfs_emit(buf, "%d\n", !!(s->flags & SLAB_SKIP_KFENCE));
> > +}
> > +
> > +static ssize_t skip_kfence_store(struct kmem_cache *s,
> > +                     const char *buf, size_t length)
> > +{
> > +     int ret = length;
> > +
> > +     if (buf[0] == '0')
> > +             s->flags &= ~SLAB_SKIP_KFENCE;
> > +     else if (buf[0] == '1')
> > +             s->flags |= SLAB_SKIP_KFENCE;
> > +     else
> > +             ret = -EINVAL;
> > +
> > +     return ret;
> > +}
> > +SLAB_ATTR(skip_kfence);
> > +
> > +#endif
> > +
> >  static struct attribute *slab_attrs[] = {
> >       &slab_size_attr.attr,
> >       &object_size_attr.attr,
> > @@ -5812,6 +5836,9 @@ static struct attribute *slab_attrs[] = {
> >       &failslab_attr.attr,
> >  #endif
> >       &usersize_attr.attr,
> > +#ifdef CONFIG_KFENCE
> > +     &skip_kfence_attr.attr,
> > +#endif
> >
> >       NULL
> >  };
> >
> > base-commit: 40d43a7507e1547dd45cb02af2e40d897c591870
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMYwxbkOc%2BLxLfZ--163yfXpQj69oOfEFkSwq7JZurbdA%40mail.gmail.com.
