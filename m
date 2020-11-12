Return-Path: <kasan-dev+bncBDX4HWEMTEBRBEH5W36QKGQE4AWKFGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 8929B2B124A
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 00:00:33 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id m11sf4755145pgq.7
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 15:00:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605222032; cv=pass;
        d=google.com; s=arc-20160816;
        b=lPSY8p7Phvw7HuzPECmXfqo6CicrqSvX7XOpCmUVbwHRLinMcvoIQI/OdN8nxN7vIt
         iS0FppuIxFHUIGjkKwFNP8T7c3VKZXHFTs+ZKrNmy3lqrvg7Zblb1uOPsDn3nG5rkyBx
         lMF6ChcjJl048jPtRR6maVWM40Wgei/vHXvurX6OnEwPWiwlDieZ2xaFuY9OkYf2HThR
         5+d4o3GKtLpPwUlT23Ht5t7JwICNdhAx43SgjzNphiVdnigivkJiY8qhjj8DmppIvcpu
         ef0i8NoymV/AjusD6WARrGKWwyfgUs677aDkZ93XDCUdcJmRkKfBCdSEM3dsxZDCJ5HU
         Z4ag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=LalxdI2tKbZeDfHicZybVgvYFgb6JZuk/PXbFEv89yk=;
        b=YbwrmF7BVInkopc2F/HgOqgpO7Iv5Awp9CvLWpLl9FebfpyiS4CYOiehogiD80ZCpF
         teOgGI/Y4YoQgSxt/OOWGc5EeY7a8e7hlCJ+zLW3qPvcx5dyceCMQqeqtNlN9koWFNgq
         waXEP6ufhG+/87C2WQknkX+eC0TBPyhBoQt66g3qBRO6Js0KaAEppPfdgGhbWMVoEVnr
         6HAT5IcDLvKtCPff6jXySxj/cT8yM3d5aopFq3YECHCX51OWtol2LB//SKK0Vtj2dwJT
         n9oROLg5SmHkog3wKw2dDHmG1H9bgiCZ7GYRMPRIKq+tGLXusAdFmtEeGlUPZXiNAODh
         /Ygg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZA7ZfI8M;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LalxdI2tKbZeDfHicZybVgvYFgb6JZuk/PXbFEv89yk=;
        b=k+xxCScqc94TCrnSjkYQu4xbaohk4U3pX+SmHrwHaZPiSJSz6Dl3QKfzlhD6bsP855
         kKi5d0zEwo9iw6tbqLwCl71KbehAF7kX1SMCDowS7jDuOXEn9ZlOI3Fv78Dje0HU1mWF
         1i4DNGAwCmxseoDDeRXQXBFTZnNfMVBG8+Qz3lI45Ic2LFpTTws+mk5MdZheLF96Vo9u
         6bR5O9vqSK//6helZndfgyjAT/eKQiM79CqPyAF4rxAJXYgGjDwtldytrAJNYKw1BGBK
         wTQuh2mRYGc7RYy8XOgP4dAlYjIBQU4Cek1N0bjcPpMtHqeHS0GPnTh7Z9bWBAa2ONvh
         EuEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LalxdI2tKbZeDfHicZybVgvYFgb6JZuk/PXbFEv89yk=;
        b=iRTH95AQGZkJ0cjd/Z8bgvUpKo59Z8VeaPQ54vOBivVYN8VlJcGKQ6ahoQFbrMJvLU
         oeWAmLFuw9MRQR761N8koZ6twHu7I/5mF8hYKiswmoAHpSnFcOXn62h54ZK0tURYkrfG
         uyG8X+RUM0FcqS/RBwVMhDldWIRkmPar6+Lhgt6fG3hTklhoQWFRM5uI9sfzdiVrMnBp
         mbAQjUEPO4OYLkhYTgOW6AOuSLU86VFce8qnp2B9jpeSRn51roooJInkBhIU9R1SGMy/
         rA64nVxkJzNB2ibdy6w8s2OuK6GQlWNqUBOav59BMo0oMdhIiKCxLRB/q2xP/QBBS4oL
         dVKg==
X-Gm-Message-State: AOAM530Ta25ITFv60rCpyajrtqwHQNFeMSnobNRijf7FB+OtdDsS5l3M
	DsaHh2KwPg26s1K18qVTb9w=
X-Google-Smtp-Source: ABdhPJxl5LcL1g2hqa8W6SHHKCLmna7GcQC+E64D3Riol3ZsrethXv4T1aUmSgs/FojMqLL3J4b/yw==
X-Received: by 2002:aa7:95a6:0:b029:155:336c:3494 with SMTP id a6-20020aa795a60000b0290155336c3494mr1477483pfk.17.1605222032268;
        Thu, 12 Nov 2020 15:00:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b086:: with SMTP id p6ls2057692plr.7.gmail; Thu, 12
 Nov 2020 15:00:31 -0800 (PST)
X-Received: by 2002:a17:902:a702:b029:d8:c562:14dc with SMTP id w2-20020a170902a702b02900d8c56214dcmr1391367plq.40.1605222031700;
        Thu, 12 Nov 2020 15:00:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605222031; cv=none;
        d=google.com; s=arc-20160816;
        b=Bcd8hHMcCgvdITTtvqaNxrOhQtI5UNhjF2GiZvjGM8uhj+zXbTN+IRZT2iA891XKex
         mwj/+AHIsDhVNM1vf5Yx4ZmPEknsoWyRVC586KYBuFYXXNl2+uQVXAXQ3BUG/SOQxDOE
         SqhXVxLK8ytm/SJvx7aGPgA+mL92wazV3EXEGzwSNIaNLB9RBGiQnVKJxKxAC5JrUWDM
         1zvVWquRaRlwQNI4cRqTIS3Z957B6e9dLvNGki+Fgpa9lPWWLurHByFQrHYaBXAAfkBb
         ahqRB29YTuwFDD4vJlLWG6wCSEAnypzMysDPmUfu5265oQ6OlO2nuAcnWD+u2fOw03ng
         hyoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mjN41sX5qjrZFdnqs5FTcpwE8cevolsZVCKbUpaXMpY=;
        b=BLxcY+no7NOGlB3OomR7IPjltLOMM0Xo5qOPGcvvlQAG5QL3/efgs6/12G/oCgKLul
         0NMKqao9oQyIkR7n4d9c8gG9xhzmnTze3vMDTfEM9kt8b6e4drLeyJRvU66pTOJYXVTZ
         3asm5+/jbOPws4s634GGccLcT9l0EQW7w3CyWLUXz6tF3R+c46sNyMoRw3i6onUEZoVv
         WltGosqbUc7OO4FqQCvpP+BRBO8u1bf2HGDSLFOOPpbMAkTdgrRZ/1Fvv146HUKjGwKU
         YxcWzJmYwWHCVQWhDzyo9T76GZbbr8FjZhaVvpdecFXi1W5X3Jg1oMLkz+oeP1pAwHYN
         HWdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZA7ZfI8M;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id l8si559753pjt.1.2020.11.12.15.00.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Nov 2020 15:00:31 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id c20so5927493pfr.8
        for <kasan-dev@googlegroups.com>; Thu, 12 Nov 2020 15:00:31 -0800 (PST)
X-Received: by 2002:a17:90b:3111:: with SMTP id gc17mr30483pjb.41.1605222031183;
 Thu, 12 Nov 2020 15:00:31 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com> <936c0c198145b663e031527c49a6895bd21ac3a0.1605046662.git.andreyknvl@google.com>
 <20201111151336.GA517454@elver.google.com>
In-Reply-To: <20201111151336.GA517454@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 13 Nov 2020 00:00:20 +0100
Message-ID: <CAAeHK+zXyNEVwLcpB16BAQDKA6OdE9H0BdOFhDo-Osgd4OSSTg@mail.gmail.com>
Subject: Re: [PATCH v2 19/20] kasan, mm: allow cache merging with no metadata
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ZA7ZfI8M;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Wed, Nov 11, 2020 at 4:13 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, Nov 10, 2020 at 11:20PM +0100, Andrey Konovalov wrote:
> > The reason cache merging is disabled with KASAN is because KASAN puts its
> > metadata right after the allocated object. When the merged caches have
> > slightly different sizes, the metadata ends up in different places, which
> > KASAN doesn't support.
> >
> > It might be possible to adjust the metadata allocation algorithm and make
> > it friendly to the cache merging code. Instead this change takes a simpler
> > approach and allows merging caches when no metadata is present. Which is
> > the case for hardware tag-based KASAN with kasan.mode=prod.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Link: https://linux-review.googlesource.com/id/Ia114847dfb2244f297d2cb82d592bf6a07455dba
> > ---
> >  include/linux/kasan.h | 26 ++++++++++++++++++++++++--
> >  mm/kasan/common.c     | 11 +++++++++++
> >  mm/slab_common.c      | 11 ++++++++---
> >  3 files changed, 43 insertions(+), 5 deletions(-)
> >
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index 534ab3e2935a..c754eca356f7 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -81,17 +81,35 @@ struct kasan_cache {
> >  };
> >
> >  #ifdef CONFIG_KASAN_HW_TAGS
> > +
> >  DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
> > +
> >  static inline kasan_enabled(void)
> >  {
> >       return static_branch_likely(&kasan_flag_enabled);
> >  }
> > -#else
> > +
> > +slab_flags_t __kasan_never_merge(slab_flags_t flags);
> > +static inline slab_flags_t kasan_never_merge(slab_flags_t flags)
> > +{
> > +     if (kasan_enabled())
> > +             return __kasan_never_merge(flags);
> > +     return flags;
> > +}
> > +
> > +#else /* CONFIG_KASAN_HW_TAGS */
> > +
> >  static inline kasan_enabled(void)
> >  {
> >       return true;
> >  }
> > -#endif
> > +
> > +static inline slab_flags_t kasan_never_merge(slab_flags_t flags)
> > +{
> > +     return flags;
> > +}
> > +
> > +#endif /* CONFIG_KASAN_HW_TAGS */
> >
> >  void __kasan_alloc_pages(struct page *page, unsigned int order);
> >  static inline void kasan_alloc_pages(struct page *page, unsigned int order)
> > @@ -240,6 +258,10 @@ static inline kasan_enabled(void)
> >  {
> >       return false;
> >  }
> > +static inline slab_flags_t kasan_never_merge(slab_flags_t flags)
> > +{
> > +     return flags;
> > +}
> >  static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
> >  static inline void kasan_free_pages(struct page *page, unsigned int order) {}
> >  static inline void kasan_cache_create(struct kmem_cache *cache,
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 940b42231069..25b18c145b06 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -81,6 +81,17 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
> >  }
> >  #endif /* CONFIG_KASAN_STACK */
> >
> > +/*
> > + * Only allow cache merging when stack collection is disabled and no metadata
> > + * is present.
> > + */
> > +slab_flags_t __kasan_never_merge(slab_flags_t flags)
> > +{
> > +     if (kasan_stack_collection_enabled())
> > +             return flags;
> > +     return flags & ~SLAB_KASAN;
> > +}
> > +
> >  void __kasan_alloc_pages(struct page *page, unsigned int order)
> >  {
> >       u8 tag;
> > diff --git a/mm/slab_common.c b/mm/slab_common.c
> > index f1b0c4a22f08..3042ee8ea9ce 100644
> > --- a/mm/slab_common.c
> > +++ b/mm/slab_common.c
> > @@ -18,6 +18,7 @@
> >  #include <linux/seq_file.h>
> >  #include <linux/proc_fs.h>
> >  #include <linux/debugfs.h>
> > +#include <linux/kasan.h>
> >  #include <asm/cacheflush.h>
> >  #include <asm/tlbflush.h>
> >  #include <asm/page.h>
> > @@ -49,12 +50,16 @@ static DECLARE_WORK(slab_caches_to_rcu_destroy_work,
> >                   slab_caches_to_rcu_destroy_workfn);
> >
> >  /*
> > - * Set of flags that will prevent slab merging
> > + * Set of flags that will prevent slab merging.
> > + * Use slab_never_merge() instead.
> >   */
> >  #define SLAB_NEVER_MERGE (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER | \
> >               SLAB_TRACE | SLAB_TYPESAFE_BY_RCU | SLAB_NOLEAKTRACE | \
> >               SLAB_FAILSLAB | SLAB_KASAN)
>
> Rather than changing this to require using slab_never_merge() which
> removes SLAB_KASAN, could we not just have a function
> kasan_never_merge() that returns KASAN-specific flags that should never
> result in merging -- because as-is now, making kasan_never_merge()
> remove the SLAB_KASAN flag seems the wrong way around.
>
> Could we not just do this:
>
>   #define SLAB_NEVER_MERGE (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER | \
>                 SLAB_TRACE | SLAB_TYPESAFE_BY_RCU | SLAB_NOLEAKTRACE | \
>                 SLAB_FAILSLAB | kasan_never_merge())
>
> ??

The issue here was that SLAB_KASAN is defined in slab.h, which
includes kasan.h, so we can't have a static inline definition of this
function for generic and software tag-based modes. So we can do this,
as long as we're fine with having kasan_never_merge() to be an actual
function call for all KASAN modes. I guess it's not a problem, so
let's do it this way.

>
> Of course that might be problematic if this always needs to be a
> compile-time constant, but currently that's not a requirement.
>
> > +/* KASAN allows merging in some configurations and will remove SLAB_KASAN. */
> > +#define slab_never_merge() (kasan_never_merge(SLAB_NEVER_MERGE))
>
> Braces unnecessary.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzXyNEVwLcpB16BAQDKA6OdE9H0BdOFhDo-Osgd4OSSTg%40mail.gmail.com.
