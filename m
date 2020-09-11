Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5OY5X5AKGQERKXHQ2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D9D5265F77
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Sep 2020 14:24:22 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id s4sf5939193pgk.17
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Sep 2020 05:24:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599827061; cv=pass;
        d=google.com; s=arc-20160816;
        b=lg4VoZEP/JqOWuxA87yAhmVlXNL50cWzN4nXpuSIG9HqNdpdB8f/gmmYZw4QwlK63b
         ML/bxjRpph1HTo5upk1TNmLmOL0Gg4URUoL5dxTqTWzjsTKnghGSFCv4xzVpxj62Sccg
         3x82Xc4s8VsBlyZbThKX1jyIpbWS8M8vLBwAbvLmm5v94k0Utvx/s73yYGBI2GfM92P2
         8mEw5+0eQygZHh5udfqGHcIn2Qv7DPt4PPxoMaLO+mfjsMKxo0EzGlrYzXG0iE6NB4HU
         ScBkOp3Cc82fQIIzcqqxP6+EBnH9pWLUk0hvMrjb7oi+TCV0n+b1abXBj1Z+nXtAHtSX
         sEqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=BMTQZIv4hyPNVUi4Q1mhBrWnISutE0axuzUj+elWtRk=;
        b=yoz0uzqzd2uInnBuOQPJFwSWeHjfxko5OQmPg7Ph6qGcjwbO1CfHVzWJpy2+hMNr7R
         fQuTyfiOg8ESEn0RUHQMxQfG02eA3KeYYJ/bKmcvrQBTYTbBgupfa7W0BazwsFlc3aCX
         7jFQR3IiCct2+FvObFIYi5sjnhpD73B2xv8R6h9b1Csm/3r/hncd6ujTOITcGcZQ3+6M
         rGj68G21O7vL3eeAGfDmEYRy/+vyEcKHQZYsv0Uwh2mBgNV6ytL1kcgQBv645eWzXTUh
         2I5RXfUJRZB0LP9casxmJjP2NQz/3zz9wkKSezS8Dx/98xQYOOX+r2IfQqzpoCYWuTbP
         lK0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AmQEQaDw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BMTQZIv4hyPNVUi4Q1mhBrWnISutE0axuzUj+elWtRk=;
        b=rOQljaqOzOHtwi7eNBur9jmAm0pRrYq7B8IJqzWEarsS0MlUB7DxkxfbQxXeDEVB+c
         ZVKoLkTNm1MhxBm7UGQmaXunInpl1dEoQB79VMPew+SFPWZSLY5cPKizgeD3zuVoo01W
         L4Y/BuqsmgU+cjpWSWR2hdHjUZII4GQWOK/YAjD7aN/phLt/pA1HIyFYEoPszyr1IS7c
         FveOH4Ug1bDX7MvviYTnZ7YvxQ0xmtnK7ZjPQWa0+THGNFvmSvGkp7oiK89AqqyfhKot
         hwjzxfIwsEoEosLjO+aChUh20OlCaCkaDaraccLZqA/94uVUNmIsnb15Fr/vFi81bXS2
         uNZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BMTQZIv4hyPNVUi4Q1mhBrWnISutE0axuzUj+elWtRk=;
        b=YPI3WA/u0TjRFBWMwoGU9gjrhBSaZ5I5NwWXwePcPRQ9eLSI3boX9s0mRoVzvQelx/
         iAek8Juy40HeYWmJiN+E1p1pOVL9widnSIwPLfwF1kOYPTbXXhgsQ3+Qv388B0y5/cA7
         dB+MC1zIWWf3gP0w3vT01cVdyTeZefBoSqsLkaE9FR/J3LZIZPNM2G4wgW3QJeoaiu+u
         pmGW3qIroCmBKe6OpeA9ZUFiutIHLNQsf6xYBoXH83Gxkgzsz6icuZX5oWTogwP2Rx9R
         d0n+D+5PFQSx+OaR2OBk1oN+RjXN2AES5xLd+8d8J+AT4Kh5i/LRsDDXBFThDJsuE9hH
         7epg==
X-Gm-Message-State: AOAM532xKX+bElw4lladhCtkaDXo3yqgD7KDsCAJlGr52kV88x26tFzy
	+OqhwOa8vtZxbJaurfLci3k=
X-Google-Smtp-Source: ABdhPJwBQteem3MNuMx5HGaGxFDG6TGOS19E3R4YxFN3m9s7CgcN6ZrkXMH0arqVF+3QWrMXbxDU/Q==
X-Received: by 2002:a17:902:b206:b029:d0:d07a:6539 with SMTP id t6-20020a170902b206b02900d0d07a6539mr2152440plr.2.1599827061256;
        Fri, 11 Sep 2020 05:24:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:5a45:: with SMTP id o66ls908193pfb.7.gmail; Fri, 11 Sep
 2020 05:24:20 -0700 (PDT)
X-Received: by 2002:a62:1652:: with SMTP id 79mr2030419pfw.28.1599827060616;
        Fri, 11 Sep 2020 05:24:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599827060; cv=none;
        d=google.com; s=arc-20160816;
        b=KS4HxEO5oD4SusnmTXZca1xJyHFl0ds5s0j4KpiMeTeCLDhdYpVaT8ByDzWUDZGbNy
         Xohgx6d9nGFTJwaXCLrwP22TW9uARMJNPyCRk5DGj7QntGizJ0WpBtrWgmDxwEQqFv9i
         KY+AR5yQx8+d71EWO6Bnij3uFZRFapXLsuZIs3UTCiZe84tSkAqklGS5r5g3sE5MUM2N
         FJO8UgEaqq2oaB0zM7OEgfW4DLUQ1Bci9eNElSfAZ6Mphu6ezRXSwYct5QCcnnjV4Jzi
         h1IGPVvogINJKMsZD7+beUTKAjLTd0pqVBl50Hq5Kszp2+smU0ZfyXjJaluJ5LSr7HMh
         /EHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zszRmbpQKBS0800usmmxgfyOo7qtmKwLO7PwkfuP3F8=;
        b=BvYjKy0K7XqyzgGkTO6KP3Q9mdEGlfCObONFTKiK5LLiouZxYjI8IsF+n6hzBF12NT
         QSCOTgqAL9vorfgAKZitpl3EOw2SIaWxtB3wFUJjTeeziEqeR7T5NSUBKiTalI/CzPHl
         QNzPYUfa4HOLvJCMUv77S3dXVAGO6wkWPfRW/+MqzGNzspclxtvAqvriHVO2bZQYh9ZZ
         2W9fz4smL5B0S7WjRaTM5Qg38VT1/LVGvajFjjAzYK22eeO0nD3Kew5zgAfTxQhoMOKk
         zzu5XG2OSDqidMxPhpLyc35JD6rfDW82ccDxPLueZJG0IlbILmlVQOn+yectRHA8XZZv
         WnyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AmQEQaDw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id b9si115475plx.0.2020.09.11.05.24.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Sep 2020 05:24:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id h17so8198143otr.1
        for <kasan-dev@googlegroups.com>; Fri, 11 Sep 2020 05:24:20 -0700 (PDT)
X-Received: by 2002:a05:6830:1e8c:: with SMTP id n12mr1091647otr.17.1599827058228;
 Fri, 11 Sep 2020 05:24:18 -0700 (PDT)
MIME-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com> <20200907134055.2878499-5-elver@google.com>
 <CACT4Y+aXNmQzp6J+mP+ELj8kUHmRPkibc1--KtV9a3ud_X8miw@mail.gmail.com>
In-Reply-To: <CACT4Y+aXNmQzp6J+mP+ELj8kUHmRPkibc1--KtV9a3ud_X8miw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 11 Sep 2020 14:24:06 +0200
Message-ID: <CANpmjNNGZ-bnzzG+nbnCMCNCWGxakJ3wq+pmDjsD5LyWmwmyoQ@mail.gmail.com>
Subject: Re: [PATCH RFC 04/10] mm, kfence: insert KFENCE hooks for SLAB
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Mark Rutland <mark.rutland@arm.com>, Pekka Enberg <penberg@kernel.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@redhat.com>, 
	Jann Horn <jannh@google.com>, Jonathan Corbet <corbet@lwn.net>, Kees Cook <keescook@chromium.org>, 
	Peter Zijlstra <peterz@infradead.org>, Qian Cai <cai@lca.pw>, Thomas Gleixner <tglx@linutronix.de>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=AmQEQaDw;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

On Fri, 11 Sep 2020 at 09:17, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Mon, Sep 7, 2020 at 3:41 PM Marco Elver <elver@google.com> wrote:
> >
> > From: Alexander Potapenko <glider@google.com>
> >
> > Inserts KFENCE hooks into the SLAB allocator.
> >
> > We note the addition of the 'orig_size' argument to slab_alloc*()
> > functions, to be able to pass the originally requested size to KFENCE.
> > When KFENCE is disabled, there is no additional overhead, since these
> > functions are __always_inline.
> >
> > Co-developed-by: Marco Elver <elver@google.com>
> > Signed-off-by: Marco Elver <elver@google.com>
> > Signed-off-by: Alexander Potapenko <glider@google.com>
> > ---
> >  mm/slab.c        | 46 ++++++++++++++++++++++++++++++++++------------
> >  mm/slab_common.c |  6 +++++-
> >  2 files changed, 39 insertions(+), 13 deletions(-)
> >
> > diff --git a/mm/slab.c b/mm/slab.c
> > index 3160dff6fd76..30aba06ae02b 100644
> > --- a/mm/slab.c
> > +++ b/mm/slab.c
> > @@ -100,6 +100,7 @@
> >  #include       <linux/seq_file.h>
> >  #include       <linux/notifier.h>
> >  #include       <linux/kallsyms.h>
> > +#include       <linux/kfence.h>
> >  #include       <linux/cpu.h>
> >  #include       <linux/sysctl.h>
> >  #include       <linux/module.h>
> > @@ -3206,7 +3207,7 @@ static void *____cache_alloc_node(struct kmem_cache *cachep, gfp_t flags,
> >  }
> >
> >  static __always_inline void *
> > -slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid,
> > +slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid, size_t orig_size,
> >                    unsigned long caller)
> >  {
> >         unsigned long save_flags;
> > @@ -3219,6 +3220,10 @@ slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid,
> >         if (unlikely(!cachep))
> >                 return NULL;
> >
> > +       ptr = kfence_alloc(cachep, orig_size, flags);
> > +       if (unlikely(ptr))
> > +               goto out_hooks;
> > +
> >         cache_alloc_debugcheck_before(cachep, flags);
> >         local_irq_save(save_flags);
> >
> > @@ -3251,6 +3256,7 @@ slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid,
> >         if (unlikely(slab_want_init_on_alloc(flags, cachep)) && ptr)
> >                 memset(ptr, 0, cachep->object_size);
> >
> > +out_hooks:
> >         slab_post_alloc_hook(cachep, objcg, flags, 1, &ptr);
> >         return ptr;
> >  }
> > @@ -3288,7 +3294,7 @@ __do_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
> >  #endif /* CONFIG_NUMA */
> >
> >  static __always_inline void *
> > -slab_alloc(struct kmem_cache *cachep, gfp_t flags, unsigned long caller)
> > +slab_alloc(struct kmem_cache *cachep, gfp_t flags, size_t orig_size, unsigned long caller)
> >  {
> >         unsigned long save_flags;
> >         void *objp;
> > @@ -3299,6 +3305,10 @@ slab_alloc(struct kmem_cache *cachep, gfp_t flags, unsigned long caller)
> >         if (unlikely(!cachep))
> >                 return NULL;
> >
> > +       objp = kfence_alloc(cachep, orig_size, flags);
> > +       if (unlikely(objp))
> > +               goto leave;
> > +
> >         cache_alloc_debugcheck_before(cachep, flags);
> >         local_irq_save(save_flags);
> >         objp = __do_cache_alloc(cachep, flags);
> > @@ -3309,6 +3319,7 @@ slab_alloc(struct kmem_cache *cachep, gfp_t flags, unsigned long caller)
> >         if (unlikely(slab_want_init_on_alloc(flags, cachep)) && objp)
> >                 memset(objp, 0, cachep->object_size);
> >
> > +leave:
> >         slab_post_alloc_hook(cachep, objcg, flags, 1, &objp);
> >         return objp;
> >  }
> > @@ -3414,6 +3425,11 @@ static void cache_flusharray(struct kmem_cache *cachep, struct array_cache *ac)
> >  static __always_inline void __cache_free(struct kmem_cache *cachep, void *objp,
> >                                          unsigned long caller)
> >  {
> > +       if (kfence_free(objp)) {
> > +               kmemleak_free_recursive(objp, cachep->flags);
> > +               return;
> > +       }
> > +
> >         /* Put the object into the quarantine, don't touch it for now. */
> >         if (kasan_slab_free(cachep, objp, _RET_IP_))
> >                 return;
> > @@ -3479,7 +3495,7 @@ void ___cache_free(struct kmem_cache *cachep, void *objp,
> >   */
> >  void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
> >  {
> > -       void *ret = slab_alloc(cachep, flags, _RET_IP_);
> > +       void *ret = slab_alloc(cachep, flags, cachep->object_size, _RET_IP_);
>
>
> It's kinda minor, but since we are talking about malloc fast path:
> will passing 0 instead of cachep->object_size (here and everywhere
> else) and then using cachep->object_size on the slow path if 0 is
> passed as size improve codegen?

It doesn't save us much, maybe 1 instruction based on what I'm looking
at right now. The main worry I have is that the 'orig_size' argument
is now part of slab_alloc, and changing its semantics may cause
problems in future if it's no longer just passed to kfence_alloc().
Today, we can do the 'size = size ?: cache->object_size' trick inside
kfence_alloc(), but at the cost breaking the intuitive semantics of
slab_alloc's orig_size argument for future users. Is it worth it?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNGZ-bnzzG%2BnbnCMCNCWGxakJ3wq%2BpmDjsD5LyWmwmyoQ%40mail.gmail.com.
