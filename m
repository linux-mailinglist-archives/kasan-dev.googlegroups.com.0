Return-Path: <kasan-dev+bncBCMIZB7QWENRBPXL5X5AKGQEPEQRH3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id 07DD7266001
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Sep 2020 15:04:00 +0200 (CEST)
Received: by mail-vk1-xa40.google.com with SMTP id w126sf2258351vkb.6
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Sep 2020 06:03:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599829439; cv=pass;
        d=google.com; s=arc-20160816;
        b=CBfkiRDlvNlOw5ZJN+l/Kv3HRur/kyGXOnINGYe5YD9il8JLsFS83vP2g7c2enZjSp
         1dLrqSljkStl5YEkq+iu31wkjLVgiXYHhRtTziQKhf7wwA9hoYxpONOOkcRnqZed/0WD
         sntGDxaOO/KZTeGaW8wFrFg/HPTvr9q4Bbmz3zfHQBopMxlufG9llBelYE3hfIEZY16x
         5Po8unWUppJ5vC7vRAkde+BeKHpKFgTQ6rDEWEBcJ3eL4Aw45V+QcQs5cLVygbfwf/OL
         SIDHgcwBa8Oqt8Iy8NJBzqRJu8eaPS+Bja/pDLXfu6IlqYe0L/KGcrFjtTmWa5kx2cJH
         aOjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=e5dX1pclkFgjmaH9Cz+LebUNEvfsdZH4zKY/owj+Z3o=;
        b=Xycdqgh8uQPfM2DGj3Hw+jk+JArHfzPYSP6by68y1bLTzbJU3KKci1CsTiNBLFG3kY
         AiKeniQxqiCyrwupmrol9zmcRn7pUbEKmFMqEPDJbUEhhnEHtdt/yGF6wv2VoXlS1ywS
         QLffqkI1F/RNTCh9dR5oYRVyyYGPGyubA67CF9YtB5btnIF8V3ClJuHBrl0PQRQaoeVZ
         Jkvh3O85nJSqfOVxbCLwLHoAvaDctylK8wsASCBXkKXcwtzg9zUJUsAWQGQWKlOk9Q3V
         0DQsv/Dn1fPvSGaa65+lSd1b2CalhQ/7/VDJGK8ID6fESHUKTsrzR+pmedEUqsUJzMz3
         ewEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Byv0FemA;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e5dX1pclkFgjmaH9Cz+LebUNEvfsdZH4zKY/owj+Z3o=;
        b=JCUuTH2s7/bPIwjoQeUuHElG8YKFxHCRFo2IPIIJBi5hMWmQjyuxx/HU0e13P3/bq8
         apULyo+liXgb8eyLbPuXRp7ePMZyb2rAIG+LAtj86o3NMSO/lT+KcHLgHWKzR54CVPQ+
         l1uTiCrwxT78y9sdBE6oC4529BF6h9VTUdlgH1QUFXvDW0ZMc9/StpNtDr28+U5VFx60
         O8iLSmWL/dZ8VCatJlsHvjqBy+awXUdVDHk5l6OtvoUbjeyGmdLn/0LyvwYhGmhakPqR
         clUQeEIp9RxKXArDFIQ3xGPv+iJDfvcETFp3SBK2qiW+S4oNFj22kiQUSvFCdQtuMxOY
         QaqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e5dX1pclkFgjmaH9Cz+LebUNEvfsdZH4zKY/owj+Z3o=;
        b=LIZyibkAABKibGX5fvVdFhCe9+jatYb0U2u6froJCuWhZOU4DPue0TP3VWxbkWAj8W
         dMYiG0HD7q6CPblfW7UvFlSegvXUvWY30gO2T5mMZtnFdrJ6Z31jNCabk0n39MRyPKv2
         +f1bLY/ve127G53a+exblurOER3n9rLE/CRP75ooNEkRzuP+a4voK5HKgFHD+dVIHcgO
         ewJS9VGjVcUJ2/V2tdfSyg9cdYxrpmjTBvFXtmGSIOMYDUauKXzPELPDIhpYm8Gwrb6m
         ZvJj3EfSf4d8xlko++1ETKtfHbj9JVDkaKUnIthodWDqIEBwn8SkyodR8MfHGtHk6/X7
         VpGg==
X-Gm-Message-State: AOAM530uldpniscKITy7UsGusGFPdYpP5ekBTIBdw6Wvshilr5Ohksvi
	Pk8/Wu/4dS8t0jzTYF+UtlM=
X-Google-Smtp-Source: ABdhPJxjqRtzklVjkEziPEJGTlElqq9ZhFMSabdK/faad/DbQKFCYsv+4BvDLSOIYoesU30Fr99nhw==
X-Received: by 2002:a67:2d48:: with SMTP id t69mr931746vst.27.1599829439033;
        Fri, 11 Sep 2020 06:03:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:172:: with SMTP id 105ls145717uak.11.gmail; Fri, 11 Sep
 2020 06:03:58 -0700 (PDT)
X-Received: by 2002:a9f:2655:: with SMTP id 79mr784634uag.140.1599829437926;
        Fri, 11 Sep 2020 06:03:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599829437; cv=none;
        d=google.com; s=arc-20160816;
        b=o5WzNauxS9Kujc0zwZ5LLSDLoHemBQcjlqUWH85c9nbdesDVdBmk5iD+IPnOa53mr5
         QvRmeR+Sxl40S9kdv1eHWurbL0uDL6BnuQXqwjnljSKMEJ6dqQTFTk2pH8TZPf9vwHfd
         Dy5+0FdKmrjyblIoEyuMwaM1J5qB0YHE92fuamVnPT4BW1bMY6YFCp74uhusM5ecQQW6
         p9J0vp2UuMZHYjufGNQnOwXBAvwyrfNwyjZ54txlypOu8k2+tS08DSJWyuzp5ZYew5Xf
         AJG9dq7Whi58IAeogm7gwbg5KJTBmZYrxIwKXCno1v50R4Hx1drQBicqzGtqE32JvkkC
         7dlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UXp+wN/Ry6nApS13CcvCEGTyxqKSfC2ghriIPUG6Irg=;
        b=Lu/Zg1r6vcC+CZ4afslASP+IPdBpHzquFCvJka2IegnzhH4xxcIgtmHB4rbn3zp0NH
         cEU4zTSaSf+cWMX9iErKJbkAT5Ggq0RiKUm3ucdh4EjrOZWcxf8923v2lzpWnd18hM4K
         wysQrRob318nPAJl/k0mIbCHWyL6Kz9nAN95H8va2K4Ehpnl1Z6upJKoCb6BdMiOGnsU
         /8pGn76uaA09n4sDkduz6JdQNrCXed9211/giAobTqV8MyOFBLa+wTUOIEs3ppXETlDW
         7rsfkFm0wpqbBVHnipp2LMoa95VIfbDNDSrdjFE75cHlQ94Kvu0j2ppEGFY/06/zK1/3
         YcyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Byv0FemA;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id 134si163022vkx.0.2020.09.11.06.03.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Sep 2020 06:03:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id r8so7685511qtp.13
        for <kasan-dev@googlegroups.com>; Fri, 11 Sep 2020 06:03:57 -0700 (PDT)
X-Received: by 2002:ac8:4806:: with SMTP id g6mr1747161qtq.380.1599829437150;
 Fri, 11 Sep 2020 06:03:57 -0700 (PDT)
MIME-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com> <20200907134055.2878499-5-elver@google.com>
 <CACT4Y+aXNmQzp6J+mP+ELj8kUHmRPkibc1--KtV9a3ud_X8miw@mail.gmail.com> <CANpmjNNGZ-bnzzG+nbnCMCNCWGxakJ3wq+pmDjsD5LyWmwmyoQ@mail.gmail.com>
In-Reply-To: <CANpmjNNGZ-bnzzG+nbnCMCNCWGxakJ3wq+pmDjsD5LyWmwmyoQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 11 Sep 2020 15:03:45 +0200
Message-ID: <CACT4Y+ZGASbeN-O9yzYo6TP_43x-XTpTQ7smK5viM5+E6i5JyQ@mail.gmail.com>
Subject: Re: [PATCH RFC 04/10] mm, kfence: insert KFENCE hooks for SLAB
To: Marco Elver <elver@google.com>
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
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Byv0FemA;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844
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

On Fri, Sep 11, 2020 at 2:24 PM Marco Elver <elver@google.com> wrote:
> > > From: Alexander Potapenko <glider@google.com>
> > >
> > > Inserts KFENCE hooks into the SLAB allocator.
> > >
> > > We note the addition of the 'orig_size' argument to slab_alloc*()
> > > functions, to be able to pass the originally requested size to KFENCE.
> > > When KFENCE is disabled, there is no additional overhead, since these
> > > functions are __always_inline.
> > >
> > > Co-developed-by: Marco Elver <elver@google.com>
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > Signed-off-by: Alexander Potapenko <glider@google.com>
> > > ---
> > >  mm/slab.c        | 46 ++++++++++++++++++++++++++++++++++------------
> > >  mm/slab_common.c |  6 +++++-
> > >  2 files changed, 39 insertions(+), 13 deletions(-)
> > >
> > > diff --git a/mm/slab.c b/mm/slab.c
> > > index 3160dff6fd76..30aba06ae02b 100644
> > > --- a/mm/slab.c
> > > +++ b/mm/slab.c
> > > @@ -100,6 +100,7 @@
> > >  #include       <linux/seq_file.h>
> > >  #include       <linux/notifier.h>
> > >  #include       <linux/kallsyms.h>
> > > +#include       <linux/kfence.h>
> > >  #include       <linux/cpu.h>
> > >  #include       <linux/sysctl.h>
> > >  #include       <linux/module.h>
> > > @@ -3206,7 +3207,7 @@ static void *____cache_alloc_node(struct kmem_cache *cachep, gfp_t flags,
> > >  }
> > >
> > >  static __always_inline void *
> > > -slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid,
> > > +slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid, size_t orig_size,
> > >                    unsigned long caller)
> > >  {
> > >         unsigned long save_flags;
> > > @@ -3219,6 +3220,10 @@ slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid,
> > >         if (unlikely(!cachep))
> > >                 return NULL;
> > >
> > > +       ptr = kfence_alloc(cachep, orig_size, flags);
> > > +       if (unlikely(ptr))
> > > +               goto out_hooks;
> > > +
> > >         cache_alloc_debugcheck_before(cachep, flags);
> > >         local_irq_save(save_flags);
> > >
> > > @@ -3251,6 +3256,7 @@ slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid,
> > >         if (unlikely(slab_want_init_on_alloc(flags, cachep)) && ptr)
> > >                 memset(ptr, 0, cachep->object_size);
> > >
> > > +out_hooks:
> > >         slab_post_alloc_hook(cachep, objcg, flags, 1, &ptr);
> > >         return ptr;
> > >  }
> > > @@ -3288,7 +3294,7 @@ __do_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
> > >  #endif /* CONFIG_NUMA */
> > >
> > >  static __always_inline void *
> > > -slab_alloc(struct kmem_cache *cachep, gfp_t flags, unsigned long caller)
> > > +slab_alloc(struct kmem_cache *cachep, gfp_t flags, size_t orig_size, unsigned long caller)
> > >  {
> > >         unsigned long save_flags;
> > >         void *objp;
> > > @@ -3299,6 +3305,10 @@ slab_alloc(struct kmem_cache *cachep, gfp_t flags, unsigned long caller)
> > >         if (unlikely(!cachep))
> > >                 return NULL;
> > >
> > > +       objp = kfence_alloc(cachep, orig_size, flags);
> > > +       if (unlikely(objp))
> > > +               goto leave;
> > > +
> > >         cache_alloc_debugcheck_before(cachep, flags);
> > >         local_irq_save(save_flags);
> > >         objp = __do_cache_alloc(cachep, flags);
> > > @@ -3309,6 +3319,7 @@ slab_alloc(struct kmem_cache *cachep, gfp_t flags, unsigned long caller)
> > >         if (unlikely(slab_want_init_on_alloc(flags, cachep)) && objp)
> > >                 memset(objp, 0, cachep->object_size);
> > >
> > > +leave:
> > >         slab_post_alloc_hook(cachep, objcg, flags, 1, &objp);
> > >         return objp;
> > >  }
> > > @@ -3414,6 +3425,11 @@ static void cache_flusharray(struct kmem_cache *cachep, struct array_cache *ac)
> > >  static __always_inline void __cache_free(struct kmem_cache *cachep, void *objp,
> > >                                          unsigned long caller)
> > >  {
> > > +       if (kfence_free(objp)) {
> > > +               kmemleak_free_recursive(objp, cachep->flags);
> > > +               return;
> > > +       }
> > > +
> > >         /* Put the object into the quarantine, don't touch it for now. */
> > >         if (kasan_slab_free(cachep, objp, _RET_IP_))
> > >                 return;
> > > @@ -3479,7 +3495,7 @@ void ___cache_free(struct kmem_cache *cachep, void *objp,
> > >   */
> > >  void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
> > >  {
> > > -       void *ret = slab_alloc(cachep, flags, _RET_IP_);
> > > +       void *ret = slab_alloc(cachep, flags, cachep->object_size, _RET_IP_);
> >
> >
> > It's kinda minor, but since we are talking about malloc fast path:
> > will passing 0 instead of cachep->object_size (here and everywhere
> > else) and then using cachep->object_size on the slow path if 0 is
> > passed as size improve codegen?
>
> It doesn't save us much, maybe 1 instruction based on what I'm looking
> at right now. The main worry I have is that the 'orig_size' argument
> is now part of slab_alloc, and changing its semantics may cause
> problems in future if it's no longer just passed to kfence_alloc().
> Today, we can do the 'size = size ?: cache->object_size' trick inside
> kfence_alloc(), but at the cost breaking the intuitive semantics of
> slab_alloc's orig_size argument for future users. Is it worth it?

I don't have an answer to this question. I will leave this to others.
If nobody has strong support for changing semantics, let's leave it as
is. Maybe keep in mind as potential ballast.
FWIW most likely misuse of 0 size for other future purposes should
manifest itself in a quite straightforward way.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZGASbeN-O9yzYo6TP_43x-XTpTQ7smK5viM5%2BE6i5JyQ%40mail.gmail.com.
