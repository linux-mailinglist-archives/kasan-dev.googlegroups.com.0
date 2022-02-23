Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKEL3KIAMGQE3RQMYMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id C8E8F4C1B60
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Feb 2022 20:06:17 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id a5-20020a92c545000000b002c2875a2a57sf1100903ilj.0
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Feb 2022 11:06:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645643176; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pda+zVzrdgr0XOaOjdFPZf0nOPfiih4D2sQur5+vChFuFONVC21Nmpufny2ULHigka
         PZ4qnO/4W8Y7iA+8/HqD2y8DfJ0We5LlI+IBaDq2ryB8QU+gnBgL4fgAZDfu8m4t9dPp
         /8QxtuVFPu4+WFI6XGmh0KMCIogwwvjkpKloKAwzE4ra+FrN0JUIz6/8ekYW+SYMApW7
         3lUT1p/RoO/wqHUBQNDMZ4WjfOpHsNlEZtl/MLjNhp4eKL7sEX1CTYuzZK2eyc1V+IZL
         /NvN8RFk3NcG4+SE/F3RhFvnq0mScFItleRZSz0eT55xMLbVXNhBqEcnbPxEV8ZhQOG8
         r9vQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=y/LWo9KlsSKZnWcoPOlW0AzwWA5Hb9Rv7TwiAiAfqlo=;
        b=zi0St7ryMrkT5Jr/7bnE9euVdxL2jDOep9RObXg3HqK5Zl7GZmUMbEmvIXOhdv5dDw
         aHg4AO4R8GFhYPGINGyuB4AKhZC8QH6UDVVI57CpVrhma58Ap5Mld+jC076c8qMUCknC
         f3iCMVGF1oCUln/6X8nva/mBlM7J8SpwHGsHDpPWp+8a9ueSlQYkzhVG2XgCMn6IsLiO
         vChzSGK6FttfT613SnVZgippEdwcXDs/ZafmxpOQPb7hL8AGkTSJ72+H0lem1tcLeU8i
         /eamHVzrQIRX3hgMTOhA4z+uuPbaSIIijlJ1lB4+CMnj0nyknIDgtR8yEJPBQQ9mNVEx
         Y6QQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XTcWUGqn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y/LWo9KlsSKZnWcoPOlW0AzwWA5Hb9Rv7TwiAiAfqlo=;
        b=DhMg21IklaG9ZFP3VpZ1RkmWSx0KR3VVBPDDrDO41psOk13Vxo+tZUoQxtUuSRBfW4
         7O951j/UySpKZapaf0n0kG/7P1ltYBLaAkB3L2p/E4bAmuo/Gjkkgd9u2s6NT/2GLY/+
         rAbkDyg31Y2ijNaIf57dnBjvBqbPonDRzaEK7y7+CAslVyiqhumps4gLk7XTlUc089sh
         9PF8BrHuUXJdqipSIYwjqxEVMgKYUZA+FpOMqUu9HRhIYAs6+4fGlgufN8v1MbqMbImc
         bx0fOcH5bPKquLpEXscr8AzEA10SZAHIx1gMRlPA3iZwhstB+ppfAox61WtvsSreUvrs
         +ZDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y/LWo9KlsSKZnWcoPOlW0AzwWA5Hb9Rv7TwiAiAfqlo=;
        b=X88xX8Er7afVL3Yg775DyL7h6sssGY6zza0nZf2uGPz6SYWcQCDGpqXL+x6hZcdZcK
         sTQ4qLWIylyKWryiOTDtBIML8oQ7zeCLCFjpmzTqlXsZG1gnt8esQif0Nd/91/aTN9TQ
         wzjaXr/uamJEwqiRVHS0PLTQ0UMq/KPsHw6ywgdEpS1GTyMsPhep2V4JZGww+JxAo9cA
         2sr/IapCjqyZXTNFpBPdhsyMIQBzki6tPHjNs7YGfSRI6XAEn3lYPeQMYRwe68gZh0hU
         hUyc9gxwCbXWRKSGX3xgNoXfpmuO/a1jaKkch2Z/5+gr1Y/yaq5ikJd8K9DDAsMNkeQY
         /aoA==
X-Gm-Message-State: AOAM532nvXkuf66QM44OBjR7jz6GfISkTja6BoT79njx2x7Ir3UYlnP1
	gmQyDRSf/UcgoZTYOTVCGSM=
X-Google-Smtp-Source: ABdhPJybZm5IAlc3qetgmGQuz1P/KwEnmYcjJ+57R7K94GhrHe+vwHt8oYkzrb2AwNoRa64uDmg7aw==
X-Received: by 2002:a05:6638:4189:b0:314:5435:76a1 with SMTP id az9-20020a056638418900b00314543576a1mr803364jab.263.1645643176636;
        Wed, 23 Feb 2022 11:06:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:218e:b0:314:37ea:5626 with SMTP id
 s14-20020a056638218e00b0031437ea5626ls176219jaj.0.gmail; Wed, 23 Feb 2022
 11:06:14 -0800 (PST)
X-Received: by 2002:a05:6638:164a:b0:314:e841:c9f8 with SMTP id a10-20020a056638164a00b00314e841c9f8mr846409jat.193.1645643174750;
        Wed, 23 Feb 2022 11:06:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645643174; cv=none;
        d=google.com; s=arc-20160816;
        b=OmiFt2hQ8CU2sKe6l7EL4ZtfbuFG8hj7hb+iJ7c0x3jri3WgZDprZK4+ewpdEL1xUF
         SWhsbUim6BhDlLBeZoCY6GHwlwYVrRI5/KmhGGqvPSBWpoWCZU9JmW6iZYJ/H7zmuQDd
         8vuFasyQOVX4BDd9hrivbszyzy6JBR/GEElo7uPx7FjczjNFTs325SnKkbXGR6NQyV0f
         4wOwGcyvOtBSpc8Efts+rXcwwxVW4fte6cvAtsZgzpQbGGQJnobDgfdQzKJeuSKsAGt4
         9patwKB3yTDckb4Dnqvpja20aPu4BFUN8Rssi3vLX42ZoI6JfWFWInjbe3+52JauY+XQ
         bqKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+uyB8qTyiqJA+8KT+MhYk3e+WJLsuNUugcYRMD4HHtc=;
        b=OgPyXSFc7VG/p/XMbHF7tFdnCp81AfCcYuCTuVEFh5+yvdmIWaRfSThgKWAbWW68aY
         HYHTcd0fN68IYItU4na6DQvZrrNq78JAodZpaTSBvjxircIJGkLvbtQa0oJS5nTjyAyI
         /+DDgjixE50PCRAJToqLEU7qHV4xGpHtCCbzggvxkG9USS4SlOyGWVNxjIrWGcuDfWOo
         dosKeOjzBGB6WQoA7fW0t6DA3CtMU0GUmJw4xpi8uq/2202BLurimL1aghnnHCMfVMPL
         NXDkZFfmhFhwMpLC/vXV0JyBqIA4XJ1V+HQFok+7Wcvdj2FRnw+4HeZ+LYMaFlEoltYn
         AcIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XTcWUGqn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id w6si18627iov.3.2022.02.23.11.06.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Feb 2022 11:06:14 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id w63so28743696ybe.10
        for <kasan-dev@googlegroups.com>; Wed, 23 Feb 2022 11:06:14 -0800 (PST)
X-Received: by 2002:a25:a4e8:0:b0:61e:1eb6:19bd with SMTP id
 g95-20020a25a4e8000000b0061e1eb619bdmr1094373ybi.168.1645643174054; Wed, 23
 Feb 2022 11:06:14 -0800 (PST)
MIME-Version: 1.0
References: <20220221105336.522086-1-42.hyeyoo@gmail.com> <20220221105336.522086-2-42.hyeyoo@gmail.com>
 <4d42fcec-ff59-2e37-4d8f-a58e641d03c8@suse.cz>
In-Reply-To: <4d42fcec-ff59-2e37-4d8f-a58e641d03c8@suse.cz>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 23 Feb 2022 20:06:02 +0100
Message-ID: <CANpmjNMjgSKommNCrfyFuaz+3HQdW92ZSF_p26LQdmS0o3L98Q@mail.gmail.com>
Subject: Re: [PATCH 1/5] mm/sl[au]b: Unify __ksize()
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org, Roman Gushchin <guro@fb.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-kernel@vger.kernel.org, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, David Rientjes <rientjes@google.com>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, Kees Cook <keescook@chromium.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrey Konovalov <andreyknvl@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=XTcWUGqn;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as
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

On Wed, 23 Feb 2022 at 19:39, Vlastimil Babka <vbabka@suse.cz> wrote:
> On 2/21/22 11:53, Hyeonggon Yoo wrote:
> > Only SLOB need to implement __ksize() separately because SLOB records
> > size in object header for kmalloc objects. Unify SLAB/SLUB's __ksize().
> >
> > Signed-off-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> > ---
> >  mm/slab.c        | 23 -----------------------
> >  mm/slab_common.c | 29 +++++++++++++++++++++++++++++
> >  mm/slub.c        | 16 ----------------
> >  3 files changed, 29 insertions(+), 39 deletions(-)
> >
> > diff --git a/mm/slab.c b/mm/slab.c
> > index ddf5737c63d9..eb73d2499480 100644
> > --- a/mm/slab.c
> > +++ b/mm/slab.c
> > @@ -4199,27 +4199,4 @@ void __check_heap_object(const void *ptr, unsigned long n,
> >  }
> >  #endif /* CONFIG_HARDENED_USERCOPY */
> >
> > -/**
> > - * __ksize -- Uninstrumented ksize.
> > - * @objp: pointer to the object
> > - *
> > - * Unlike ksize(), __ksize() is uninstrumented, and does not provide the same
> > - * safety checks as ksize() with KASAN instrumentation enabled.
> > - *
> > - * Return: size of the actual memory used by @objp in bytes
> > - */
> > -size_t __ksize(const void *objp)
> > -{
> > -     struct kmem_cache *c;
> > -     size_t size;
> >
> > -     BUG_ON(!objp);
> > -     if (unlikely(objp == ZERO_SIZE_PTR))
> > -             return 0;
> > -
> > -     c = virt_to_cache(objp);
> > -     size = c ? c->object_size : 0;
>
> This comes from commit a64b53780ec3 ("mm/slab: sanity-check page type when
> looking up cache") by Kees and virt_to_cache() is an implicit check for
> folio slab flag ...
>
> > -
> > -     return size;
> > -}
> > -EXPORT_SYMBOL(__ksize);
> > diff --git a/mm/slab_common.c b/mm/slab_common.c
> > index 23f2ab0713b7..488997db0d97 100644
> > --- a/mm/slab_common.c
> > +++ b/mm/slab_common.c
> > @@ -1245,6 +1245,35 @@ void kfree_sensitive(const void *p)
> >  }
> >  EXPORT_SYMBOL(kfree_sensitive);
> >
> > +#ifndef CONFIG_SLOB
> > +/**
> > + * __ksize -- Uninstrumented ksize.
> > + * @objp: pointer to the object
> > + *
> > + * Unlike ksize(), __ksize() is uninstrumented, and does not provide the same
> > + * safety checks as ksize() with KASAN instrumentation enabled.
> > + *
> > + * Return: size of the actual memory used by @objp in bytes
> > + */
> > +size_t __ksize(const void *object)
> > +{
> > +     struct folio *folio;
> > +
> > +     if (unlikely(object == ZERO_SIZE_PTR))
> > +             return 0;
> > +
> > +     folio = virt_to_folio(object);
> > +
> > +#ifdef CONFIG_SLUB
> > +     if (unlikely(!folio_test_slab(folio)))
> > +             return folio_size(folio);
> > +#endif
> > +
> > +     return slab_ksize(folio_slab(folio)->slab_cache);
>
> ... and here in the common version you now for SLAB trust that the folio
> will be a slab folio, thus undoing the intention of that commit. Maybe
> that's not good and we should keep the folio_test_slab() for both cases?
> Although maybe it's also strange that prior this patch, SLAB would return 0
> if the test fails, and SLUB would return folio_size(). Probably because with
> SLUB this can be a large kmalloc here and with SLAB not. So we could keep
> doing that in the unified version, or KASAN devs (CC'd) could advise
> something better?

Is this a definitive failure case? My opinion here is that returning 0
from ksize() in case of failure will a) provide a way to check for
error, and b) if the size is used unconditionally to compute an
address may be the more graceful failure mode (see comment added in
0d4ca4c9bab39 for what happens if we see invalid memory per KASAN
being accessed).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMjgSKommNCrfyFuaz%2B3HQdW92ZSF_p26LQdmS0o3L98Q%40mail.gmail.com.
