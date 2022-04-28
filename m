Return-Path: <kasan-dev+bncBD52JJ7JXILRB442VSJQMGQEYM4OQZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 83013513E3D
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Apr 2022 23:56:04 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id s19-20020ad44b33000000b00456107e1120sf4774435qvw.0
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Apr 2022 14:56:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651182963; cv=pass;
        d=google.com; s=arc-20160816;
        b=O0rp8GcSlULFKqECrnc+BXBVvDAijoYRCOyPEGG+kUGhT4vAXLw9F7Br/9dRy/suX/
         Tfw0YEn+Bie+lC1xqmy+DRELvUG5Ow5Q063q3kPXX/r6tN7Fvg54Rv5V6ib8nVtW0kJH
         ceQJJQ2F6LTCW8KuJeqeJLeOmD6hPf6PBs3dRujN360hArwuIpv4X6GBHP8eoQiIAJ+Y
         3R6s2syeh4DrQnIBBimqTu/WYx+2FYzTXw38w3OzRp9XajuFrwNK1RSpgX3xvaqPaob7
         fUUH9Db6OlfKQUs134XqhrXl/dw2a0HvOr1wmdQfeCoTkxns0cdaQd8DZ2Kqsneo8Ld3
         PoIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=f9zIrDRFa0r7MmdxSHvVuUA7v5LDbruK3iccoKGrVPA=;
        b=ko09MFEevV/j9p4m+j/cELvlO802WpMCc7lNCkgUEPEzD58zglT/h5EbIpULueZOJo
         BzgWZApKZM89r7mrLH3KgtsDGIRC0HVLd4peXzXY/iMaDgvzCWOyMtvY93dNCqR05WoB
         FxsDW4HCGkx/PRlH2QwL06AYIH6yDSp7Ra5W+9ycCNe6bbHE15c8g1RniBZ2rGTitUes
         yQ96Pm9Px/kAHvcj4cpjJtiGHt+39euT4Q0/mUUCuWVlDuvDyoxiUjDEgXhrxwpe2se/
         1iCWUnBDhgkFru8WIVHO5dHcwLBFelORPrboJgYESjzDtMxwQ9OEBlofbw54OHmLsKlH
         +Msw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=OYu5UJio;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::92e as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f9zIrDRFa0r7MmdxSHvVuUA7v5LDbruK3iccoKGrVPA=;
        b=eaClPMujbMSm00fm4FyCdBG11bk4aoXISB0OoQNUP9LVN/OL+8tBnGy28hJm1EzPMm
         PjZxHkWa0NmhU+kFXy6txZ5nAjWDZro76+r78emPlK69IRWEUPNeDb/4VylZKbfUwKPT
         7nZ8XfA0cc6rY+skLXB2JSIYlPrMlLTRHUFSjJ+uYZjCX9agkyzMF9N5xheboc2WLdoj
         qE5JZKA5neUamYgL65YjdJfSOk7VP13VCiLfvII48kwRFclXqfPKdjCAo6KM7BYgcIZE
         Q0LpNgNWBOzcGbqw+zTaiJ0+B6n+sifbFd40N1WxWbYGkWW8Q/t5QV20rRr97nHGlCVV
         pR5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f9zIrDRFa0r7MmdxSHvVuUA7v5LDbruK3iccoKGrVPA=;
        b=GonL1j0hdJjqz/Rd/87uDnXzhDFFAFi3nI9zxZ8QGCgGmpWN6tZGvGaG/FB3ahQ5N0
         tddts+of6wsOPrGznEtEsKEBsDia6u3BGkwmNNaEdkculysbZd4wYM7eSnDfBghaCE/x
         OXvtm2YQA/uJ0wlEcZodwBhxbNtxJq+4/a2l5cC358Kku1G77XnmFXNE5TsPNe1SjnyG
         06aR/PhTlC6S4s7+xoDsEFZAfu77m3F7wStnc9QaPKO7Ipptdsq2xg1VjLWwDiWChizd
         9KWPtow72lQ60DTVjPqWAazUeBzt+k5q3clo92gfW8WGhf0RvjB4FBTPrNyPO6rAV0Ir
         Cp5Q==
X-Gm-Message-State: AOAM530PSoHXhsRu95VNb0c/+HLEEZid6qvovB5Md/UtbhYrCW2z7459
	nEFqeFwbarPKCBop6lurxsc=
X-Google-Smtp-Source: ABdhPJyF6OYwHEg5geF5tXzYHluOFOVp+eFIDjOMLqOsyyceTnUHZdihwSRcHZ6rINnTrQSyYlkOoA==
X-Received: by 2002:a0c:facd:0:b0:456:5186:de3e with SMTP id p13-20020a0cfacd000000b004565186de3emr7602134qvo.71.1651182963461;
        Thu, 28 Apr 2022 14:56:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:f14:b0:69b:dd23:cc12 with SMTP id
 v20-20020a05620a0f1400b0069bdd23cc12ls659803qkl.9.gmail; Thu, 28 Apr 2022
 14:56:03 -0700 (PDT)
X-Received: by 2002:a05:620a:6c8:b0:69c:7adc:7370 with SMTP id 8-20020a05620a06c800b0069c7adc7370mr20592070qky.49.1651182962969;
        Thu, 28 Apr 2022 14:56:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651182962; cv=none;
        d=google.com; s=arc-20160816;
        b=0SZ39EN9RRJL0Q17p0mvesG0C8qBiGQBgyg817tPzcMcsY0XVj3U6qWGMsKr7pnuqb
         wdPnwrxajN9obXOAhkzE4XSCIFmJXaL/1D8BGA7oWbWY0F/fcVhPSxqvTIzba0j5wEPn
         i9W2qPW2Ug/kRGrvWISEuDxfQPH6+oJ9p/cR/lt9ScnGYj3JwlQMSb6yY6Oni5CkUWCU
         KJvDAUCYSAtLdDNO/Dfm/jcRBaLGVrHxHQF3s2gRdOcVaYwAjiATJiX6xybTe4QKWaSd
         9O/CrwOlGUEy+G9QDs+yUL95FZP2S/8wq3lOe8cYaV/1SVtbF91p+GC4lsF2X/1RJrWY
         Yx+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ykl24436SaU3yo8134eJXPByhNLIxnoisxRIQCMfPNU=;
        b=O98PXzYu7aM6sZbwAZ2T+t6bR+b1IPcswEF10h2M9gKdqn0PbhJNv+L/R7QJ6/5DV0
         DklQIkZ7QdVzNugWXWwgqX1VR2uW53kEKZBbvsbbqiQak+rlOyDozrBB3G+dc/jF6R8S
         FWJ0x0UAUxYZh5rT6M53WmZ+3to5BbCWwgHFgKDXtrbWPEcDlfCH02J38DAcHyGQzz7E
         a+Nt//+n+/CyNUOy18LPKEBQRPMPHdwNBaK7nWBPvyC/SIa5A/CSRlZSOfE6kcIBgJy8
         rEFDRyNyCKdRg4tzHcCVwjIPkwAt56vHjWJS2qiTO1lmBGs/ZeHTufwDKrx+V0/rJJru
         +pOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=OYu5UJio;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::92e as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x92e.google.com (mail-ua1-x92e.google.com. [2607:f8b0:4864:20::92e])
        by gmr-mx.google.com with ESMTPS id 79-20020a370752000000b0069f92e9a004si452549qkh.3.2022.04.28.14.56.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Apr 2022 14:56:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::92e as permitted sender) client-ip=2607:f8b0:4864:20::92e;
Received: by mail-ua1-x92e.google.com with SMTP id 63so2252320uaw.10
        for <kasan-dev@googlegroups.com>; Thu, 28 Apr 2022 14:56:02 -0700 (PDT)
X-Received: by 2002:ab0:7308:0:b0:35f:acfb:c011 with SMTP id
 v8-20020ab07308000000b0035facfbc011mr10636031uao.51.1651182962546; Thu, 28
 Apr 2022 14:56:02 -0700 (PDT)
MIME-Version: 1.0
References: <20220427195820.1716975-1-pcc@google.com> <20220427195820.1716975-2-pcc@google.com>
 <20220427132738.fdca02736b5d067c92185c5b@linux-foundation.org>
In-Reply-To: <20220427132738.fdca02736b5d067c92185c5b@linux-foundation.org>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 28 Apr 2022 14:55:51 -0700
Message-ID: <CAMn1gO4sdaqZDoa0CErkTOaP=z2Y_ZitPck9opdXNbexdLaVOg@mail.gmail.com>
Subject: Re: [PATCH v5 2/2] mm: make minimum slab alignment a runtime property
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Pekka Enberg <penberg@kernel.org>, roman.gushchin@linux.dev, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, David Rientjes <rientjes@google.com>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Eric Biederman <ebiederm@xmission.com>, 
	Kees Cook <keescook@chromium.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=OYu5UJio;       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::92e as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

On Wed, Apr 27, 2022 at 1:27 PM Andrew Morton <akpm@linux-foundation.org> wrote:
>
> On Wed, 27 Apr 2022 12:58:20 -0700 Peter Collingbourne <pcc@google.com> wrote:
>
> > When CONFIG_KASAN_HW_TAGS is enabled we currently increase the minimum
> > slab alignment to 16. This happens even if MTE is not supported in
> > hardware or disabled via kasan=off, which creates an unnecessary
> > memory overhead in those cases. Eliminate this overhead by making
> > the minimum slab alignment a runtime property and only aligning to
> > 16 if KASAN is enabled at runtime.
> >
> > On a DragonBoard 845c (non-MTE hardware) with a kernel built with
> > CONFIG_KASAN_HW_TAGS, waiting for quiescence after a full Android
> > boot I see the following Slab measurements in /proc/meminfo (median
> > of 3 reboots):
> >
> > ...
> >
> > --- a/mm/slab.c
> > +++ b/mm/slab.c
> > @@ -3009,10 +3009,9 @@ static void *cache_alloc_debugcheck_after(struct kmem_cache *cachep,
> >       objp += obj_offset(cachep);
> >       if (cachep->ctor && cachep->flags & SLAB_POISON)
> >               cachep->ctor(objp);
> > -     if (ARCH_SLAB_MINALIGN &&
> > -         ((unsigned long)objp & (ARCH_SLAB_MINALIGN-1))) {
> > -             pr_err("0x%px: not aligned to ARCH_SLAB_MINALIGN=%d\n",
> > -                    objp, (int)ARCH_SLAB_MINALIGN);
> > +     if ((unsigned long)objp & (arch_slab_minalign() - 1)) {
> > +             pr_err("0x%px: not aligned to arch_slab_minalign()=%d\n", objp,
> > +                    (int)arch_slab_minalign());
>
> printf/printk know about size_t.  Use %zu, no cast needed.  But...
>
> >       }
> >       return objp;
> >  }
> > diff --git a/mm/slab_common.c b/mm/slab_common.c
> > index 2b3206a2c3b5..33cc49810a54 100644
> > --- a/mm/slab_common.c
> > +++ b/mm/slab_common.c
> > @@ -154,8 +154,7 @@ static unsigned int calculate_alignment(slab_flags_t flags,
> >               align = max(align, ralign);
> >       }
> >
> > -     if (align < ARCH_SLAB_MINALIGN)
> > -             align = ARCH_SLAB_MINALIGN;
> > +     align = max_t(size_t, align, arch_slab_minalign());
>
> max_t/min_t are nature's way of telling us "you screwed up the types".
>
> So what type _is_ slab alignment?  size_t seems sensible, but the code
> prefers unsigned int.  So how about we stick with that?
>
>
> This compiles.  Still some max_t's in slob.c because I was too lazy to
> go fix the type of ARCH_KMALLOC_MINALIGN.
>
> Shrug, I don't know if we can be bothered.   You decide :)

Hi Andrew,

No strong opinions here. I'm happy with the fixup that you added to
your tree on top of my patch.

Peter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMn1gO4sdaqZDoa0CErkTOaP%3Dz2Y_ZitPck9opdXNbexdLaVOg%40mail.gmail.com.
