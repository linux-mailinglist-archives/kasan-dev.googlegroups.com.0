Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE7K5X5AKGQE2OINY7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id B27D8265FF6
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Sep 2020 15:01:08 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id o13sf6530428qtl.6
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Sep 2020 06:01:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599829267; cv=pass;
        d=google.com; s=arc-20160816;
        b=XmDBN/Li/cFZSgebfGWKe1V0gNBVn5mce5Sp1KgRfYM6sf7U5MsuP/YDhq5TZey9BV
         0LNPaCND7Xp6H1l4kb/6a2lKDPhRCmtVqXZwV+E8yuWNfUavzGaxx7j03nZ2oV+VKaPE
         +GJK87UDK8U7FYtUk7Lfu/hJY2giSUj43Y/lrMvdBvOzAM/+fQVBawctdi5xlkbpzAAz
         LyE8B31AiOPElTBh0TIeym5K8ngGXaRay6qL7PN1T5dz4RIOvYOM61rgME2/YP4QdLob
         +noktcmTwGiR7FKFaOGn2L1tTaaKzLTgbdXC0hbPJN8HXx+7eaNGDuf8oSIJs9Osv4Fn
         8D1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=sTETq+PpJWvdNbegLnt3pxdLyd0Fx5zFk+kiZeQhH6Q=;
        b=vB6NN5QdcGmaS1TTTARvj6ATR4mhTUgrJ9cJOcuF4KPb5Cvv1wStq8y+ME7b1WP8JN
         f4UsXLAN500SHr4fGmv7Ivw+9vXA6cvF8mDvINDcaP604PibV10tidT+nr7yFpD8LhsG
         PmwmHjW5baCmXy7FKbDEVUqzoktSfpWY/zikcUvL3CTyr14WzK5BMBNG7ygM+HS1sbbp
         lGrLbCWzigVcLYZfhfl3t6zi2NxAdjOi+svYS9SMAymf3OzR+RX6ZzGjmHb1/fm8fbSg
         41B+8voi80EsPpRnHUCH4JVCAkHCk65J7ma06pO0hpHWn/htDfnXE4LcIvzV1xtMYZg7
         PnGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=T96RFKKM;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sTETq+PpJWvdNbegLnt3pxdLyd0Fx5zFk+kiZeQhH6Q=;
        b=SPwhKfBjGVA3J4NL1JwGC+PZ3PY9+jQvwoYwHr0MSErgHioM28AoDDcMnYwmmovxPL
         cu8wCFO974WZEm9Rw610HctTMg48RuzQjyQu85WO55qu+BaWfACt46JCfnb896LChzG0
         cGOhcuyNmEyARohNLRJrIzgGjXB9NlphnHsAQTJE/jceoC9UkDx997H4aN0dOOmisTWe
         RcDGPsqZ6U3qt5fOKV3Mvtsb0ZusVLOFT21mJDkaBDeAKfnm7EGJHba0bkbLaVv0xNez
         gxrGIaXSYDFG7P+poN5H6sueukqUsBq7SYYstxJ/3Nn4t+CxsP8mYlpn3EjjaCeKjO/o
         pMZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sTETq+PpJWvdNbegLnt3pxdLyd0Fx5zFk+kiZeQhH6Q=;
        b=L/WUVnLcbOnbG6gH3qMHk+61nbysX9AKGXiAhUHzvbKt3c5/HVNPMDblh1GSvAg1Hd
         1uzfaD+l1Nq9XKon5u2Sm5y6sLTM5QkbsqKPePGrw3dbk9DY/YLRYaRO2a29PLHQZFSH
         o7l+ommCEjenJkPw0rcQ6EsfPjP3y3IAuDSZOK19qbc7ZDrgbaonnoTXZ/S2Yym8Izn9
         Va7Acrd1C1wDyhTgg5Po6iIf8EjmZ1DCjGJwrhJos59/6kVeJBc6tboiv91atguqhoiF
         XvUBqSFiZhD9hYvDO+ahoyJjljebSZwVRZS3S9kz2m+N02vKkvRZTkTG0w0EHh92qIqJ
         HxXA==
X-Gm-Message-State: AOAM531Zns616JdM9BDreSTRRmAa3CPqcJErIXURaB70iJ7nNEDxo0Mw
	37zEzPAAeJfmWjFvSsEe7EE=
X-Google-Smtp-Source: ABdhPJz+GG75xDHP7et6voQRtu6zt1c55hkiGYukCBhzGaKqdNSeWcO3VfVzgRJoaJxPcKlls/1iTg==
X-Received: by 2002:ac8:f23:: with SMTP id e32mr1746124qtk.168.1599829267519;
        Fri, 11 Sep 2020 06:01:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:f50b:: with SMTP id l11ls975231qkk.6.gmail; Fri, 11 Sep
 2020 06:01:07 -0700 (PDT)
X-Received: by 2002:a37:7286:: with SMTP id n128mr1330850qkc.423.1599829266902;
        Fri, 11 Sep 2020 06:01:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599829266; cv=none;
        d=google.com; s=arc-20160816;
        b=K54ivlnleqj+vEGeKSNKIdhbYq6F50WOcVUSgbICj4jl5ZmGyLm7LxY+645Hr+VNT1
         4GN+L/PmXy9vDKhNS0kaXIOV0riljKUsyXEU/7+vrsvIB1Xt1u4cjVI74srhaFFzeE+1
         0kbc1MlhoyHqnnrLBXdoKnCEbuylmXKIMLcx61v5RsJK3/biddK7tL+kcQg+ZQme0fS4
         Cmwpb6k78pQQeLVlmqbo7BVhA7VrbxybMd/j8iwqUzjWJReWrEgv7cZcXw7rM4A1Roou
         LLxP+6tbiKaxdZB0Po2iK2K+b0k9nKnLRWFgx4TdglWIdZqyyTm7iRBtBOWQ7Vm6m1g3
         +7jw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ge/FjJXhyj8+NsSSsvCMLGtUiAk37fA1+cTelebZ4Go=;
        b=b1EmhWQqirLjEAV0CWs9FrCF1x9C0Y2sC2Lw4403t92JuFurMvIMVld+3LsjbbhqfD
         7wyUpK8ANAR6zUYen5FlUwkV+5E9IiZUsB2s3wx0wn3eaqZzZ7X36XLQapl7rypODegd
         V0RgSJUXsk/XRcpjdE6NHRR3MUvaVu8zecnXiLTi3vxbondAO+TO55j3fhT8JsPlxBQr
         QgIBeZ13+cFL9SQX1wh7Jp94yBL+T+fYX1fjsIL6Ot5OlBQLEUv6s2HlXVChd/12QSiP
         V6iD21268t3dWk6oRhwOmWLBhMJkTCYtwQhZkvaiQgTbu2FSBwn5uu4ERZ5lTIjg3Ir0
         Cxfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=T96RFKKM;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id x13si128693qtp.0.2020.09.11.06.01.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Sep 2020 06:01:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id u25so8250278otq.6
        for <kasan-dev@googlegroups.com>; Fri, 11 Sep 2020 06:01:06 -0700 (PDT)
X-Received: by 2002:a9d:758b:: with SMTP id s11mr1038835otk.251.1599829266141;
 Fri, 11 Sep 2020 06:01:06 -0700 (PDT)
MIME-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com> <20200907134055.2878499-7-elver@google.com>
 <CACT4Y+b=Ph-fD_K5F_TNMp_dTNjD7GXGT=OXogrKc_HwH+HHwQ@mail.gmail.com>
In-Reply-To: <CACT4Y+b=Ph-fD_K5F_TNMp_dTNjD7GXGT=OXogrKc_HwH+HHwQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 11 Sep 2020 15:00:54 +0200
Message-ID: <CANpmjNMHHWjdLiWi+vhffcWq=UNFVGV7so6AggezcvnoOFHvKA@mail.gmail.com>
Subject: Re: [PATCH RFC 06/10] kfence, kasan: make KFENCE compatible with KASAN
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
 header.i=@google.com header.s=20161025 header.b=T96RFKKM;       spf=pass
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

On Fri, 11 Sep 2020 at 09:05, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Mon, Sep 7, 2020 at 3:41 PM Marco Elver <elver@google.com> wrote:
> >
> > From: Alexander Potapenko <glider@google.com>
> >
> > We make KFENCE compatible with KASAN for testing KFENCE itself. In
> > particular, KASAN helps to catch any potential corruptions to KFENCE
> > state, or other corruptions that may be a result of freepointer
> > corruptions in the main allocators.
> >
> > To indicate that the combination of the two is generally discouraged,
> > CONFIG_EXPERT=y should be set. It also gives us the nice property that
> > KFENCE will be build-tested by allyesconfig builds.
> >
> > Co-developed-by: Marco Elver <elver@google.com>
> > Signed-off-by: Marco Elver <elver@google.com>
> > Signed-off-by: Alexander Potapenko <glider@google.com>
> > ---
> >  lib/Kconfig.kfence | 2 +-
> >  mm/kasan/common.c  | 7 +++++++
> >  2 files changed, 8 insertions(+), 1 deletion(-)
> >
> > diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
> > index 7ac91162edb0..b080e49e15d4 100644
> > --- a/lib/Kconfig.kfence
> > +++ b/lib/Kconfig.kfence
> > @@ -10,7 +10,7 @@ config HAVE_ARCH_KFENCE_STATIC_POOL
> >
> >  menuconfig KFENCE
> >         bool "KFENCE: low-overhead sampling-based memory safety error detector"
> > -       depends on HAVE_ARCH_KFENCE && !KASAN && (SLAB || SLUB)
> > +       depends on HAVE_ARCH_KFENCE && (!KASAN || EXPERT) && (SLAB || SLUB)
> >         depends on JUMP_LABEL # To ensure performance, require jump labels
> >         select STACKTRACE
> >         help
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 950fd372a07e..f5c49f0fdeff 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -18,6 +18,7 @@
> >  #include <linux/init.h>
> >  #include <linux/kasan.h>
> >  #include <linux/kernel.h>
> > +#include <linux/kfence.h>
> >  #include <linux/kmemleak.h>
> >  #include <linux/linkage.h>
> >  #include <linux/memblock.h>
> > @@ -396,6 +397,9 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
> >         tagged_object = object;
> >         object = reset_tag(object);
> >
> > +       if (is_kfence_address(object))
> > +               return false;
>
> Is this needed?
> At least in the slab patch I see that we do :
>
> if (kfence_free(objp)) {
>   kmemleak_free_recursive(objp, cachep->flags);
>   return;
> }
>
> before:
>
> /* Put the object into the quarantine, don't touch it for now. */ /*
> Put the object into the quarantine, don't touch it for now. */
> if (kasan_slab_free(cachep, objp, _RET_IP_)) if
> (kasan_slab_free(cachep, objp, _RET_IP_))
>   return; return;
>
>
> If it's not supposed to be triggered, it can make sense to replace
> with BUG/WARN.

It is required for SLUB. For SLAB, it seems it might not be necessary.
Making the check in kasan/common.c conditional on the allocator seems
ugly, so I propose we keep it there.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMHHWjdLiWi%2BvhffcWq%3DUNFVGV7so6AggezcvnoOFHvKA%40mail.gmail.com.
