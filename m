Return-Path: <kasan-dev+bncBC7OD3FKWUERBY4AWWXAMGQEDVZWN3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id EF3E7855604
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 23:36:20 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-68058b0112csf3871726d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 14:36:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707950180; cv=pass;
        d=google.com; s=arc-20160816;
        b=w58C4dRXvkSn/VgazAtIO50bbg6c9+SHS4owa+1TJkGLxN8Jmb9ESm3ybqTk6jnnD/
         w+dwAtFRzOgryFNLz1Q18ev/3BVai/6lJ2yc6XVm2UrFPQKeFgSg6/avA25ju5DFivy7
         tjuggxsaX7lOgYsVhKfkadNDQOt71iZ8/0yc16xJiuT8OabjlBDpNdCEvBJG7uFqfPJg
         16tfVLI+vb1Mk7YlTPxFXlT93CJzH6QfJp0qK2kNIFwYB0CsZ3r/9UNzjQLcpRzrFQrU
         XZtrAJVgEQdHL9csjk5rykEfIOpcDLOVZdA2nIXKOYnkLaBQa9mgAryneWnVORHedT2k
         PFDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5VogrLN9Nn0IbdnJuFzetwWl+BHNDB4FAXkIxlC/2OM=;
        fh=CfdC0p4r+gQb93LDQAKpDW3AJLhVsG+raOQ0iuSwnAY=;
        b=p5jE/z+FbXfRT59/YNw8dq89IwZnpZeg5fNYqak509uS3MzJd8qXCyI0kRZ7s08sUy
         r3qKnJnsR1Hyk/dtawWqzJXYpdDGleckoIRB0aS8aF9IrDn/0rA3b+L1lT4JL0ma1tjl
         v3YyM1LnrF8pMPWokx7OfES0sKW6oRWsswKXIX938Iu5u+uIAEh5WVmTw9HPT8U6S0hr
         i6bHmKBH0rL9Lpa2qMQXf0EehN8BXTvReCYfas3A/f2AvYf4t764+sxsmsEm/LlCjPjZ
         qKAF1dL+6aKJy5Umf6yuW8K7wjaD45e2Kt2q3Vnps6p8XZMOG6Tner8hsjhRNg0znR5g
         OlVg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=b1PWwgX0;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707950180; x=1708554980; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5VogrLN9Nn0IbdnJuFzetwWl+BHNDB4FAXkIxlC/2OM=;
        b=OzmB7jt+he1pXKjaVUQX21h22oBrBlp1p62W1XdtP6TUWgYK4HLVXuZTuNABggZFdd
         HGHCfYUKJw4S/xt/uB+KT3UH/Rh6RUSVPBE/4hHKHLmz93d+m3BysC1njupL0HhPe8g0
         fX2Yx3iqcOY3dhSq3A/syeXHFBGodnwSVe7LKs6Je2FBx1ZPpf21EcrDVKmsVHw8F5+O
         a5dkdmz+JN6w6EnnvyXVPpDF1okO7CH5fWtAk/MyZdcz8QzhS+FCZzwgzuPYN1n/Fn7u
         jZTu35i+K9WSTzB7FTg/UHuTGYPPN3qwMVWTDsAnr13T6ssDryVZkl2sWI8BgFz8k4a7
         qdkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707950180; x=1708554980;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=5VogrLN9Nn0IbdnJuFzetwWl+BHNDB4FAXkIxlC/2OM=;
        b=g7beduFVQy+f+EzMDAwBfYv2EMx0LTC4ziDQbtw5VC4MWcf5s99PwEnQkimmkg6ZEO
         g3PlQhrU5aZFar50l/1pduxbCFFpH8OIWUaBr6YYv9fTqF8Gp9BDjkKPvG+pOO6qzdGU
         1oSiO55kVnf6yDFMC4P6q59K6SKGgVW8+ZOzMo9Vyj8oDy0x7gSnLnWTRRBmWXjvrry4
         KZQcrcNiTzmjOdwGPAa/XxO9ThAWjstoYYPjtcZkuaGtms2TkXKIkoU2wGAfL3IoOMzf
         d/XUmcUw2L9YkEafoLGuVzD+hKr5kUVutuhqvhIhgngkLb1BiP9dd9KeOvgTb4H59cqq
         s1gg==
X-Forwarded-Encrypted: i=2; AJvYcCUMcIJII9gD2xWmK5VmyXEJkFWSdg7GX3tguAM3q968mMTQawaWfUR4ga4iP/Z+jVTieqZ0zQjxOASHVXGvJRWgLENSSZanYQ==
X-Gm-Message-State: AOJu0YwOKCypWr3J29no90jHvArE/5N7cTGfbPPEjI2U+T9s2/7JL+vr
	epfBPTOTZHQMGaPZREH3/p21KW9rTF4uvx0Wq0Iigr25Lyy+yorX
X-Google-Smtp-Source: AGHT+IFTTNn8CIJHz8ZsdZ/IyTdrbzDyyKRGPFFh+NAj1ubdoKFMjOMOiQRhr1tgd0JpdGVrsXzYcQ==
X-Received: by 2002:a0c:f50d:0:b0:68e:faa6:6b57 with SMTP id j13-20020a0cf50d000000b0068efaa66b57mr23018qvm.24.1707950179867;
        Wed, 14 Feb 2024 14:36:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4eef:0:b0:68e:eeaa:8248 with SMTP id dv15-20020ad44eef000000b0068eeeaa8248ls2800872qvb.2.-pod-prod-06-us;
 Wed, 14 Feb 2024 14:36:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVW+7BDOuZnWKj1HCL4toa68hxuqel7ZcU5FWYFYF0BUO+MaV3UaWwH8UWHViBn283zvz+QpPg00jd1ixXs6yPI90YLmNFJJ9iVqw==
X-Received: by 2002:a1f:d506:0:b0:4c0:7753:9a57 with SMTP id m6-20020a1fd506000000b004c077539a57mr3907586vkg.1.1707950179146;
        Wed, 14 Feb 2024 14:36:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707950179; cv=none;
        d=google.com; s=arc-20160816;
        b=t/GrKsXXDPMpvZQ+IGp8j/AgXqIDMWAmFQktnXtiT49PJ7Ze/rfPplGukyVEtjUdON
         f3loiMqoEt4qDy2gH/j7EE+KquFksB2zciz//aOx3ZpfQX8ReUozBSFNJdZvhn5kk84a
         n+LBmrCqYFUfdVea63Oe/cQvbpmhKfA9V/aH92G07KZtAFTbVLryOzwHrSqj9Qyxemqj
         B6ufgBgnaPRGpX4PtuWO5Et6AYmSNuqCGjqjDquyyStO3XjZ/fxWUeIoTu07aNMJS+xd
         Q0PogIbKFdMf4SdWYSpyBb3zTXm0DzjUl+qVdgbavjJWp1uC/Wqh5T/ewhYHQKfOXyEW
         Qhqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=mIZ+3Vimc+Fu9uNEqwRF3MpLhrYbsxAAnrlrt3WNttw=;
        fh=JROHHoChu0LoB6PIkzog3V3NMUQbqqxXS01ObHRxEcc=;
        b=kdoanySKM4hAvUow2Z4rWX5sTaOoPloWlWj04n3ON3XtW5SAkojgebVECKDPfQ0dUG
         89bFJOvcYuE934eH2eqF1I50QDZcY13ETH6/ujbwdVZTt+2OKaOSY8sW5HTYZfXeDtG1
         TAAOMLQ5CliH7haXmiE+7dMXNfkmfSfFd6V7orgz2M/4Mw3JSFymRbvt4SfrULRFvgKm
         EUhgIdrr3nKxLQ+hocR8xEMtCsGaItw8iWTLkpoDf/xCqpCFil4YMSkGRe/9WGFyBAN4
         wQriOptBuOLTMKocNIZ5TmUFwyjGvRmxNxViqshV9CLlemiCeOWEakwbsP/bp9NY0roY
         /+wg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=b1PWwgX0;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2d.google.com (mail-yb1-xb2d.google.com. [2607:f8b0:4864:20::b2d])
        by gmr-mx.google.com with ESMTPS id az4-20020a0561220d0400b004b2e6e4330asi7301vkb.1.2024.02.14.14.36.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Feb 2024 14:36:19 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) client-ip=2607:f8b0:4864:20::b2d;
Received: by mail-yb1-xb2d.google.com with SMTP id 3f1490d57ef6-dcd94fb9e4dso173769276.2
        for <kasan-dev@googlegroups.com>; Wed, 14 Feb 2024 14:36:19 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVjrHNxkvL/HZnY2/Ko6kuFl9JT7mR2Sdc9CjKuEImTBh0/QPYw+4NcHYpuLaS7qm0krnQxyRcP3qFcRHJWm7B45gsY9HJJ3uw3eg==
X-Received: by 2002:a25:208:0:b0:dc6:9c4f:9e85 with SMTP id
 8-20020a250208000000b00dc69c4f9e85mr3483617ybc.49.1707950178324; Wed, 14 Feb
 2024 14:36:18 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-26-surenb@google.com>
 <Zc09KRo7nMlSGpG6@dread.disaster.area>
In-Reply-To: <Zc09KRo7nMlSGpG6@dread.disaster.area>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 14 Feb 2024 14:36:06 -0800
Message-ID: <CAJuCfpGPyf9VzohFi8HzvT0XsW4bd3EAnCAb6xxedfJGtzZbBA@mail.gmail.com>
Subject: Re: [PATCH v3 25/35] xfs: Memory allocation profiling fixups
To: Dave Chinner <david@fromorbit.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=b1PWwgX0;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2d as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Wed, Feb 14, 2024 at 2:22=E2=80=AFPM Dave Chinner <david@fromorbit.com> =
wrote:
>
> On Mon, Feb 12, 2024 at 01:39:11PM -0800, Suren Baghdasaryan wrote:
> > From: Kent Overstreet <kent.overstreet@linux.dev>
> >
> > This adds an alloc_hooks() wrapper around kmem_alloc(), so that we can
> > have allocations accounted to the proper callsite.
> >
> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > ---
> >  fs/xfs/kmem.c |  4 ++--
> >  fs/xfs/kmem.h | 10 ++++------
> >  2 files changed, 6 insertions(+), 8 deletions(-)
> >
> > diff --git a/fs/xfs/kmem.c b/fs/xfs/kmem.c
> > index c557a030acfe..9aa57a4e2478 100644
> > --- a/fs/xfs/kmem.c
> > +++ b/fs/xfs/kmem.c
> > @@ -8,7 +8,7 @@
> >  #include "xfs_trace.h"
> >
> >  void *
> > -kmem_alloc(size_t size, xfs_km_flags_t flags)
> > +kmem_alloc_noprof(size_t size, xfs_km_flags_t flags)
> >  {
> >       int     retries =3D 0;
> >       gfp_t   lflags =3D kmem_flags_convert(flags);
> > @@ -17,7 +17,7 @@ kmem_alloc(size_t size, xfs_km_flags_t flags)
> >       trace_kmem_alloc(size, flags, _RET_IP_);
> >
> >       do {
> > -             ptr =3D kmalloc(size, lflags);
> > +             ptr =3D kmalloc_noprof(size, lflags);
> >               if (ptr || (flags & KM_MAYFAIL))
> >                       return ptr;
> >               if (!(++retries % 100))
> > diff --git a/fs/xfs/kmem.h b/fs/xfs/kmem.h
> > index b987dc2c6851..c4cf1dc2a7af 100644
> > --- a/fs/xfs/kmem.h
> > +++ b/fs/xfs/kmem.h
> > @@ -6,6 +6,7 @@
> >  #ifndef __XFS_SUPPORT_KMEM_H__
> >  #define __XFS_SUPPORT_KMEM_H__
> >
> > +#include <linux/alloc_tag.h>
> >  #include <linux/slab.h>
> >  #include <linux/sched.h>
> >  #include <linux/mm.h>
> > @@ -56,18 +57,15 @@ kmem_flags_convert(xfs_km_flags_t flags)
> >       return lflags;
> >  }
> >
> > -extern void *kmem_alloc(size_t, xfs_km_flags_t);
> >  static inline void  kmem_free(const void *ptr)
> >  {
> >       kvfree(ptr);
> >  }
> >
> > +extern void *kmem_alloc_noprof(size_t, xfs_km_flags_t);
> > +#define kmem_alloc(...)                      alloc_hooks(kmem_alloc_no=
prof(__VA_ARGS__))
> >
> > -static inline void *
> > -kmem_zalloc(size_t size, xfs_km_flags_t flags)
> > -{
> > -     return kmem_alloc(size, flags | KM_ZERO);
> > -}
> > +#define kmem_zalloc(_size, _flags)   kmem_alloc((_size), (_flags) | KM=
_ZERO)
> >
> >  /*
> >   * Zone interfaces
> > --
> > 2.43.0.687.g38aa6559b0-goog
>
> These changes can be dropped - the fs/xfs/kmem.[ch] stuff is now
> gone in linux-xfs/for-next.

Thanks for the note. Will drop in the next submission.

>
> -Dave.
> --
> Dave Chinner
> david@fromorbit.com

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpGPyf9VzohFi8HzvT0XsW4bd3EAnCAb6xxedfJGtzZbBA%40mail.gmail.=
com.
