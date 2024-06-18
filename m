Return-Path: <kasan-dev+bncBCCMH5WKTMGRBTGEY2ZQMGQEYXFOQRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E56490D685
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 17:05:50 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-25443e5e1basf6999460fac.3
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 08:05:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718723148; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZBSKwzsvmHybgwPDoQlueMD/khA6fuk5HKCG6CVFrwEkIWcyg2zZFDl48tsH50Zqty
         sQfRmkGsnJUacqJ0J33cKQTOdiBrtD8u5PVsXTrp/5fjhEWaDlP9ZdoOSGOwi34CCjv4
         kUUgKjcwCt493a2UVhpR1kt/dFfyF8gSJEX2/1w+w4BWu941WmEMB+5wDWmHCDqcj9VM
         neHyGaUmml+4JA5J0FSc5zI+T8sj3DZ+4XcC8YLPgy1HiuRJ0Nxb2dAX3ZL2nBc+jV9i
         l1cFCQoJdAe8/hfxCeLNQFPqTACC2hipPag40ZI2MgYD4KCwy9vF0iJGTVgfOjDFdXWF
         FT1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nXiLHUWXZTjmj3gKe52U4NCQOFXVD+YfU69/N27QjlA=;
        fh=sRPXM+wF386PJ92L5t+V6t+uRFdfgFjQit/moVorbN8=;
        b=mhArTNXT9MskmTHuqLV953G/aP5p1l95EjYevDi9NLhV+lnzFu3jFebykklmTp1dMC
         raIcVjmm72OdfzGBQEAKix2uIyT1t6CqIWkcO39cqAZsK/We2llJWGh0SDvTeSYRm4GO
         +5ULR/lPq1ODxT+uNwINqYcoDB0/WZBTM0FVGhPP/5R7XEQhzVXt4U1jXwIFxbJ03P0Z
         U0uVB8Wo72cTvNt+cwyhe+9vkiMtOmMvn5Z0D8sC/Nb5GX8tHSEZVGmcYX4fdsYc9nGK
         C8tleOQf8oap+mFd8fV9hHm5ONxpwejgBlbllcUOY4AJCWFW/uxpJo9DYirUJE/y3E0a
         lnXA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FxDHvCNz;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718723148; x=1719327948; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nXiLHUWXZTjmj3gKe52U4NCQOFXVD+YfU69/N27QjlA=;
        b=rIK5l6sEDWOa8e4pB5Qf/PGYz4l1eo8ZvgNhfk+z5HA5cKoV0fV6sXmuXnmIKBHOM6
         J7rTnMayFdCN1Q/ccpMJ27C6pBkXD7Jvwy03kf9Ti4Y2Bpw7IxvJQo0MsoNcjhYipVaT
         PRTkzRTDtOBxTsqwJnU+voR/vuk1CLRUEOSJYohbcdeX4ndZKC1CEdHbJibSCBXUDN+d
         8JgvEDY519axNalWFfkI0n/Ovb6ZqbqKVDABMTqfn4KgYmcam9gmXdJXdDKLHBUvK1A7
         tZVOuN8n4NQ8xTqpSxNhmaFBN2O0ma/yNLt9PIzcm5ei11L7W79/RuSh7aHmetYPQO/O
         ponw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718723148; x=1719327948;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=nXiLHUWXZTjmj3gKe52U4NCQOFXVD+YfU69/N27QjlA=;
        b=InUmKSfMKlTWD91Q7In3BnCo0IJI8dvuJjLOdx0OEuxkvhKjxPoCfxhRdHv4l1xJQG
         A++K6nocC9Nw7yHk4GulSqGgMGYcPrN0A8+vq1golIYsDspwOVPNKcVI5YLKlXoUJHl8
         0XCHtyfZ2bQCShlJTcUcvn1iFl4qgphFT6F9656Nq+NCwq9hu2XUNgmXW+jR67Hh865D
         zj5LcR2ZUVoUD9kURxvXk4OARQ9ykdbprbgrWVWVAzNvyNdoP3bcHc8kfJtXRQaVZtU1
         jptF7GkUvEeaD0pg3bhI7EDwBcEWBYlepvQ8sXMEtUcFxUJwN9dbzlQtjh18Hoklu/tU
         S5VQ==
X-Forwarded-Encrypted: i=2; AJvYcCXjxaDW9btMllDnTXuSp3O8IH/V9RTcQp3Apk8K0YOYD0usycG0lUk6wxi18k5gh8jtKIW1im+wttJU0FWWI4MvSCLGnvDFyQ==
X-Gm-Message-State: AOJu0YxZBj0c6EBaTwpHN5+Fx0s1Afk82gbs0ZIDVk0ahtDJK7BSIaA2
	K+ni/xHNUJ7RUmmmA9Oer9VTpCAPliCDTDNaz4D8YcY6iyKrIUdh
X-Google-Smtp-Source: AGHT+IFTQlu3HtE7dJ8JVZiQC6+yzJ5CSvEfo/Uq48Qmz7JtxYKUWGSRausPy12GdMGOUEBAuyHV4A==
X-Received: by 2002:a05:6870:1714:b0:259:80dc:13e4 with SMTP id 586e51a60fabf-25c949c028bmr30226fac.10.1718723148443;
        Tue, 18 Jun 2024 08:05:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:c6a3:b0:24f:fada:1780 with SMTP id
 586e51a60fabf-2552bbe8b60ls619322fac.1.-pod-prod-08-us; Tue, 18 Jun 2024
 08:05:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV/QfcfwtA5HuTUjsBAetDrZRPVAONo8HMchqszYd2oBv4exO9Hu+tWIXFHB5qN5xeuo78rc7pA2BUPPGQyuBa3WosjIMUucQMdiw==
X-Received: by 2002:a05:6808:21a3:b0:3d2:244e:711c with SMTP id 5614622812f47-3d51bb02cccmr42410b6e.55.1718723147597;
        Tue, 18 Jun 2024 08:05:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718723147; cv=none;
        d=google.com; s=arc-20160816;
        b=Ck/QWMAc+QxHZ14QzpfKFw8my+ECyFYOL0uiaz0rVLFe8i9ZNd2jvVUy/JsWbL0NYy
         AeE+HPkRTgpfI1M1SRuaitTWnx2RNtru6BWOtr9Ogiw9PD7NxxV35pXwqnu/J0ptkYnw
         ta8pUZrgdUXs47Li5vBkjVRrL8zQ01WCcjW/oULs+bRur49Bbo512oUZBkiPJNDuvZqr
         gamJv4oa9ij2B57QsXTI9paqyjmvsFbWNSN+j//mUP9Sw1XMp9BIv9rS3QJXVpxzUacf
         h1mOtgIps20t5Ewz0QhZF5PywwZFRN8ZxF4u92bUzbyhQp7m+2vEwc6UivQY/DewfYOt
         y9fw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=fy3M/AH6/xybCaot3WBwIJpFavAawHNjcL6fl3GGJgo=;
        fh=fZNsBd6e6qYHhRzLc8hXhxCZLdyKt/ZBh+c2HR/vag0=;
        b=RVrUaGXMYnCCe3H9RK7V702uu3Mtby+b64/ubv2mjXWjUE0Nlufz1FX+VCpwMwX27Y
         4c9EtJ9a2JckCj2sIIyCR46AzpCqCwD6b4DSEqRU/ORHS9E7L6Vuctge6goAF3wWj3up
         E/6SWgqnNDriueHaCW5Mv2y+6izdo/KRNXUBKl7Eklrg1hrgIbZEtHAH7dQv0sDbWPEZ
         nm2lljaXoVZDXCb3Zk/8CS0Opj5LGMAv8obA8pXRhXFYKras0jvpnJQihB8hYGuQo4jG
         IZcyt18ChfXNLQ61qpe7Z2vb5PJdnJrY7OxNP9I7ZmHtrPE0xdnUo7NbXT1dVTNJ8Zl6
         C8jQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FxDHvCNz;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2b.google.com (mail-qv1-xf2b.google.com. [2607:f8b0:4864:20::f2b])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3d2479698b2si496195b6e.1.2024.06.18.08.05.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Jun 2024 08:05:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) client-ip=2607:f8b0:4864:20::f2b;
Received: by mail-qv1-xf2b.google.com with SMTP id 6a1803df08f44-6b05c9db85fso28073386d6.2
        for <kasan-dev@googlegroups.com>; Tue, 18 Jun 2024 08:05:47 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXma9PelS02TBE17ffHMqw4aM8S6zqkXjcZAE+ywk5OFvv22zoxtr3P4L11nsIQUHVvz17XkUhYmJcBBus1VJCtx3hpmcY3jNf6hg==
X-Received: by 2002:a0c:df02:0:b0:6b5:61:53a9 with SMTP id 6a1803df08f44-6b50061578fmr5936766d6.28.1718723146610;
 Tue, 18 Jun 2024 08:05:46 -0700 (PDT)
MIME-Version: 1.0
References: <20240613233044.117000-1-sj@kernel.org> <5a8a3c85760c19be66965630418e09a820f79277.camel@linux.ibm.com>
In-Reply-To: <5a8a3c85760c19be66965630418e09a820f79277.camel@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 18 Jun 2024 17:05:10 +0200
Message-ID: <CAG_fn=VoCfRAKqesutB6eP2Qi0aG8Tyq4zqoiy0_A3MJDQAEfw@mail.gmail.com>
Subject: Re: [PATCH v4 12/35] kmsan: Support SLAB_POISON
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: SeongJae Park <sj@kernel.org>, Alexander Gordeev <agordeev@linux.ibm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=FxDHvCNz;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Fri, Jun 14, 2024 at 1:44=E2=80=AFAM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> On Thu, 2024-06-13 at 16:30 -0700, SeongJae Park wrote:
> > Hi Ilya,
> >
> > On Thu, 13 Jun 2024 17:34:14 +0200 Ilya Leoshkevich
> > <iii@linux.ibm.com> wrote:
> >
> > > Avoid false KMSAN negatives with SLUB_DEBUG by allowing
> > > kmsan_slab_free() to poison the freed memory, and by preventing
> > > init_object() from unpoisoning new allocations by using __memset().
> > >
> > > There are two alternatives to this approach. First, init_object()
> > > can be marked with __no_sanitize_memory. This annotation should be
> > > used
> > > with great care, because it drops all instrumentation from the
> > > function, and any shadow writes will be lost. Even though this is
> > > not a
> > > concern with the current init_object() implementation, this may
> > > change
> > > in the future.
> > >
> > > Second, kmsan_poison_memory() calls may be added after memset()
> > > calls.
> > > The downside is that init_object() is called from
> > > free_debug_processing(), in which case poisoning will erase the
> > > distinction between simply uninitialized memory and UAF.
> > >
> > > Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> > > ---
> > >  mm/kmsan/hooks.c |  2 +-
> > >  mm/slub.c        | 13 +++++++++----
> > >  2 files changed, 10 insertions(+), 5 deletions(-)
> > >
> > [...]
> > > --- a/mm/slub.c
> > > +++ b/mm/slub.c
> > > @@ -1139,7 +1139,12 @@ static void init_object(struct kmem_cache
> > > *s, void *object, u8 val)
> > >     unsigned int poison_size =3D s->object_size;
> > >
> > >     if (s->flags & SLAB_RED_ZONE) {
> > > -           memset(p - s->red_left_pad, val, s->red_left_pad);
> > > +           /*
> > > +            * Use __memset() here and below in order to avoid
> > > overwriting
> > > +            * the KMSAN shadow. Keeping the shadow makes it
> > > possible to
> > > +            * distinguish uninit-value from use-after-free.
> > > +            */
> > > +           __memset(p - s->red_left_pad, val, s-
> > > >red_left_pad);
> >
> > I found my build test[1] fails with below error on latest mm-unstable
> > branch.
> > 'git bisect' points me this patch.
> >
> >       CC      mm/slub.o
> >     /mm/slub.c: In function 'init_object':
> >     /mm/slub.c:1147:17: error: implicit declaration of function
> > '__memset'; did you mean 'memset'? [-Werror=3Dimplicit-function-
> > declaration]
> >      1147 |                 __memset(p - s->red_left_pad, val, s-
> > >red_left_pad);
> >           |                 ^~~~~~~~
> >           |                 memset
> >     cc1: some warnings being treated as errors
> >
> > I haven't looked in deep, but reporting first.  Do you have any idea?
> >
> > [1]
> > https://github.com/awslabs/damon-tests/blob/next/corr/tests/build_m68k.=
sh
> >
> >
> > Thanks,
> > SJ
> >
> > [...]
>
> Thanks for the report.
>
> Apparently not all architectures have __memset(). We should probably go
> back to memset_no_sanitize_memory() [1], but this time mark it with
> noinline __maybe_unused __no_sanitize_memory, like it's done in, e.g.,
> 32/35.
>
> Alexander, what do you think?

We could probably go without __no_sanitize_memory assuming that
platforms supporting KMSAN always have __memset():

  #if defined(CONFIG_KMSAN)
  static inline void *memset_no_sanitize_memory(void *s, int c, size_t n)
  {
          return __memset(s, c, n);
  }
  #else
  static inline void *memset_no_sanitize_memory(void *s, int c, size_t n)
  {
          return memset(s, c, n);
  }
  #endif

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVoCfRAKqesutB6eP2Qi0aG8Tyq4zqoiy0_A3MJDQAEfw%40mail.gmai=
l.com.
