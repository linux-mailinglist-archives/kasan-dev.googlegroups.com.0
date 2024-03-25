Return-Path: <kasan-dev+bncBC7OD3FKWUERB4XWQ2YAMGQEMHDQJEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id D29AD88ACBC
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Mar 2024 18:59:16 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-3688077ae17sf18457585ab.3
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Mar 2024 10:59:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711389555; cv=pass;
        d=google.com; s=arc-20160816;
        b=GSTYk+e4ptr2ruJOT9473+GWi2iW7FwVDnf449N8F2mn++JHGXk4mbChIE3YehRP1x
         b+JbYp+PH0uyY/u2uJmTmtCuu5ScXVh5+ZOlFySr6qkZlxF2tKQjhzmqK+zg/OLd2k7o
         EGTmLsTyPPoxFpJfAlxSjqqJddLjNfb1t17N7pF9IF86ugRwxUkyBVBX7VEB1Drq7bcg
         EwFTrts4Gx8096gVx9ZMBUNoGiRde3Ocfddy9Hbc37039Jba9fjJ4P9pIIGtDYvYCVbL
         naK9gymaWsafHvqK7q9iZVQg0uY5B1tJw1fDfK8bRHO/Capbl8Pb+pfcNO4oIruZ10PW
         lnIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=muDf0g5debYBp8JkybJUPVco/k4z2q4ZCUhPOBw0w58=;
        fh=ofed7B05tWazegXyHqI5SRLdPh70kWbtfwsPtbk0j08=;
        b=eAtXlmM+usXo/10BIeBBSJknOWoSO+6zSZhWphSUB7hYhYezk6KSYKqUEGprD+vuPh
         DUjsGeqg1G6su84srv1eb3gRUEGC9ki+XhOb3geukuR4hioDtn3OlzG8IR0GrT84OKOV
         XHmfQvQZvQxRkNP62pOqZ+hMToGjMtfROFcvr83S2mRES1LB39b4scLD0TQ0vAne5aq6
         K1hQMXYBuqlKc0bnTuvTMZICzltpF1+PQnPfZJ0sRdk4znbL6oSmOBXI04ap3Nqo/6XY
         x1vjIJ1YfNaYIApMNUOOG7F1e2ZJ5MPo5OIjpsFuWkuaewDUv+hWUqWKJaVceDaL8MDX
         VFVQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=LN43J2Mm;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711389555; x=1711994355; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=muDf0g5debYBp8JkybJUPVco/k4z2q4ZCUhPOBw0w58=;
        b=mB5iCT3aMZwTvAoUoAJfk80QuMNwBmY/ouQ3499BKChKO7pX6E5wdJnJRs8iunQVMf
         Iu/u89RRbYS1NfYfncd8zgVNX0AdXmOZrPSgJCAgperuWE0yzlZhlW8/2PWw/fxtO43Q
         HMj4+eAh8PLOchfDVFq8yzsJ01uQ4TVD9PK0tL7cQcyNLCvy6s+2q+k0yPogkpmxj8az
         ZMZ2CQsWF2QJvWYrHOoJqJ4/8lvkF+WMhT77+3t6PT/d//IMLOYuFvZBYifUJBShc0fi
         ocSsTksn4qRgJX42parDugFjfBlJjiCZlFzxJDrc6QR8HaMe1fMbXzNTU3cPR77MGNHv
         jw/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711389555; x=1711994355;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=muDf0g5debYBp8JkybJUPVco/k4z2q4ZCUhPOBw0w58=;
        b=wuhaWXKCGb+fbU3gyQXvaCovc46VfNzUMIevGhrUBvvP6OIsnd0z5mfTyfGF4gq73G
         b9vFGJR3qQcI4a1L1YqWMdc8Ff03ngvIZYXB0vt6ptnbi0MhWbvax702REVvkGw/6nnc
         zxTIgIsjPTLNNb3KFuOws8phdotWWutEWMQOqSCsYhl9VYn+p6rtaxb6zQldirGTfpfb
         tw9zVZ1tsc92/GYf0fbYoOqCa9BJ7q2Be1LqRLBCid8MX1oAZ5P4GGSbmj7D/+4xg7Vr
         I+mgYIw7bQxGCFYtlCiRKBcc5ovC2+CSDdMaqB9b5eC8HkgXDKBLUYweLcK/0xuXqlcK
         ZtKg==
X-Forwarded-Encrypted: i=2; AJvYcCV7/6X9aKl5YIghUf6IYOxueTgWxYzNdT1wDklWHGv9uqzVvXMfraaeImO96kGax/2v+rO1rZ5CWirQfo4YpPVwxfK9rHr0rQ==
X-Gm-Message-State: AOJu0YzIfnlDYlfzzDTcDSnFF0VkyWX7KJPwTg+tKjJ7b2EHtoYeAwkE
	99L+Aqd+gldnlhYExCQLZKoHWJfjLY7JmUudq9VykhC69xuKdY8O
X-Google-Smtp-Source: AGHT+IEiy3cxPs7kHFLztgPI0QyJEMdBGMMbTHyq7/qejkkugtlfVmE+nZeFetDi66aztpNF4FEaJw==
X-Received: by 2002:a92:c142:0:b0:368:6eac:3520 with SMTP id b2-20020a92c142000000b003686eac3520mr8637866ilh.17.1711389555400;
        Mon, 25 Mar 2024 10:59:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3388:b0:368:9d0a:4c26 with SMTP id
 bn8-20020a056e02338800b003689d0a4c26ls79646ilb.1.-pod-prod-06-us; Mon, 25 Mar
 2024 10:59:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXG7P5wWkLvGRDdMrOwe5JgwdjDGT2tB2SXyadQ4kb1LNbRca6B6hkgjwl9GC89hNnqbmlPEr1U0no8esrSErwY1WjRd771KLaU0g==
X-Received: by 2002:a05:6e02:114f:b0:368:9ab5:6482 with SMTP id o15-20020a056e02114f00b003689ab56482mr1017471ill.13.1711389554118;
        Mon, 25 Mar 2024 10:59:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711389554; cv=none;
        d=google.com; s=arc-20160816;
        b=Shh6gqNS/grwd+LdfUbZPzYzkeozhg2DtFnrsPDWIwUnk8N2u040/R5yXC0HrSd9oz
         30ZK0zjNWuOo+da4y1kRjHH9cxaK0ckGGRcd32f+9MAHvgejuwp0G7XQ41wrcYXg++AP
         4D/HzMovdyVo7U/s5jyGixV0UVDRs79AG3Ak3TuuwoHVXdHNqtWjnb2oKpXza0xHg/20
         BQKM2vvsoDzLIsjKNDsL7WJ3+6vBmoouZR1xwrGZ5wl1hya00kL+V+mNqvE+1eayDCRl
         FggmXlO/D92svW+OrFHTXsXOk6Y2KryneWktUtX8zA9KU+kkAetxIwp8uuTZkROhigzY
         LQag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=g1H2/sqpi/sh2ma0fgAVRjfY65QgsbrlBKsllNKG2ck=;
        fh=ODD4ij610XVxigUXw+pMqSOdwWx+dch7OLXCXvfFJ6U=;
        b=I6+Il93gBWdFRj/ZFB8aL+s/m0HSMq9xXfUAL3KcgjezBngkFrg5jPm2n6tGljAhZg
         xG2kJkvR/yOMHcOpw9PTpI4gJTxSkBq9k2vuBFPVs/iYebTpHsEpD2HMgY+dh+XGVPbl
         ugKsGfpAcWmTa06+idkeJVP9rDiubMvazXJFVta2X/9s+QMokWmR8peQlcSa7eJwkhIv
         CFB1eJx/LlYpubU7h/xkFcW2K+SCKc0GmZbVQBw7ZNwUw5njal/lId5KDhK/hXXwjpJL
         8MgG0fDtXcP2hrjcwssTmMx0yyz7ojqD0DJ2Av4bGD7PcqFJQlB5/l89LxJ8uq9ILKL7
         wHuA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=LN43J2Mm;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb35.google.com (mail-yb1-xb35.google.com. [2607:f8b0:4864:20::b35])
        by gmr-mx.google.com with ESMTPS id x2-20020a056638010200b00476fb4f1fa4si558348jao.0.2024.03.25.10.59.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 25 Mar 2024 10:59:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) client-ip=2607:f8b0:4864:20::b35;
Received: by mail-yb1-xb35.google.com with SMTP id 3f1490d57ef6-dd10ebcd702so4730442276.2
        for <kasan-dev@googlegroups.com>; Mon, 25 Mar 2024 10:59:14 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWcEl4dyZRQkX2C/AVyvs3lgo5JTgaxoMEcEfa7ztadiHwRq40UHNWzmUUEpmxap9Rro9TXJUda07Hkf4ELuxnBmdAF3PVgy2/JbA==
X-Received: by 2002:a25:acd6:0:b0:dc7:4067:9f85 with SMTP id
 x22-20020a25acd6000000b00dc740679f85mr6265207ybd.58.1711389552854; Mon, 25
 Mar 2024 10:59:12 -0700 (PDT)
MIME-Version: 1.0
References: <CAJuCfpFnGmt8Q7ZT2Z+gvz=DkRzionXFZ0i5Y1B=UKF6LLqxXA@mail.gmail.com>
 <20240325174934.229745-1-sj@kernel.org>
In-Reply-To: <20240325174934.229745-1-sj@kernel.org>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 25 Mar 2024 10:59:01 -0700
Message-ID: <CAJuCfpGiuCnMFtViD0xsoaLVO_gJddBQ1NpL6TpnsfN8z5P6fA@mail.gmail.com>
Subject: Re: [PATCH v6 30/37] mm: vmalloc: Enable memory allocation profiling
To: SeongJae Park <sj@kernel.org>
Cc: mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org, 
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net, 
	willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=LN43J2Mm;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b35 as
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

On Mon, Mar 25, 2024 at 10:49=E2=80=AFAM SeongJae Park <sj@kernel.org> wrot=
e:
>
> On Mon, 25 Mar 2024 14:56:01 +0000 Suren Baghdasaryan <surenb@google.com>=
 wrote:
>
> > On Sat, Mar 23, 2024 at 6:05=E2=80=AFPM SeongJae Park <sj@kernel.org> w=
rote:
> > >
> > > Hi Suren and Kent,
> > >
> > > On Thu, 21 Mar 2024 09:36:52 -0700 Suren Baghdasaryan <surenb@google.=
com> wrote:
> > >
> > > > From: Kent Overstreet <kent.overstreet@linux.dev>
> > > >
> > > > This wrapps all external vmalloc allocation functions with the
> > > > alloc_hooks() wrapper, and switches internal allocations to _noprof
> > > > variants where appropriate, for the new memory allocation profiling
> > > > feature.
> > >
> > > I just noticed latest mm-unstable fails running kunit on my machine a=
s below.
> > > 'git-bisect' says this is the first commit of the failure.
> > >
> > >     $ ./tools/testing/kunit/kunit.py run --build_dir ../kunit.out/
> > >     [10:59:53] Configuring KUnit Kernel ...
> > >     [10:59:53] Building KUnit Kernel ...
> > >     Populating config with:
> > >     $ make ARCH=3Dum O=3D../kunit.out/ olddefconfig
> > >     Building with:
> > >     $ make ARCH=3Dum O=3D../kunit.out/ --jobs=3D36
> > >     ERROR:root:/usr/bin/ld: arch/um/os-Linux/main.o: in function `__w=
rap_malloc':
> > >     main.c:(.text+0x10b): undefined reference to `vmalloc'
> > >     collect2: error: ld returned 1 exit status
> > >
> > > Haven't looked into the code yet, but reporting first.  May I ask you=
r idea?
> >
> > Hi SeongJae,
> > Looks like we missed adding "#include <linux/vmalloc.h>" inside
> > arch/um/os-Linux/main.c in this patch:
> > https://lore.kernel.org/all/20240321163705.3067592-2-surenb@google.com/=
.
> > I'll be posing fixes for all 0-day issues found over the weekend and
> > will include a fix for this. In the meantime, to work around it you
> > can add that include yourself. Please let me know if the issue still
> > persists after doing that.
>
> Thank you, Suren.  The change made the error message disappears.  However=
, it
> introduced another one.

Ok, let me investigate and I'll try to get a fix for it today evening.
Thanks,
Suren.

>
>     $ git diff
>     diff --git a/arch/um/os-Linux/main.c b/arch/um/os-Linux/main.c
>     index c8a42ecbd7a2..8fe274e9f3a4 100644
>     --- a/arch/um/os-Linux/main.c
>     +++ b/arch/um/os-Linux/main.c
>     @@ -16,6 +16,7 @@
>      #include <kern_util.h>
>      #include <os.h>
>      #include <um_malloc.h>
>     +#include <linux/vmalloc.h>
>
>      #define PGD_BOUND (4 * 1024 * 1024)
>      #define STACKSIZE (8 * 1024 * 1024)
>     $
>     $ ./tools/testing/kunit/kunit.py run --build_dir ../kunit.out/
>     [10:43:13] Configuring KUnit Kernel ...
>     [10:43:13] Building KUnit Kernel ...
>     Populating config with:
>     $ make ARCH=3Dum O=3D../kunit.out/ olddefconfig
>     Building with:
>     $ make ARCH=3Dum O=3D../kunit.out/ --jobs=3D36
>     ERROR:root:In file included from .../arch/um/kernel/asm-offsets.c:1:
>     .../arch/x86/um/shared/sysdep/kernel-offsets.h:9:6: warning: no previ=
ous prototype for =E2=80=98foo=E2=80=99 [-Wmissing-prototypes]
>         9 | void foo(void)
>           |      ^~~
>     In file included from .../include/linux/alloc_tag.h:8,
>                      from .../include/linux/vmalloc.h:5,
>                      from .../arch/um/os-Linux/main.c:19:
>     .../include/linux/bug.h:5:10: fatal error: asm/bug.h: No such file or=
 directory
>         5 | #include <asm/bug.h>
>           |          ^~~~~~~~~~~
>     compilation terminated.
>
>
> Thanks,
> SJ
>
> [...]

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpGiuCnMFtViD0xsoaLVO_gJddBQ1NpL6TpnsfN8z5P6fA%40mail.gmail.=
com.
