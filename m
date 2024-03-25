Return-Path: <kasan-dev+bncBCC4R3XF44KBBNXSQ2YAMGQEEVJWAXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id 423BA88AC4D
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Mar 2024 18:49:44 +0100 (CET)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-60cd073522csf84473457b3.1
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Mar 2024 10:49:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711388983; cv=pass;
        d=google.com; s=arc-20160816;
        b=uTjwx6fUxnSFiddQLOU+5tlkBoFeAZBcRWYkqVjV8tU3kaYIKbXEzrHitqTiFOKXck
         FlAyefYE4dFeeUSb2yQhd3BFdkM1/QndRYLK/lEgW4x6apoM6Qrs6qyKcmECesE/difj
         m0Fc9vswD/3RjMpd4xpZNtUvB8ISMDxqqRRiXxustkNk3G5+Im4ruYE+17yarNOXQQh2
         CCDzA0O7LJSN0T5zvY4F1GRpblf+f/IKPXkqIFf/Q7SG4Kr5UnsuRYNeUqjlv58mWeze
         m1aix5wKnh+fvyEwtS1RTetHVrkAmduSbiYVblSKqC75ZfTl0kZv3lWWbc/ENRw4+F9X
         s9Sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature;
        bh=+DXOYlD2s1qsSSULp2cD2ORwnO67xbRmH+3ngXKPkjk=;
        fh=7lsNXHtWE5D19Rhe4/ejHVqajZ91z2g0YQhU6WQ6an8=;
        b=n+nZrYyQptrUTIgOU3EuBAi7pE4FcdHPB0E6cMjloLRUuJRcvLkNCVQFYiyAvhLbOr
         UXqdW9TWtxkh+qRVY9XyLeziEhkcnoJxOPdyR17ldVYqunwE0WfoQaKBywW21NUGb6pB
         F5+yqwAciiu7wYn0gm72QZByvzZI6EAF+kuavjvkQpA+6w/5sVtTA8MEeqwhaiEPDXOQ
         FxGCSgJaNRAcIMdlL3ZEQePaXUnhaN926u1UWzcm1tGRBhMpOPq/7zgedn2z5VUCT6oV
         Lk4zH0KYlID5wCeDU+tKYlmPtQIMDqc762FJdoRBIw6yEFtTXnB9M5asP8lxN5Nx0G5q
         KGiw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="bKfexc/+";
       spf=pass (google.com: domain of sj@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=sj@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711388983; x=1711993783; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+DXOYlD2s1qsSSULp2cD2ORwnO67xbRmH+3ngXKPkjk=;
        b=mSVXXzjt2uawlDPI7Xl6jJdzbLqGJ2mcvgPUSv5Py6YNTdsGDdB2qvF1cGgxVgDE8v
         bxoGyPq12rpcGDj1pdK8LriQmRRMoooipynBbkg6fJE5uJ3iFaru4cXq46vbkAO6pPdn
         ldzOO9/LKC1ixAMvQSd5nI4jy6cHULcsCV4F8YW6+d+K/+pp+2Lsj3ViMz1jEN3iRMM+
         +LffCjb16oJMtYSA8tHToKb9NNrFedn1GDrpKA9ipHT9kJNbjEHksuPuRKUOYhF3CcnX
         3L6+jEI3I810Chdz0U5jvn0RwpChVSKoHAQ3+qpeSQtK3zGDHFOLGKSecrddn+/QTlBf
         m2GA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711388983; x=1711993783;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+DXOYlD2s1qsSSULp2cD2ORwnO67xbRmH+3ngXKPkjk=;
        b=oL2sLCgIYlIEFEiY1Nz2yqTbRsowcVqAUsBW+lSGVljCPEDpJ6ryBQQniBuIIIpalV
         grEjmmfud/e54YKC4GOiOkTurWsWWIUi1KO6dSXuhXpc199gRnicOOjkEGUUcwYXOMsK
         mlDGlBXA23SxyB1bfFwSUEam6CHddEOy+anynm7n+mONDxsFYhMUNdLTZ8kFqTMAnWkc
         mhEJJ35sLkb7e19PFGf37QN+auaKP3inUThqGGlbUC1zQyYMu5WsDyLt224uNe3fjAYR
         rG+7gUR9w0WglqwyM+MfrSlyvUy4fnBvr6JZf/PDNnd/os/NN706znGkQzJplRfaBsWn
         aT3Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX/hkUnipORuccYBIMJcDPHJsMJAfBcsbbmDtVllOl+TD3uk+Kk7zYVvzsUCRsDvmp8Q5KJ/lCJ/+0HkWeeo/HEVTHaxW+y1Q==
X-Gm-Message-State: AOJu0Yz+Vwo/d0tXGxqGHzDVWua4cd/TzOANMQ/tpjyZkaDgLCjwnH8U
	nx7vQBJM2m9xzm+YOA56bXrfcYynnvtZDrd8pSErDSPppt75ehYT
X-Google-Smtp-Source: AGHT+IFDxqOis1d+pbY7fNv7KDFM+JjiyONEXyi6UK1lmqfrM1dytEhFOdFUbvA9R6pNM17JQXPsUQ==
X-Received: by 2002:a5b:c45:0:b0:dcc:84ae:9469 with SMTP id d5-20020a5b0c45000000b00dcc84ae9469mr5535039ybr.64.1711388982942;
        Mon, 25 Mar 2024 10:49:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:df97:0:b0:dcb:bfe0:81b8 with SMTP id w145-20020a25df97000000b00dcbbfe081b8ls626507ybg.0.-pod-prod-09-us;
 Mon, 25 Mar 2024 10:49:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU4IpGoRigpfME8JMH1bXJK7L44FTQhWksmrEK/qS+YfnchKEEGLtMB5l7o+fSLswKvCMlC08aq54qsQ5hvoklOemYX3u9wB4HUzw==
X-Received: by 2002:a25:ad64:0:b0:dcc:5a73:1cad with SMTP id l36-20020a25ad64000000b00dcc5a731cadmr5090390ybe.42.1711388982074;
        Mon, 25 Mar 2024 10:49:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711388982; cv=none;
        d=google.com; s=arc-20160816;
        b=dFm4dnLSR4g3vD6D7Ww77qaAVJyJ5Naz/EjTNYPhs9Z7msIoBJMmodbFQMFC5ubs03
         AB+2A/LETLrVGwvPvoSSQGrSB/l6CQQJrXyEoQLOBxzI0vF33EIimCiqyn7u6xrTsWy8
         ghs3/EJma0kFsTnc7wBgx6g52wtlBwEh1RsC3KHlc3Aky35aEeLIrExv6KcjatIy3UaD
         YmgQPeqBbDNzTDUlVpMs9CIeesTjVTG9F9/vBDULBgSnaouhF008gF82QqivQNrZQs2L
         Y5dWUzrenxaK4UheE7pux86pmahvMau8He888uMmNyXnI/TxtAnTFmE/uYVNp3QuWFCF
         Kz7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=K+GhxBixP5JjAGdOkr+lUVwgcmucBfd7EsXTC56o3cw=;
        fh=2R6AFbA8yJpj5foQHOi8v811Q5b4vopO54Zi7EcoQRo=;
        b=df7nTDcXudZT4UfHyMUE/ufX8J1nrXiCFhRCeMEB37eifbYH/HULTg/AerTh77uD+a
         P/ThUCnVNyUvytDswc2WqPVkIiEPAaRRSuCHm/zmKvAzwrrHoBqRbTw+pcSTOTAB2nCI
         hV3IeUy9MQnIAZhpIeGmCCcOKPA75JtO+Ik/mfvmgt7OLPwnM4ZqAah/J+9xOJa2/SEr
         js1HFmWc/gaid/eEPkGRndCA6wtCqIQwBpBP/6g6wWYBinAS0hnHFDVdWy+hASaOatZR
         V0gv89qL4rHpEPW/i4YbuMuOKzPIuPVzor2+Q+i/w54eQ2ZAi104DDS8yMEzQWUD355j
         nLkQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="bKfexc/+";
       spf=pass (google.com: domain of sj@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=sj@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id x202-20020a25ced3000000b00dcd162eec7esi520324ybe.2.2024.03.25.10.49.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Mar 2024 10:49:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of sj@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 8694C61195;
	Mon, 25 Mar 2024 17:49:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4ADB6C433C7;
	Mon, 25 Mar 2024 17:49:36 +0000 (UTC)
From: SeongJae Park <sj@kernel.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: SeongJae Park <sj@kernel.org>,
	mhocko@suse.com,
	vbabka@suse.cz,
	hannes@cmpxchg.org,
	roman.gushchin@linux.dev,
	mgorman@suse.de,
	dave@stgolabs.net,
	willy@infradead.org,
	liam.howlett@oracle.com,
	penguin-kernel@i-love.sakura.ne.jp,
	corbet@lwn.net,
	void@manifault.com,
	peterz@infradead.org,
	juri.lelli@redhat.com,
	catalin.marinas@arm.com,
	will@kernel.org,
	arnd@arndb.de,
	tglx@linutronix.de,
	mingo@redhat.com,
	dave.hansen@linux.intel.com,
	x86@kernel.org,
	peterx@redhat.com,
	david@redhat.com,
	axboe@kernel.dk,
	mcgrof@kernel.org,
	masahiroy@kernel.org,
	nathan@kernel.org,
	dennis@kernel.org,
	jhubbard@nvidia.com,
	tj@kernel.org,
	muchun.song@linux.dev,
	rppt@kernel.org,
	paulmck@kernel.org,
	pasha.tatashin@soleen.com,
	yosryahmed@google.com,
	yuzhao@google.com,
	dhowells@redhat.com,
	hughd@google.com,
	andreyknvl@gmail.com,
	keescook@chromium.org,
	ndesaulniers@google.com,
	vvvvvv@google.com,
	gregkh@linuxfoundation.org,
	ebiggers@google.com,
	ytcoode@gmail.com,
	vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com,
	rostedt@goodmis.org,
	bsegall@google.com,
	bristot@redhat.com,
	vschneid@redhat.com,
	cl@linux.com,
	penberg@kernel.org,
	iamjoonsoo.kim@lge.com,
	42.hyeyoo@gmail.com,
	glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	songmuchun@bytedance.com,
	jbaron@akamai.com,
	aliceryhl@google.com,
	rientjes@google.com,
	minchan@google.com,
	kaleshsingh@google.com,
	kernel-team@android.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev,
	linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org,
	linux-mm@kvack.org,
	linux-modules@vger.kernel.org,
	kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH v6 30/37] mm: vmalloc: Enable memory allocation profiling
Date: Mon, 25 Mar 2024 10:49:34 -0700
Message-Id: <20240325174934.229745-1-sj@kernel.org>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <CAJuCfpFnGmt8Q7ZT2Z+gvz=DkRzionXFZ0i5Y1B=UKF6LLqxXA@mail.gmail.com>
References: 
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: sj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="bKfexc/+";       spf=pass
 (google.com: domain of sj@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=sj@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, 25 Mar 2024 14:56:01 +0000 Suren Baghdasaryan <surenb@google.com> w=
rote:

> On Sat, Mar 23, 2024 at 6:05=E2=80=AFPM SeongJae Park <sj@kernel.org> wro=
te:
> >
> > Hi Suren and Kent,
> >
> > On Thu, 21 Mar 2024 09:36:52 -0700 Suren Baghdasaryan <surenb@google.co=
m> wrote:
> >
> > > From: Kent Overstreet <kent.overstreet@linux.dev>
> > >
> > > This wrapps all external vmalloc allocation functions with the
> > > alloc_hooks() wrapper, and switches internal allocations to _noprof
> > > variants where appropriate, for the new memory allocation profiling
> > > feature.
> >
> > I just noticed latest mm-unstable fails running kunit on my machine as =
below.
> > 'git-bisect' says this is the first commit of the failure.
> >
> >     $ ./tools/testing/kunit/kunit.py run --build_dir ../kunit.out/
> >     [10:59:53] Configuring KUnit Kernel ...
> >     [10:59:53] Building KUnit Kernel ...
> >     Populating config with:
> >     $ make ARCH=3Dum O=3D../kunit.out/ olddefconfig
> >     Building with:
> >     $ make ARCH=3Dum O=3D../kunit.out/ --jobs=3D36
> >     ERROR:root:/usr/bin/ld: arch/um/os-Linux/main.o: in function `__wra=
p_malloc':
> >     main.c:(.text+0x10b): undefined reference to `vmalloc'
> >     collect2: error: ld returned 1 exit status
> >
> > Haven't looked into the code yet, but reporting first.  May I ask your =
idea?
>=20
> Hi SeongJae,
> Looks like we missed adding "#include <linux/vmalloc.h>" inside
> arch/um/os-Linux/main.c in this patch:
> https://lore.kernel.org/all/20240321163705.3067592-2-surenb@google.com/.
> I'll be posing fixes for all 0-day issues found over the weekend and
> will include a fix for this. In the meantime, to work around it you
> can add that include yourself. Please let me know if the issue still
> persists after doing that.

Thank you, Suren.  The change made the error message disappears.  However, =
it
introduced another one.

    $ git diff
    diff --git a/arch/um/os-Linux/main.c b/arch/um/os-Linux/main.c
    index c8a42ecbd7a2..8fe274e9f3a4 100644
    --- a/arch/um/os-Linux/main.c
    +++ b/arch/um/os-Linux/main.c
    @@ -16,6 +16,7 @@
     #include <kern_util.h>
     #include <os.h>
     #include <um_malloc.h>
    +#include <linux/vmalloc.h>
   =20
     #define PGD_BOUND (4 * 1024 * 1024)
     #define STACKSIZE (8 * 1024 * 1024)
    $
    $ ./tools/testing/kunit/kunit.py run --build_dir ../kunit.out/
    [10:43:13] Configuring KUnit Kernel ...
    [10:43:13] Building KUnit Kernel ...
    Populating config with:
    $ make ARCH=3Dum O=3D../kunit.out/ olddefconfig
    Building with:
    $ make ARCH=3Dum O=3D../kunit.out/ --jobs=3D36
    ERROR:root:In file included from .../arch/um/kernel/asm-offsets.c:1:
    .../arch/x86/um/shared/sysdep/kernel-offsets.h:9:6: warning: no previou=
s prototype for =E2=80=98foo=E2=80=99 [-Wmissing-prototypes]
        9 | void foo(void)
          |      ^~~
    In file included from .../include/linux/alloc_tag.h:8,
                     from .../include/linux/vmalloc.h:5,
                     from .../arch/um/os-Linux/main.c:19:
    .../include/linux/bug.h:5:10: fatal error: asm/bug.h: No such file or d=
irectory
        5 | #include <asm/bug.h>
          |          ^~~~~~~~~~~
    compilation terminated.


Thanks,
SJ

[...]

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240325174934.229745-1-sj%40kernel.org.
