Return-Path: <kasan-dev+bncBC7OBJGL2MHBBI4Q632QKGQELLZJ3DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B5691D38C6
	for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 20:04:20 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id q5sf134135pgt.16
        for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 11:04:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589479459; cv=pass;
        d=google.com; s=arc-20160816;
        b=pDjdY9O/g/Lt7Pog+Ig8mPd6s+1zNEmo4iKiPBd7ZgzTAx3iV8qYScx3DOQTi6Kj0e
         TuOTGF9BQU3nY5gjEQBQF0MdiWLfX1j6qd9dqNV3fK10zBq0t//kFGdygLYvvHLi4Beu
         TBQAkToxK6j5mwUlSSex6ufQP2/gA+Z07BTJadjCwvvvMjd0fXjF9N8yi0e+EWDOIeLh
         KuusI9WZiha8opRvX2qz8aWZk/viYjEKk/0KxTK742kly8KUMUWlKO/5gjQSkxLtTtdo
         F2Da0QCtbbty+IMkqQJMs8kObcUxa3iE1XBe78qcxNzccwUKbUyLF0pCzbymhwA3Et38
         FFng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=QE4YBL1T232ODmRWid68XAT4au/IrXRDKGpEXVezVdk=;
        b=NikoK+6dDf3n7x4Wx8FRb/Eq7mVfYbDSTNAFz9ADQRQTRDfqkqMCLmvD5/UVAuAk87
         pY1rhXiXs8Ez66kaRRXOSBtqqnCGR7FK9MlupTF0D78PedvsW9E60T9yZ/7LgTJG7zMq
         fyS6qzckcEooKlyfyGv2ueh3WdvjPwyKhy2Ap3dfOJMpeEnyLyyP9a1oOf7rdlmMtCMC
         eOQrl7HqDY80yxawDN35bf601EB+ojSnxkJFCsRoTcqTLJU0h+uCiVU2N9AP1Lv0MXGQ
         hHkRAJXod5dJWJ1DicCaq5LYldQ1CT3/Ig3kjUk4i3pjXNrifPtyNpK5/LDG/9nP1X6L
         2etw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dZsQllqj;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QE4YBL1T232ODmRWid68XAT4au/IrXRDKGpEXVezVdk=;
        b=odQ1XmnAa3/ubHeTgHeGvGkRCOBBuPOm8xNDhUoqX3erjYQjybQ6NlorpbsnePfCSn
         OPRLs7iye70YVtxD5U7ZFu20yrKghO/VbPquV50cn2DP6ZgMdoQyRV/5Aemitw5gwoO9
         JvoD4Ivfab7jGO+6PnOsfVh+o9FdwnM5RIPqihEJXVH6xvu+TGDSEqzkCnZRtcPJ9DtR
         dgyXhPrdHJTesl0/RSZlzbsrz+xyOBcaMq4uRjBnQtcSdUFoReqjiMzO/bJdoFk641Xe
         EhWvin/Ea3/+ZMewz/T3Q2TwWY22269Fpi/PyfxICA5iFfpEhwvLaaU0y9HvRxFfUjRk
         uSfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QE4YBL1T232ODmRWid68XAT4au/IrXRDKGpEXVezVdk=;
        b=ArHjyOehg3i4lRTUaQAfAj+nsA6UHji+UvdtoJgLehWRyor0HCN6pt161aMNNvoBn9
         1udA12aT51ehay1/84dtBrRAgIT/kPOpoqDyrK2YYJrSnI2PbQY3e7fMPhKgD2WSjCSo
         M8kHouPQO65pFr1nqJ/Qe3eOTybHkjGng0U4+9qvV0LF3gW5yPPuKqM4purCZe7d7tdV
         L+gW+AXG9IBFbBHa+YjutGkMyrjDzH6UNCmyxRruTwyaMT0WTp6uJg23fSFy6d2f53f1
         T5UsFMJtcoozvTLSAUZolhEsaw9kAxjh8bUFF6TxieP5CgA0M67Y8CWPXuoBrLdssE0T
         uqPA==
X-Gm-Message-State: AGi0Puadf1Cp7TrxbugM0c0pVVVtUVOB6HyP3q1n+yw3DupfmMSYPR+T
	UasjgjMbKR5Lx1TFu8UwcpM=
X-Google-Smtp-Source: APiQypLa4O4WBBCslrPP+P0P0YsByWyT6BTmWZ+Dl4wYzDlqmBaPyAiSmGQxDfOFREqMv+e6+Dlrzg==
X-Received: by 2002:a17:90a:2843:: with SMTP id p3mr39866714pjf.204.1589479459115;
        Thu, 14 May 2020 11:04:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4d05:: with SMTP id mw5ls3073942pjb.1.canary-gmail;
 Thu, 14 May 2020 11:04:18 -0700 (PDT)
X-Received: by 2002:a17:902:442:: with SMTP id 60mr5247010ple.103.1589479458647;
        Thu, 14 May 2020 11:04:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589479458; cv=none;
        d=google.com; s=arc-20160816;
        b=gcYpoJdeRNtRVWhigImEiQme6hhz/AOvAhwm3GN/Hjvf3a9knfRbIG0VJN0o2jbQ7J
         mp7jw+JWxdx3b6IEILqdcA9vgtqSQOy7FmVGras23vs0ss+hMbusovi4jVbmTOyLX00r
         EfrEqL1yl5jLs2JJWcByLFmryzehzuwikQ9Tta0XZ/GkgP4xd1ZBYWdv6JDqYjb3SHJO
         HvHONnP9nikIrELMqctEQrs6lYQxEdPBM9rlMfj1ooGlEGRTLQYUaHtNt1AhaIpC+RuC
         sgKWCJlwyWEu0Hf8WLcKJ64+XmTNHI7ef+4S5vIv58F/+9nTwJ96iHZxFi8yw8DN2T3l
         1uzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hm1L4TxK6USvoL4ulsK5K70owcN6rXPibVE1+OmeBO8=;
        b=dr5H59jJUumV4odN/wX2jjo4KajGCEU4AyYRmBUKaTa1WUmOqLKCW+ytDo/DyhwFzg
         /hAjae4g1g6/axRDmQY3sFiezRAtNBJBipSjn9oiB6QcKgiuddEKoF5SymAyqnVa+0YE
         ZIgJ2LxdYwCzL2VWZ1g2gPD1FppLue9JUfWXciOFq/O/gE/SrXJ12yb5OzX0kUD/iVfp
         W3SQzQyA+5TvxokZn+eKY4cR7g0iwWsvg9fiUVBHBGP8o3P2krUyHTwzi71nLLqy6e56
         Clf6BwccnJhbtYMSAT5MFwyFyroK5OPMuFEQYeJn7DsK6yxW4jg05dKyTVxWw/hNCZHu
         PmYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dZsQllqj;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id u6si31830plz.5.2020.05.14.11.04.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 May 2020 11:04:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id o24so25343332oic.0
        for <kasan-dev@googlegroups.com>; Thu, 14 May 2020 11:04:18 -0700 (PDT)
X-Received: by 2002:aca:ebc5:: with SMTP id j188mr2465007oih.70.1589479457678;
 Thu, 14 May 2020 11:04:17 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNNLY9EcSXhBbdjMR2pLJfrgQoffuzs27Xrgx3nOuAUxMQ@mail.gmail.com>
 <CAKwvOdnQaeQ2bLqyXs-H3MZTPBd+yteVG4NiY0Wd05WceAad9g@mail.gmail.com>
In-Reply-To: <CAKwvOdnQaeQ2bLqyXs-H3MZTPBd+yteVG4NiY0Wd05WceAad9g@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 May 2020 20:04:06 +0200
Message-ID: <CANpmjNPLgFdFpHzj5Hb_1CfFzPMmqy3z1O98N=wsr8kQ1VS9_Q@mail.gmail.com>
Subject: Re: ORC unwinder with Clang
To: Nick Desaulniers <ndesaulniers@google.com>
Cc: clang-built-linux <clang-built-linux@googlegroups.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Peter Zijlstra <peterz@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dZsQllqj;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Thu, 14 May 2020 at 19:48, 'Nick Desaulniers' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> + Josh, Peter
>
> On Thu, May 14, 2020 at 10:41 AM Marco Elver <elver@google.com> wrote:
> >
> > Hi,
> >
> > Is CONFIG_UNWINDER_ORC=y fully supported with Clang?
>
> We're down to 4 objtool warnings in an allyesconfig build.  3 I
> understand pretty well, and patches exist for them, but I haven't
> looked into the 4th yet.  Otherwise it works (to the best of anyone's
> knowledge).  Though kbuild test robot has dug up 4 new reports from
> randconfigs that I need to look into.
>
> Here's our list of open issues with the objtool label:
> https://github.com/ClangBuiltLinux/linux/issues?q=is%3Aopen+is%3Aissue+label%3A%22%5BTOOL%5D+objtool%22
>
> I remember Josh mentioning
> https://github.com/ClangBuiltLinux/linux/issues/612 which I haven't
> had time to look into.
>
> >
> > I'm seeing frames dropped in stack-traces with
> > stack_trace_{dump,print}. Before I dig further, the way I noticed this
> > is when running the KCSAN test (in linux-next):
> >
> > CONFIG_KCSAN=y
> > CONFIG_KCSAN_TEST=y
> >
> > The test-cases "test_assert_exclusive_access_writer" for example fail
> > because the frame of the function that did the actual access is not in
> > the stack-trace.
> >
> > When I use __attribute__((disable_tail_calls)) on the functions that
> > do not show up in the stack traces, the problem goes away. Obviously
> > we don't want to generally disable tail-calls, but it highlights an
> > issue with the ORC unwinder and Clang.
> >
> > Is this a known issue? Any way to fix this?
>
> First I've heard of it.  Which functions, and what's the minimal set
> of configs to enable on top of defconfig to reproduce?

In linux-next:

CONFIG_KCSAN=y
CONFIG_KCSAN_TEST=y

And wait for the "test_assert_exclusive*" test-cases, which will fail.
The stack traces of the races shown should all start with a
"test_kernel_*" function, but do not. Then:

  sed -i "s/noinline/noinline __attribute__((disable_tail_calls))/"
kernel/kcsan/kcsan-test.c

which adds the disable_tail_calls attribute to all "test_kernel_*"
functions, and the tests pass.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPLgFdFpHzj5Hb_1CfFzPMmqy3z1O98N%3Dwsr8kQ1VS9_Q%40mail.gmail.com.
