Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGEURCKQMGQEX2QT6AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C387544FF4
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 16:56:25 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id m6-20020ac866c6000000b002f52f9fb4edsf18839364qtp.19
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 07:56:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654786584; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q6kOw9HaI2hS28dh73PdNhlCAgZQAD5Sqc2lh/9lcM+SIC72OYf6/U6mc8miYe6lip
         l3NLgJfleLfJfV17b5DvxyhTBeQdaT1XfxGjMNxfPp9S1qHYOVYIP2mgPChwa1g3zCr3
         X2KDFgWTiT7UBEVgpBP/sWc+iLnoFHhFfxsNiZVdUGv4bS864ynD/PPSWBExC2WTrmEO
         T8QljnhiWbn/mCb6IoYMxgrTDN8YNJ6blt8I6oAbD/0UkxgbQ6stMMnd3DKiNi/T/2b0
         ciQkkLQKIvJkESmIEFEdhIZ+b/dUPrvrlq16MWQSS+tV7AcVorSiBuZc5XbSg+SGCoYt
         B9aA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=sTV8t5ZbNLUMeWCOEzKr+LrHqKSCHc8yW11ZA1uNALQ=;
        b=BU8ha1PNMXKgXwruN77op4NCIkZVV0eSmVtov4TLE66m02lvGC8mMkinLKEzMjrnMk
         M9nYzXK9/MQ+9PFX+zXRxPy8vem8aQySFcgWZS76Uwt7jDe+wLFovzjzFc1AnqSEHfam
         uIQsJ6EPPMLwGDDh+yd3MSlHNhP60cE1qB+LRtESgi+ecDH6ChPQUi2asx6+iit8Unq0
         WfLt5QtDMwIxBBcqZz92grl10rZ77s63hPGNN2vizQ0OtnXoa2ick1N1RZ5FBHiA9CRF
         0YR3VfTzqYcfnsUYNBOLGCXYgl3aQtJkIkz36CFzsG3UskCHgTrlBLelFpTSRoPBRZ3P
         ge/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=deUfDUG4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sTV8t5ZbNLUMeWCOEzKr+LrHqKSCHc8yW11ZA1uNALQ=;
        b=IQAKBuhAy9YX3w5Ia7lpmw4lbNLOKsi5x56jv/TvZxaeH4W2ACmlz1ILEIaG4BWI7r
         F4gbW5gSp4J+N6JEumWCDQ+gqJv6hvyllj6oOF2kMQMVXQOZijVkG6L4Tqwii1QfVeog
         n948QpWUKGSApPGye2wheY3f5UNzyp7OAHYn08kuS9tdZnPAVTvfNhNiiKRZdrnlZl5v
         BxzWTp83wVMxJZUa8zTondM1pBDC6QUK4/FSIgGma93pa1RS/w3Nx4S8/otW4ISyQrl7
         YhMLhiTZn9+VhK7S2nT44Pfi/FWFuBRD6wQ38jtDSUCxonOFlCPFOcWTbH4eg2wdGxie
         yl/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sTV8t5ZbNLUMeWCOEzKr+LrHqKSCHc8yW11ZA1uNALQ=;
        b=DWR0YW+G3mgoiB02DyT1zAfaPjQkbERDhrrwZDAdSqdf6arEFIQvQVgHFgw3hVbaW+
         /maPIhcXxalLAus8tR3Zo3O1rgfhbo/f2iRmO77HugwAiPzJyCu15cLe2q41jITgMaTa
         9nVt0CTRbVbnTU9ZErGAuJBVJCkDgZb4XcokZK+bp1w+kHmEdkaVjAxXqkVAOgLWH5Pl
         VwdBbuIHaoE5cl46ckKO4srgM11BfFKuaPK9zeIVFWXOkW04GLUgoHOhk3fhjtV9TC8b
         rJmNn0RD2vL6VHr3TfaeLZrOzLHlUQBkoJiPPHQ5Tz3rNzS8RAk06p8w0mMBqnOkhvXh
         QyQg==
X-Gm-Message-State: AOAM532IWb8AgAOTPiucSO+ZoVEzWV0AkERISW/Y0cQ/ybG6oDQ0PFPY
	C0Vc8IUy5A0W14pNTrOQh70=
X-Google-Smtp-Source: ABdhPJzFw0CDS0xXupZn4d7bMGd75kyY4s26VOiFVXLNAVaBzicQ+9uvPBDLaIwgVHNs83xLU5p+vQ==
X-Received: by 2002:a05:6214:d8b:b0:46b:a79a:2f2b with SMTP id e11-20020a0562140d8b00b0046ba79a2f2bmr14643050qve.36.1654786584228;
        Thu, 09 Jun 2022 07:56:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:308:b0:304:ebe4:7307 with SMTP id
 q8-20020a05622a030800b00304ebe47307ls7124516qtw.4.gmail; Thu, 09 Jun 2022
 07:56:23 -0700 (PDT)
X-Received: by 2002:a05:622a:590:b0:2f9:4396:aed3 with SMTP id c16-20020a05622a059000b002f94396aed3mr31990747qtb.353.1654786583615;
        Thu, 09 Jun 2022 07:56:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654786583; cv=none;
        d=google.com; s=arc-20160816;
        b=xuWxZgyOnYdYJx8LngNxumBJ2yBkLmin1m/Q0Sn7nnRvbup+PO6CSonXHtJ9VkqLmB
         2q7bj5eTXZ15ufwN19Y51z0uAA8l+oHzRWlsIXgm6eVbkHHUEie5dNgqI6r6uLdNw5xz
         k/k/jYDen4T+QzG3+BgZatNkownex/i64KicVAP7pTTGs9C790XSAuR4V44BoAfREC/r
         4STM705uvVSeHD/+/Zlau1Lxg9GOFcV40vBhaQaHHJ/c+LCYU4RPJpV03uM9T14CKw9M
         lpmCfhv0rB/2q+sh17Kv6G8seiZDYnTmMoTpq7QxAim6us+B6t5DpZD0HYOv6hO1XX4g
         p71g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0+SkCjGgZBFq5wRCXTYfFTyaGhOAcbR2Sdoh6LQhmUA=;
        b=MgARaRC7wpFUb4GqCydsx+lw8u9UMZ9Z8b+wqfz5D4rtg0Uhtu9dbf+yBPK5R8zXvf
         JlwTDKcPHPBatymwQBBsVWzwUlXLEWJyVRHB/gt53LZEorjLWitShdNtG95SynItOj7r
         naqOZMVjnA2DcTOnpj9BhK2FPNRGJNur32NA+egnV4k9DCySxm48FWOinCsccHGheGFZ
         JkrkuivmzrtPLivkl553z0SIBLcf9Q2QdmVjVKfneX5+l/2+o24GlftRTbZbhHaSdFAy
         eYqEenQaUohIoDgfVSa52Ew0UKD0vildx78iQb6lyPU48OMO54739XGLYJCWj9PRdy2t
         S7zw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=deUfDUG4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112a.google.com (mail-yw1-x112a.google.com. [2607:f8b0:4864:20::112a])
        by gmr-mx.google.com with ESMTPS id ee18-20020a05620a801200b006a717217db6si187411qkb.7.2022.06.09.07.56.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 07:56:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) client-ip=2607:f8b0:4864:20::112a;
Received: by mail-yw1-x112a.google.com with SMTP id 00721157ae682-31336535373so92972607b3.2
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 07:56:23 -0700 (PDT)
X-Received: by 2002:a0d:c0c6:0:b0:2ff:bb2:1065 with SMTP id
 b189-20020a0dc0c6000000b002ff0bb21065mr44984991ywd.512.1654786583034; Thu, 09
 Jun 2022 07:56:23 -0700 (PDT)
MIME-Version: 1.0
References: <20220609113046.780504-1-elver@google.com> <20220609113046.780504-2-elver@google.com>
 <CACT4Y+bOFmCyqfSgWS0b5xuwnPqP4V9v2ooJRmFCn0YAtOPmhQ@mail.gmail.com>
In-Reply-To: <CACT4Y+bOFmCyqfSgWS0b5xuwnPqP4V9v2ooJRmFCn0YAtOPmhQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Jun 2022 16:55:46 +0200
Message-ID: <CANpmjNNtV_6kgoLv=VX3z_oM6ZEvWJNAOj9z4ADcymqmhc+crw@mail.gmail.com>
Subject: Re: [PATCH 1/8] perf/hw_breakpoint: Optimize list of per-task breakpoints
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, linux-perf-users@vger.kernel.org, x86@kernel.org, 
	linux-sh@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=deUfDUG4;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as
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

On Thu, 9 Jun 2022 at 16:29, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, 9 Jun 2022 at 13:31, Marco Elver <elver@google.com> wrote:
> >
> > On a machine with 256 CPUs, running the recently added perf breakpoint
> > benchmark results in:
> >
> >  | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
> >  | # Running 'breakpoint/thread' benchmark:
> >  | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
> >  |      Total time: 236.418 [sec]
> >  |
> >  |   123134.794271 usecs/op
> >  |  7880626.833333 usecs/op/cpu
> >
> > The benchmark tests inherited breakpoint perf events across many
> > threads.
> >
> > Looking at a perf profile, we can see that the majority of the time is
> > spent in various hw_breakpoint.c functions, which execute within the
> > 'nr_bp_mutex' critical sections which then results in contention on that
> > mutex as well:
> >
> >     37.27%  [kernel]       [k] osq_lock
> >     34.92%  [kernel]       [k] mutex_spin_on_owner
> >     12.15%  [kernel]       [k] toggle_bp_slot
> >     11.90%  [kernel]       [k] __reserve_bp_slot
> >
> > The culprit here is task_bp_pinned(), which has a runtime complexity of
> > O(#tasks) due to storing all task breakpoints in the same list and
> > iterating through that list looking for a matching task. Clearly, this
> > does not scale to thousands of tasks.
> >
> > While one option would be to make task_struct a breakpoint list node,
> > this would only further bloat task_struct for infrequently used data.
>
> task_struct already has:
>
> #ifdef CONFIG_PERF_EVENTS
>   struct perf_event_context *perf_event_ctxp[perf_nr_task_contexts];
>   struct mutex perf_event_mutex;
>   struct list_head perf_event_list;
> #endif
>
> Wonder if it's possible to use perf_event_mutex instead of the task_sharded_mtx?
> And possibly perf_event_list instead of task_bps_ht? It will contain
> other perf_event types, so we will need to test type as well, but on
> the positive side, we don't need any management of the separate
> container.

Hmm, yes, I looked at that but then decided against messing the
perf/core internals. The main issue I have with using perf_event_mutex
is that we might interfere with perf/core's locking rules as well as
interfere with other concurrent perf event additions. Using
perf_event_list is very likely a no-go because it requires reworking
perf/core as well.

I can already hear Peter shouting, but maybe I'm wrong. :-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNtV_6kgoLv%3DVX3z_oM6ZEvWJNAOj9z4ADcymqmhc%2Bcrw%40mail.gmail.com.
