Return-Path: <kasan-dev+bncBCMIZB7QWENRBOGTS6CQMGQE4FVRUGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id A83BB389CD0
	for <lists+kasan-dev@lfdr.de>; Thu, 20 May 2021 06:46:50 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id bo19-20020a17090b0913b029015d14c17c54sf4341364pjb.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 May 2021 21:46:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621486009; cv=pass;
        d=google.com; s=arc-20160816;
        b=IWSazt/6sUwwtqCMBgSVd/g3BBk/2ufz2aCns0AAp5dDhKpLIQkyy4Rx4zr/LTMHfm
         jwXUDx8ISUWv64qNgVbMnMHty8dsUYpcTBwpn4fcYNAd6oNHdk4x70yXr1Ns+LVpkKNd
         N5tNpm1rvHlsP1foMDtRpebKZ4XtbCD7xFaiBf/MG7dD1/MsAa+yXRd8G+4yy6N4Pd6+
         pQwAjgPpOJGANIZ7ZVCrX7PNesonppMLndzr7wm/wb+ArOLCZF46KZaMNueZ8nnjWZ/+
         jPnUl/afniAfLKMCRtBpjYbVBywfyAZXORxRXl+H60ssKYtF6bPeh7xiGJSRiCEpMJRS
         tQgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=za9q7ibJY6/FDFVy7YIoEJfS/0UjT35hAi4RCGRQ3k8=;
        b=rIt7+wOq04bdx+1gFSbKz76A1yUfT/BJud8F2dCJUdqsIyQ2HqxDVqY42B7fcwkvJ0
         TrvY7XC0mmBEL8qsfvBR0AuicHisjha2VUnZmp/cpPkdBPcAMNCnR11b5lmB0Djzyb6f
         Xtw4kq0q6pS7ej/yxCKKv4ov4bSIzQza4VpZkMffIyue/jUvWl7ztp3y/BMyQqhUHnxn
         BRoSyP/v8ZB/GXRoL0+AaqgTrtQSDkOdCI7YJGrZXUtAKQClEMTeI+xoPMQ9JtcWIrXL
         +HRRsmWhOudQ2RGRds5FSAUibsCiUFocOEYAlKiY/oCdKahlJfeXHAvs8m3eJfRvL4yI
         4ToA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=i+jg8hta;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=za9q7ibJY6/FDFVy7YIoEJfS/0UjT35hAi4RCGRQ3k8=;
        b=q79Nl+HUw9iuTw3kjRGjxkzye2G4wngMbZC7Inn0bP1jIMYP+q9qADC4NPtzclV675
         7gCYbm2qw6sDPG+zdzBtNFsSzgR4S0MMHif4YTDKs40LgYbNoSXxsLGvm95qFpj4XMW7
         535J8GUyxxaLgZFZ2go0GsJCrB0qE6dOGHUswfozGNdXy33L6T2dl3yhklj2hvAFEosP
         +bfPm6A9qx8ZnA1x4AsjIoYKX1283DtZmqHxtHs3Fhf2ZFmKuOlTlWMNeP4uzZbm2lTQ
         yT4em3bXqahMPIevxrW0TjaD06W7z6Wp2i6OpKJnELEkMRYAIf+EEYsNC1hllUSZ9sVr
         Ydhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=za9q7ibJY6/FDFVy7YIoEJfS/0UjT35hAi4RCGRQ3k8=;
        b=Nd/5KC4g7qGk7l7Qzc39yXRDnZziH3Eox7srB+aFTCeoINH5NMhBSgbZc/YYe76y5M
         KKDSBo/f6hiMrCMxSuk1i+iHwr2vLkf0tAqrgdjU8VWREzN8Z06MyIIRO1bVzBAgjsx9
         0XkUWmioIra2I9ZP8RyfCwt2o2c4b2g3/pDE4biJ3N5JA9sdVaYGf3ykKVYFysT0oZNa
         bz10PwOLu1RnvtS7kQ6CbaKvGL3nPoAUD9NFVtqpZ/5+AbUvZf3YAzD+nYqgCpAVbtYm
         N/AX+xCfQM9NZ9vWtQg21dm5ohf8vih6r+oOCxJCZDUdNpAMwHM5/TRhsCPFGxL1gGOz
         PMqA==
X-Gm-Message-State: AOAM533apwwHRrheClWNhiHUIcvEWRXrZwKtygS0xnH3iBXiLucU8H7X
	yUVna06S65GPdS3AG4cm+YE=
X-Google-Smtp-Source: ABdhPJx3N2dEuqOvwEEZx24cEQI0cH1GALyL4lQEPC+1nMfWXT2UajonIiJtG/btko4NJcdlsFNAMg==
X-Received: by 2002:a62:3344:0:b029:25e:a0a8:1c51 with SMTP id z65-20020a6233440000b029025ea0a81c51mr2675617pfz.58.1621486009126;
        Wed, 19 May 2021 21:46:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8184:: with SMTP id g4ls652815pfi.4.gmail; Wed, 19 May
 2021 21:46:48 -0700 (PDT)
X-Received: by 2002:a62:4ecc:0:b029:2d7:d315:2579 with SMTP id c195-20020a624ecc0000b02902d7d3152579mr2550820pfb.21.1621486008492;
        Wed, 19 May 2021 21:46:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621486008; cv=none;
        d=google.com; s=arc-20160816;
        b=kuvozHco0EH36M1okt0lt/1D/TtTG3bBcE9K65Etv9TXFibs8+/7HOmAWAptZPO0nr
         0xoUE0JaKEEBP26SxKkwXPFGfIVOe8/8uqCFWEp+DFkUSwRcwU9oejd2Frh+de7v8cnV
         4x6n+lfpHUIMDoplYbMfa/LeB+dv8CBXDt4SJHcjBthg6K29DXN86NMSCHdgwPZoUx34
         hchc7NQxXxmNl2fEXsrQBwZe7wQzQqilGc0quiMJdYfqkmJjkJhLTHXmn23bXf9d4AXK
         Zo/UmcnmlPE28ibTRqkREQVB36lGuhydfzcJQZjtpF8wxUevgTXx7yz44JK/d7m/1Gc7
         6IfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=acWOWB79IB5wK5gqHZwES9UHk0FkmXJsAWxv92aElkw=;
        b=L0oiKdI9r9wAomuhe8r9bmIZpMhGTpL7BDQSivWOGdWj23wrRZ5p32G9LCWAV9MYRl
         YmymRttH632lDnjwTp0S8ZaoYL22bRIirG4+oa0nc8Oon+bgBlvL0sIXZWmPLtmVEC/V
         yYLKuS+ZFjGENOH6VZX8BF3DQfL/9bnane9gzquT/j+jyPP+gg9FVzrJArD0+JqiPn4W
         OqKruC+s0gXHFuDBhb6ODSv8xXhExZLvomxBbZr0qnGvJEuFc/9YzJSgfluxMY0lZl18
         unDBZSOxEpLlAe90eHEhv0Aq2oDFY8bE1RkCAyte6MkV9oGTSAoS8gOpoWu35RqTn4dK
         qeAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=i+jg8hta;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf33.google.com (mail-qv1-xf33.google.com. [2607:f8b0:4864:20::f33])
        by gmr-mx.google.com with ESMTPS id f1si215452plt.3.2021.05.19.21.46.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 May 2021 21:46:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) client-ip=2607:f8b0:4864:20::f33;
Received: by mail-qv1-xf33.google.com with SMTP id ee9so8020738qvb.8
        for <kasan-dev@googlegroups.com>; Wed, 19 May 2021 21:46:48 -0700 (PDT)
X-Received: by 2002:a0c:f883:: with SMTP id u3mr3374112qvn.44.1621486007445;
 Wed, 19 May 2021 21:46:47 -0700 (PDT)
MIME-Version: 1.0
References: <20210512181836.GA3445257@paulmck-ThinkPad-P17-Gen-1>
 <CACT4Y+Z+7qPaanHNQc4nZ-mCfbqm8B0uiG7OtsgdB34ER-vDYA@mail.gmail.com>
 <20210517164411.GH4441@paulmck-ThinkPad-P17-Gen-1> <CANpmjNPbXmm9jQcquyrNGv4M4+KW_DgcrXHsgDtH=tYQ6=RU4Q@mail.gmail.com>
 <20210518204226.GR4441@paulmck-ThinkPad-P17-Gen-1> <CANpmjNN+nS1CAz=0vVdJLAr_N+zZxqp3nm5cxCCiP-SAx3uSyA@mail.gmail.com>
 <20210519185305.GC4441@paulmck-ThinkPad-P17-Gen-1> <CANpmjNMskihABCyNo=cK5c0vbNBP=fcUO5-ZqBJCiO4XGM47DA@mail.gmail.com>
In-Reply-To: <CANpmjNMskihABCyNo=cK5c0vbNBP=fcUO5-ZqBJCiO4XGM47DA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 20 May 2021 06:46:35 +0200
Message-ID: <CACT4Y+bNeErg4L5Tn=asK6ZNr+V6bnwwuD+Pg26x=pMO+pRXXw@mail.gmail.com>
Subject: Re: "Learning-based Controlled Concurrency Testing"
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, syzkaller <syzkaller@googlegroups.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=i+jg8hta;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f33
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

On Wed, May 19, 2021 at 10:24 PM Marco Elver <elver@google.com> wrote:
>
> On Wed, 19 May 2021 at 20:53, Paul E. McKenney <paulmck@kernel.org> wrote:
> > On Wed, May 19, 2021 at 11:02:43AM +0200, Marco Elver wrote:
> > > On Tue, 18 May 2021 at 22:42, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > [...]
> > > > > All the above sound like "functional coverage" to me, and could be
> > > > > implemented on top of a well-thought-out functional coverage API.
> > > > > Functional coverage is common in the hardware verification space to
> > > > > drive simulation and model checking; for example, functional coverage
> > > > > could be "buffer is full" vs just structural (code) coverage which
> > > > > cannot capture complex state properties like that easily.
> > > > >
> > > > > Similarly, you could then say things like "number of held locks" or
> > > > > even alluding to your example (5) above, "observed race on address
> > > > > range". In the end, with decent functional coverage abstractions,
> > > > > anything should hopefully be possible.
> > > >
> > > > Those were in fact the lines along which I was thinking.
> > > >
> > > > > I've been wondering if this could be something useful for the Linux
> > > > > kernel, but my guess has always been that it'd not be too-well
> > > > > received because people don't like to see strange annotations in their
> > > > > code. But maybe I'm wrong.
> > > >
> > > > I agree that it is much easier to get people to use a tool that does not
> > > > require annotations.  In fact, it is best if it requires nothing at all
> > > > from them...
> > >
> > > While I'd like to see something like that, because it'd be beneficial
> > > to see properties of the code written down to document its behaviour
> > > better and at the same time machine checkable, like you say, if it
> > > requires additional effort, it's a difficult sell. (Although the same
> > > is true for all other efforts to improve reliability that require a
> > > departure from the "way it used to be done", be it data_race(), or
> > > even efforts introducing whole new programming languages to the
> > > kernel.)
> >
> > Fair point!  But what exactly did you have in mind?
>
> Good question, I'll try to be more concrete -- most of it are
> half-baked ideas and questions ;-), but if any of it makes sense, I
> should maybe write a doc to summarize.
>
> What I had in mind is a system to write properties for both functional
> coverage, but also checking more general properties of the kernel. The
> latter I'm not sure about how useful. But all this isn't really used
> for anything other than in debug builds.
>
> Assume we start with macros such as "ASSERT_COVER(...)" (for
> functional coverage) and "ASSERT(...)" (just plain-old assertions).
> The former is a way to document potentially interesting states (useful
> for fuzzers to reach them), and the latter just a way to just specify
> properties of the system (useful for finding the actual bugs).
> Implementation-wise the latter is trivial, the former requires some
> thought on how to expose that information to fuzzers and how to use
> (as Dmitry suggested it's not trivial). I'd also imagine we can have
> module-level variants ("GLOBAL_ASSERT*(...)") that monitor some global
> state, and also add support for some subset of temporal properties
> like "GLOBAL_ASSERT_EVENTUALLY(precond, eventually_holds)" as
> suggested below.
>
> I guess maybe I'd have to take a step back and just ask why we have no
> way to write plain and simple assertions that are removed in non-debug
> builds? Some subsystems seem to roll their own, which a 'git grep
> "#define ASSERT"' tells me.
>
> Is there a fundamental reason why we shouldn't have them, perhaps
> there was some past discussion? Today we have things like
> lockdep_assert_held(), but nothing to even write a simple assert
> otherwise. If I had to guess why something like ASSERT is bad, it is
> because it gives people a way to check for unexpected conditions, but
> if those checks disappear in non-debug builds, the kernel might be
> unstable. Therefore every possible state must be handled and we must
> always be able to recover. The argument in favor is, if the ASSERT()s
> are proven invariants or conditions where we'd recover either way, and
> are only there to catch accidental regressions during testing; and in
> non-debug builds we don't suffer the performance overheads.

There are some (see below) and I am sure there are precedents in other
subsystems as well.
What's the rationale behind not having a common debug assert/config...
maybe because nobody cared enough. The current approach is poorly
suited for CIs/generic testing but fine for human-oriented workflows
for testing a single subsystem only.

$ grep DEBUG_VM mm/*.c
mm/debug.c:#ifdef CONFIG_DEBUG_VM
mm/debug.c:#endif /* CONFIG_DEBUG_VM */
mm/filemap.c: if (!IS_ENABLED(CONFIG_DEBUG_VM) && unlikely(page_mapped(page))) {
mm/huge_memory.c: if (IS_ENABLED(CONFIG_DEBUG_VM) && mapcount) {
mm/interval_tree.c:#ifdef CONFIG_DEBUG_VM_RB
mm/interval_tree.c:#ifdef CONFIG_DEBUG_VM_RB
mm/ksm.c:#ifdef CONFIG_DEBUG_VM
mm/ksm.c:#if defined (CONFIG_DEBUG_VM) && defined(CONFIG_NUMA)
mm/memcontrol.c:#ifdef CONFIG_DEBUG_VM
mm/memcontrol.c:#ifdef CONFIG_DEBUG_VM
mm/mmap.c:#ifdef CONFIG_DEBUG_VM_RB
mm/page_alloc.c:#ifdef CONFIG_DEBUG_VM
mm/page_alloc.c: if (!IS_ENABLED(CONFIG_DEBUG_VM)) {
mm/page_alloc.c:#ifdef CONFIG_DEBUG_VM
mm/page_alloc.c: * With DEBUG_VM enabled, order-0 pages are checked
immediately when being freed
mm/page_alloc.c: * With DEBUG_VM disabled, order-0 pages being freed
are checked only when
mm/page_alloc.c:#endif /* CONFIG_DEBUG_VM */
mm/page_alloc.c:#ifdef CONFIG_DEBUG_VM
mm/page_alloc.c: * With DEBUG_VM enabled, order-0 pages are checked
for expected state when
mm/page_alloc.c: * With DEBUG_VM disabled, free order-0 pages are
checked for expected state
mm/page_alloc.c:#endif /* CONFIG_DEBUG_VM */
mm/slab_common.c:#ifdef CONFIG_DEBUG_VM
mm/vmacache.c:#ifdef CONFIG_DEBUG_VM_VMACACHE
mm/vmstat.c:#ifdef CONFIG_DEBUG_VM_VMACACHE

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbNeErg4L5Tn%3DasK6ZNr%2BV6bnwwuD%2BPg26x%3DpMO%2BpRXXw%40mail.gmail.com.
